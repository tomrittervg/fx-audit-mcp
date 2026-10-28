#!/usr/bin/env python3
"""Run a testcase in the browser a real Felt sign-in spawns.

`browser_evaluator` cannot do this. On an `--enable-enterprise` build a bare
launch comes up as the Felt sign-in UI, and `MOZ_BYPASS_FELT` only avoids that
by producing a browser the fork's surface is missing from: the Felt actors are
registered under `Services.felt?.isFeltUI()`, which the bypass makes false, so
they are not in the process at all, and there is no console policy, no SSO
token and no SQLite DEK. A clean result from such a browser is evidence only
for fork-modified shared code.

The sequence here is the one the fork's own tests use:

    mock console + SSO (the fork's own servers, see felt/console.py)
      -> launch the Felt UI with Marionette
      -> fill #felt-form__email and click #felt-form__sign-in-btn, in chrome
      -> Felt authenticates, fetches the primarySecret, spawns the browser
      -> read <managed profile>/MarionetteActivePort, attach to the child
      -> open the testcase in the child and wait

Deliberately not built on grizzly/ffpuppet. Those own the launch and the profile
of the process they start, which here is the Felt UI -- the wrong process. Their
prefs would land on the wrong profile and their liveness check would watch the
wrong tree. What is kept is everything that travels by environment inheritance,
because the Felt UI's environment is the spawned browser's: `ASAN_OPTIONS=
log_path` means reports from the spawned browser and its content processes land
where this can find them, and `ffpuppet.helpers.SANDBOX_ENV_VARS` gives
`enable_sandbox` the same meaning here as under `browser_evaluator`. Their
parsers then turn the logs into the same result model.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import suppress
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ffpuppet.helpers import SANDBOX_ENV_VARS

from ..models import BrowserCrashInfo
from .console import FeltConsole
from .marionette import Marionette

# The Felt UI needs its own Marionette port, and the spawned browser gets one
# from the console's extra_prefs (marionette.port = 0). 2828 is the default and
# a singleton: a leftover Felt UI holding it makes the next launch exit 69 while
# a client connects to the stale instance and reports success. Always allocate.
_FELT_UI_PORT_BASE = 2900


def apply_sandbox_env(env: dict[str, str], *, enable_sandbox: bool) -> None:
    """Set `env` so the spawned browser's sandbox is in the asked-for state.

    Reaches that browser by the same inheritance as `ASAN_OPTIONS` and
    `MOZ_LOG`: `FeltProcessParent.startFirefox` spawns it with
    `environmentAppend: true`, so `Subprocess` starts from the Felt UI's
    environment and merges the console's startup policies onto it.

    Both states are written explicitly, never left to chance. Firefox checks
    these variables by presence and not by value, and the caller's `env`
    starts from `os.environ` -- so an inherited `MOZ_DISABLE_*_SANDBOX` would
    silently unsandbox every run, with nothing recording that it had. For the
    same reason the enabled branch deletes the keys rather than writing `"0"`,
    which would *disable* the sandbox.

    The variables come from ffpuppet so that `enable_sandbox` means the same
    thing here as under `browser_evaluator`, including if ffpuppet adds an
    eighth process type.
    """
    for sandbox_var in SANDBOX_ENV_VARS:
        if enable_sandbox:
            env.pop(sandbox_var, None)
        else:
            env[sandbox_var] = "1"


SIGN_IN_JS = """
  const email = document.querySelector("#felt-form__email");
  if (!email) return {ok: false, why: "no #felt-form__email"};
  email.value = arguments[0];
  email.dispatchEvent(new Event("input", {bubbles: true}));
  const btn = document.querySelector("#felt-form__sign-in-btn");
  if (!btn) return {ok: false, why: "no #felt-form__sign-in-btn"};
  if (btn.disabled) return {ok: false, why: "sign-in button still disabled"};
  btn.click();
  return {ok: true};
"""

# The identity provider page the SSO server serves is a real form: it posts to
# /auth, which is what sets the sign-in cookie. Clicking the Felt sign-in button
# only gets as far as rendering it, so a session needs two interactions, not
# one. Without this the Felt UI logs `SSO login timed out`.
SUBMIT_IDP_JS = """
  const btn = document.querySelector("#submit");
  if (!btn) return {ok: false, why: "identity-provider form not loaded yet"};
  btn.click();
  return {ok: true};
"""

OPEN_TESTCASE_JS = """
  const gb = window.gBrowser;
  if (!gb) return {ok: false, why: "no gBrowser in the spawned browser"};
  // A null principal, not the system principal. The triggering principal is
  // what the load is attributed to, and it decides the security checks and the
  // process the document lands in. Opening with the system principal describes
  // a load chrome itself started, which is not the threat being audited and can
  // place the document somewhere web content never would be. A null principal
  // is an untrusted, opaque origin -- the closest chrome can get to "some page
  // navigated here".
  gb.selectedTab = gb.addTab(arguments[0], {
    triggeringPrincipal: Services.scriptSecurityManager.createNullPrincipal({}),
  });
  return {ok: true, tabs: gb.tabs.length};
"""

# Read after the testcase has had a moment to load. remoteType is the process
# class the document actually landed in -- `web`, `webIsolated=<site>`, `file`,
# `privilegedabout` and so on -- and is the cheapest honest answer to "did this
# run as web content". Reported in the result so a caller never has to infer it.
REMOTE_TYPE_JS = """
  const b = window.gBrowser && window.gBrowser.selectedBrowser;
  if (!b) return {ok: false, why: "no selectedBrowser"};
  return {
    ok: true,
    remoteType: b.remoteType,
    uri: b.currentURI && b.currentURI.spec,
  };
"""


class _TestcaseServer:
    """Serve the testcase over HTTP, and record what was fetched.

    The testcase used to be opened as a `file://` URI, which is the wrong
    security context for every question this tool exists to answer: a
    `file://` document is same-origin with other local files, is exempt from
    parts of the web security model, and lands in the `file` remote type
    instead of a web content process. `browser_evaluator` serves over HTTP for
    that reason and so does this.

    The request log is the second reason. A Felt session has no
    `FuzzingFunctions` unless a pref enables it, and that pref cannot currently
    reach the spawned browser, so a testcase has no way to announce itself.
    An entry here is independent proof the document was fetched, which is
    otherwise unobtainable -- two audits reported being unable to show their
    page had loaded at all.
    """

    def __init__(self, directory: Path, log_path: Path):
        self._log = log_path.open("w", encoding="utf-8", buffering=1)
        log = self._log

        class Handler(SimpleHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                log.write(
                    f"{time.strftime('%H:%M:%S')} {self.address_string()} "
                    f"{fmt % args}\n"
                )

        # 127.0.0.1, not 0.0.0.0: nothing outside this machine has any business
        # reaching a testcase, and the browser is local.
        self._httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), partial(Handler, directory=str(directory))
        )
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def url_for(self, name: str) -> str:
        """The URL an entry-point file is served at."""
        return f"http://127.0.0.1:{self.port}/{name}"

    def stop(self) -> None:
        """Shut the server down; safe to call more than once."""
        with suppress(Exception):
            self._httpd.shutdown()
        with suppress(Exception):
            self._httpd.server_close()
        with suppress(Exception):
            self._log.close()


def _browser_output(stdout_path: Path, dest: Path) -> Path | None:
    """Extract the spawned browser's own output from the Felt UI's stdout.

    The spawned browser is not this process's child -- Felt launches it and
    reads its pipes, then re-emits each line through its own logger as
    `FeltBrowser: "[<pid>]: ..."`, which lands on the *Felt UI's* stdout. So
    the browser's stderr is not in `log_stderr.txt`; that file is legitimately
    empty, and a caller looking there for a testcase's output finds nothing and
    concludes the page never ran. Two audits reached exactly that wrong
    conclusion.

    Args:
        stdout_path: The Felt UI's captured stdout.
        dest: Where to write the extracted lines.

    Returns:
        The written file, or None if there was nothing to extract.
    """
    if not stdout_path.is_file():
        return None
    pattern = re.compile(r'Felt(?:Browser|Process\w*):\s*"\[(\d+)\]:\s*(.*)"\s*$')
    lines: list[str] = []
    for raw in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = pattern.search(raw)
        if m:
            lines.append(f"[pid={m.group(1)}] {m.group(2)}")
    if not lines:
        return None
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def _free_port(start: int = _FELT_UI_PORT_BASE) -> int:
    """A port nothing is listening on, so two runs cannot collide."""
    import socket

    for offset in range(200):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", start + offset))
            except OSError:
                continue
            return start + offset
    raise RuntimeError(f"no free port in {start}..{start + 200}")


def _managed_profile_port_file(home: Path, timeout_s: float) -> Path:
    """Wait for the spawned browser to publish its Marionette port.

    Felt derives a managed profile per signed-in user under the enterprise
    profile root and the child writes `MarionetteActivePort` into it, so the
    file appearing is also the signal that the browser actually started.

    Args:
        home: The run's private HOME, under which Felt puts that profile.
        timeout_s: How long to wait for the file.

    Raises:
        TimeoutError: The browser did not publish a port in time.
    """
    roots = [
        home / ".config" / "mozilla" / "firefoxenterprise",
        home / ".mozilla" / "firefoxenterprise",
    ]
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for root in roots:
            if not root.is_dir():
                continue
            found = sorted(root.glob("*/MarionetteActivePort"))
            if found:
                return found[-1]
        time.sleep(0.5)
    raise TimeoutError(
        "the Felt UI did not spawn a browser that published a Marionette port."
        " Check the Felt log for 'Not enough cookies!!' (the SSO server set no"
        " cookie) or for the sign-in never being driven."
    )


async def felt_browser_evaluator(  # pragma: no cover
    file_paths: dict[str, Path],
    entry_point: str,
    firefox_binary: Path,
    firefox_root: Path,
    timeout: int = 120,
    email: str = "nobody@mozilla.org",
    enable_sandbox: bool = False,
) -> BrowserCrashInfo:
    """Run a testcase in the browser a real Felt sign-in spawns.

    The testcase is served over HTTP on 127.0.0.1, so it loads as ordinary web
    content in a web content process, and is opened with a null triggering
    principal rather than the system principal.

    **How to prove your testcase ran.** `FuzzingFunctions` is not available
    here: it is gated on `fuzzing.enabled`, and that pref currently cannot
    reach the browser Felt spawns -- the console's `extra_prefs` is the only
    delivery path and the fork hardcodes it. So page script cannot announce
    itself the way it can under `browser_evaluator`. Use the request log
    instead:

    - `logs.stdout` contains `log_stdout_requests.txt`, one line per HTTP
      request the testcase made. Have the page fetch a uniquely named
      sub-resource and look for it there. That is positive proof the document
      loaded *and* that its script ran, and it depends on no logging
      configuration at all.
    - `logs.stdout` also contains `log_stdout_session.txt`, recording
      `remote_type` -- the process class the document landed in. `web` or
      `webIsolated=<site>` is a web content process; `file` would mean
      something is wrong with the serving. It also records `enable_sandbox`,
      so a finding's artifacts show which process boundary was in force.
    - `logs.stderr` contains `log_stderr_browser.txt`, the spawned browser's
      own output, demultiplexed from the Felt UI's log and prefixed by pid.
      Note that `console.log`/`console.error` from *content* does not reliably
      appear here even with the console MOZ_LOG module enabled, which is why
      the request log is the recommended mechanism.

    Args:
        file_paths: Testcase files, keyed by the name to serve them as. All of
            them are served, so any can be used as a proof token.
        entry_point: Which of those files to open.
        firefox_binary: The `--enable-enterprise` build to launch.
        firefox_root: The checkout holding `mach` and the enterprise harness,
            whose mock console servers this starts.
        timeout: Seconds to let the testcase run once it is open.
        email: Address to sign in with; any address is accepted.
        enable_sandbox: Leave the sandbox enabled in the spawned browser. Same
            name, type and default as `browser_evaluator`'s, and the same
            seven `MOZ_DISABLE_*_SANDBOX` variables, so a testcase moves
            between the two evaluators without changing which boundary is in
            force. Off by default, matching `browser_evaluator`: a content
            process that cannot make the faulting access does not report the
            defect. Turn it on to prove a finding survives the real boundary.
            The state used is recorded in `log_stdout_session.txt`.

    Returns:
        The same `BrowserCrashInfo` shape `browser_evaluator` returns, so a
        caller does not have to special-case which evaluator produced it.
        `timed_out` means the browser stopped answering -- a real hang -- and
        not merely that the testcase ran for its whole window without crashing,
        which is the ordinary no-crash outcome and reports False.

    Raises:
        FileNotFoundError: The binary does not exist.
        RuntimeError: The session could not be established.
    """
    # Imported here to keep the module importable without grizzly installed.
    from ..browser_evaluator import (
        _categorize_logs,
        _crashed_process_fields,
        _extract_crash_pids,
    )

    if not firefox_binary.exists():
        raise FileNotFoundError(f"Firefox binary not found at {firefox_binary}")

    felt_port = _free_port()
    work = Path(tempfile.mkdtemp(prefix="fxe-felt-eval-"))
    log_dir = work / "logs"
    log_dir.mkdir()
    profile = work / "felt-ui-profile"
    profile.mkdir()
    runtime_dir = work / "runtime"
    runtime_dir.mkdir(mode=0o700)
    home_dir = work / "home"
    home_dir.mkdir(mode=0o700)
    # user.js, not prefs.js: writing prefs.js into a fresh profile makes Felt
    # report "Previous FELT session ended unexpectedly" and take another path.
    # marionette.port is a pref, not a command-line flag -- `--marionette` only
    # switches the server on. The spawned browser gets its own port from the
    # console's extra_prefs (marionette.port = 0), so the two cannot collide.
    (profile / "user.js").write_text(
        'user_pref("enterprise.log_level", "all");\n'
        f'user_pref("marionette.port", {felt_port});\n',
        encoding="utf-8",
    )

    testcase_dir = work / "testcase"
    testcase_dir.mkdir()
    for name, src in file_paths.items():
        dst = testcase_dir / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    console = FeltConsole(firefox_root, log_path=log_dir / "log_console.txt")
    server = _TestcaseServer(testcase_dir, log_dir / "log_stdout_requests.txt")
    proc: subprocess.Popen[bytes] | None = None
    remote_type: object = None
    loaded_uri: object = None
    try:
        endpoints = console.start()
        env = {
            **os.environ,
            "MOZ_ENTERPRISE_CONSOLE_URL": endpoints.console_url,
            "MOZ_DISABLE_NONLOCAL_CONNECTIONS": "0",
            # Chrome context is required to reach #felt-form__email, which is a
            # moz-input-text whose real input is in shadow DOM.
            "MOZ_REMOTE_ALLOW_SYSTEM_ACCESS": "1",
            # Inherited by the whole tree, so the spawned browser's reports land
            # here too -- that inheritance is what makes this work at all.
            "ASAN_OPTIONS": f"log_path={log_dir / 'log_ffp_asan'}:detect_leaks=0",
            # Every enterprise build brands itself `firefoxenterprise`, and
            # XREUserRunTimeDir is /run/user/<uid>/<remoting name>/. Two
            # instances therefore share one runtime directory and fight over one
            # DBus remote name: the loser logs `onNameLost` and exits, taking
            # its content processes with it ("Exiting due to channel error").
            # The Felt UI and the browser it spawns are two instances, so this
            # is not a concurrency edge case -- it happens on every run. Give
            # the run its own runtime directory.
            "XDG_RUNTIME_DIR": str(runtime_dir),
            # Felt derives the *managed* profile from the signed-in user under
            # the enterprise profile root in HOME, and the mock SSO returns the
            # same user every time, so successive runs would reuse one managed
            # profile. That profile is encrypted with the primarySecret the
            # console handed over, and `serve()` mints a fresh random
            # TEST_PRIMARY_SECRET per console process -- so the second run gets
            # a profile it cannot decrypt, fails in
            # EnterpriseStorageEncryption.load, and Marionette reports the
            # opaque "session not created: The connection was denied by the
            # user". Observed on every retry in fxe-session-smoke-3, where the
            # first call per run succeeded and every later one did not.
            # A private HOME gives each run its own managed profile, matching
            # the secret that run's console actually issued.
            "HOME": str(home_dir),
            # Set explicitly: an inherited XDG_CONFIG_HOME would otherwise still
            # point at the real one and put the managed profile back on the
            # shared path, defeating the private HOME above.
            "XDG_CONFIG_HOME": str(home_dir / ".config"),
            # Pointing XDG_RUNTIME_DIR somewhere private makes Firefox look for
            # a Wayland socket there and fail ("Failed to connect to Wayland
            # display .../runtime/wayland-0"). The display here is Xvfb, so say
            # so rather than letting it auto-detect into an empty directory.
            "MOZ_ENABLE_WAYLAND": "0",
            "GDK_BACKEND": "x11",
            # The same modules browser_evaluator sets, for the same reason and
            # by the same mechanism: the environment is inherited by the whole
            # tree, so the browser Felt spawns and its content processes get
            # them too. `console` is what carries a testcase's console.log and
            # console.error out of a content process -- without it page script
            # has no way to say anything, which a Felt session makes worse
            # because FuzzingFunctions needs a pref that cannot currently reach
            # the spawned browser. ChildProcessLifecycle is what maps a crashing
            # pid back to a process type.
            "MOZ_LOG": "console:5,PageMessages:5,ChildProcessLifecycle:5",
        }
        env.pop("MOZ_BYPASS_FELT", None)

        apply_sandbox_env(env, enable_sandbox=enable_sandbox)

        # Firefox needs a display; without one it exits with "Exiting due to
        # channel error" and Marionette never binds. grizzly handles this with
        # its own xvfb display mode, which is unavailable here because the
        # launch is not grizzly's.
        launcher = (
            ["xvfb-run", "-a"]
            if sys.platform == "linux" and shutil.which("xvfb-run")
            else []
        )
        # Capture stdout as well as stderr: Felt's own diagnostics go through
        # console.debug, which lands on stdout. Discarding it leaves a failed
        # session with nothing to go on but "Exiting due to channel error".
        stderr_path = log_dir / "log_stderr.txt"
        stdout_path = log_dir / "log_stdout.txt"
        with stderr_path.open("wb") as stderr_fh, stdout_path.open("wb") as stdout_fh:
            proc = subprocess.Popen(
                [
                    *launcher,
                    str(firefox_binary),
                    "-profile",
                    str(profile),
                    "-marionette",
                ],
                env=env,
                stdout=stdout_fh,
                stderr=stderr_fh,
            )

            felt_ui = Marionette(felt_port)
            felt_ui.connect(attempts=60)
            felt_ui.new_session()
            felt_ui.set_context("chrome")
            signed_in = felt_ui.execute_script(SIGN_IN_JS, [email])
            value = (
                signed_in.get("value", signed_in)
                if isinstance(signed_in, dict)
                else signed_in
            )
            if not (isinstance(value, dict) and value.get("ok")):
                raise RuntimeError(f"could not drive the Felt sign-in: {value}")

            # Second interaction: the identity provider's own form, rendered
            # in the Felt UI's content frame. Polled because the click above
            # only starts the navigation that produces it.
            _submit_idp_form(felt_ui, timeout_s=60)

            port_file = _managed_profile_port_file(home_dir, timeout_s=180)
            child = Marionette(int(port_file.read_text().strip()))
            child.connect(attempts=60)
            child.new_session()
            child.set_context("chrome")
            opened = child.execute_script(
                OPEN_TESTCASE_JS, [server.url_for(entry_point)]
            )
            opened_value = (
                opened.get("value", opened) if isinstance(opened, dict) else opened
            )
            if not (isinstance(opened_value, dict) and opened_value.get("ok")):
                raise RuntimeError(f"could not open the testcase: {opened_value}")

            # Read once the document has had a chance to commit; before that
            # remoteType still describes about:blank. Never fatal -- a crashed
            # or navigating tab legitimately has nothing to report, and losing
            # the result would be worse than losing this detail.
            with suppress(Exception):
                probed = child.execute_script(REMOTE_TYPE_JS, [])
                probed = (
                    probed.get("value", probed) if isinstance(probed, dict) else probed
                )
                if isinstance(probed, dict) and probed.get("ok"):
                    remote_type = probed.get("remoteType")
                    loaded_uri = probed.get("uri")

            window_expired = _wait_for_crash(log_dir, proc, timeout)
            # `timed_out` means a hang in browser_evaluator's vocabulary, and a
            # testcase that simply ran its window without crashing is not one.
            # Reporting True for every non-crashing run told two audits they
            # were chasing a hang; one escalated the timeout 30 -> 60 -> 180
            # against a browser that was perfectly healthy. Ask the browser
            # instead: an unresponsive child is the real thing this is for.
            timed_out = window_expired and not _child_responsive(child)
            with suppress(Exception):
                child.close()
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            with suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=20)
            if proc.poll() is None:
                proc.kill()
        console.stop()
        server.stop()

    # Written after the Felt UI has exited, so its stdout is complete. The
    # filenames are not cosmetic: _categorize_logs buckets by substring, so
    # "stderr" puts the browser's own output where a caller looks for a
    # testcase's output, "stdout" puts the request log alongside other
    # informational output, and anything matching neither would land in
    # crashdata and be read as a crash report.
    _browser_output(log_dir / "log_stdout.txt", log_dir / "log_stderr_browser.txt")

    # What the testcase actually became, recorded rather than left to be
    # inferred. remoteType is the process class the document landed in, and for
    # a tool whose whole purpose is "untrusted web content reaches privileged
    # surface" it is the difference between a result and a guess. Written to a
    # log rather than added to BrowserCrashInfo, which browser_evaluator shares.
    (log_dir / "log_stdout_session.txt").write_text(
        f"testcase_url: {server.url_for(entry_point)}\n"
        f"loaded_uri: {loaded_uri}\n"
        f"remote_type: {remote_type}\n"
        f"enable_sandbox: {enable_sandbox}\n"
        "note: remote_type is the spawned browser's selectedBrowser.remoteType\n"
        "      just after the testcase was opened. A web content process reads\n"
        "      as web or webIsolated=<site>; `file` would mean the testcase was\n"
        "      not served over HTTP and the security context is wrong.\n",
        encoding="utf-8",
    )

    logs = _categorize_logs(log_dir)
    crash_pids = _extract_crash_pids(logs.crashdata)
    # parent_pid is None: the Felt UI's pid is not the spawned browser's
    # parent, so attribution rests on the ChildProcessLifecycle records in
    # stderr alone. An unresolved pid leaves the child flags None rather
    # than False, which is the conservative direction.
    fields = _crashed_process_fields(logs, parent_pid=None)
    return BrowserCrashInfo(
        crashed=bool(crash_pids),
        timed_out=timed_out,
        logs=logs,
        **fields,
    )


def _submit_idp_form(felt_ui: Marionette, timeout_s: float) -> None:
    """Click Authenticate on the identity-provider form, once it appears.

    Args:
        felt_ui: A Marionette session on the Felt UI.
        timeout_s: How long to wait for the form to render.

    Raises:
        RuntimeError: The form never appeared.
    """
    felt_ui.set_context("content")
    deadline = time.time() + timeout_s
    last: object = None
    while time.time() < deadline:
        result = felt_ui.execute_script(SUBMIT_IDP_JS)
        value = result.get("value", result) if isinstance(result, dict) else result
        if isinstance(value, dict) and value.get("ok"):
            return
        last = value
        time.sleep(1)
    raise RuntimeError(
        f"the identity-provider form never rendered: {last}."
        " The Felt UI logs 'SSO login timed out' when this step is missed."
    )


def _child_responsive(child: Marionette) -> bool:
    """Whether the spawned browser still answers Marionette.

    The distinction between "the testcase ran its window" and "the browser
    hung" cannot be made from a timer alone, and this tool has a live chrome
    connection to the child, so it can simply ask. A browser that evaluates a
    trivial script is not hung whatever the clock says.

    Args:
        child: The connected Marionette client for the spawned browser.

    Returns:
        True if it answered, False on any error or timeout.
    """
    try:
        answer = child.execute_script("return 1 + 1;", [])
    except Exception:
        return False
    value = answer.get("value", answer) if isinstance(answer, dict) else answer
    return value == 2


def _wait_for_crash(log_dir: Path, proc: subprocess.Popen[bytes], timeout: int) -> bool:
    """Poll for a sanitizer report until the timeout.

    Returns:
        True if the time limit expired without one, which is the `timed_out`
        sense `browser_evaluator` uses.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(log_dir.glob("log_ffp_asan*")):
            return False
        if proc.poll() is not None:
            # The Felt UI exited; a report may have been written on the way out.
            return not any(log_dir.glob("log_ffp_asan*"))
        time.sleep(0.5)
    return True
