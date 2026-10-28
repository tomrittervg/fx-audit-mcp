#!/usr/bin/env python3
"""Run the fork's own mock enterprise console + SSO servers.

This does **not** implement a console. It starts the servers in
`testing/enterprise/felt_tests.py` -- `ConsoleHttpHandler` and `SsoHttpHandler`,
driven by that module's `serve()` -- so an audit exercises the same endpoints
the fork's own browser tests do.

An earlier version of this file reimplemented those endpoints from reading the
harness. It worked, eventually, but every blocker took a browser run to
rediscover something the harness already encoded: that the SSO callback redirect
must carry a query string, that `/auth` has to set a cookie or Felt refuses to
spawn the browser, and that the cookie's Domain has to match the host actually
used. Reproducing a protocol whose sequencing is undocumented is how those get
lost; running the real thing is how they stay fixed.

The servers need `requests`, `marionette_driver` and `mozprofile`, which
fx-audit-mcp does not depend on, so they run under the checkout's
`mach python` in a subprocess. Only the ports come back.

What this relies on is written down next to the servers themselves, in
`testing/enterprise/CONSOLE_CONTRACT.md`, so a change there is visible to
whoever makes it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

LAUNCHER = Path(__file__).with_name("console_launcher.py")
# Generous on purpose, but not for the reason first assumed. `mach python` does
# create its `common` virtualenv on first use, which looked like it could
# dominate this; measured 2026-10-28 it is ~1.6s and needs no network, because
# the venv is empty and a generated mach.pth points at in-tree code -- requests
# is vendored at third_party/python/requests, marionette_driver and mozprofile
# live under testing/. What this timeout actually covers is a cold `mach`
# itself on a checkout whose build state has to be re-read.
BIND_TIMEOUT_S = 180.0


@dataclass(frozen=True)
class ConsoleEndpoints:
    """Where the running servers are, and the cookie the SSO server will set."""

    console_url: str
    sso_url: str
    cookie_name: str
    cookie_value: str


class FeltConsole:
    """The fork's mock console and SSO servers, as a context manager.

    Args:
        firefox_root: The Firefox Enterprise checkout. Must contain `mach` and
            `testing/enterprise/felt_tests.py`.
    """

    def __init__(self, firefox_root: Path, log_path: Path | None = None):
        self._root = Path(firefox_root)
        self._log_path = log_path
        self._proc: subprocess.Popen[bytes] | None = None
        self._tmp: TemporaryDirectory[str] | None = None
        self.endpoints: ConsoleEndpoints | None = None

    def __enter__(self) -> ConsoleEndpoints:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start(self) -> ConsoleEndpoints:
        """Launch both servers and block until each has bound a port.

        Returns:
            Where the servers are listening, and the SSO cookie identity.

        Raises:
            FileNotFoundError: The checkout has no `mach` or no harness.
            RuntimeError: The servers exited or failed to bind in time.
        """
        mach = self._root / "mach"
        harness = self._root / "testing" / "enterprise" / "felt_tests.py"
        for path, what in ((mach, "mach"), (harness, "the enterprise test harness")):
            if not path.exists():
                raise FileNotFoundError(f"{self._root} has no {what} at {path}")

        self._tmp = TemporaryDirectory(prefix="fxe-console-")
        port_file = Path(self._tmp.name) / "ports.json"

        # PYTHONPATH carries testing/enterprise so felt_tests can find its
        # siblings (base_test, felt_consts); mach python supplies the rest.
        self._proc = subprocess.Popen(
            [str(mach), "python", str(LAUNCHER), "--port-file", str(port_file)],
            cwd=self._root,
            env={**_inherited_env(), "PYTHONPATH": "testing/enterprise"},
            stdout=subprocess.DEVNULL,
            # BaseHTTPRequestHandler logs every request here and the harness does
            # not silence it, so this is the server-side request log. Keeping it
            # is what makes a failed handshake diagnosable from the other end --
            # a 401 on token redemption looks identical in the browser whether
            # the callback was never served or the token was already spent.
            stderr=(self._log_path.open("wb") if self._log_path else subprocess.PIPE),
        )

        deadline = time.time() + BIND_TIMEOUT_S
        while time.time() < deadline:
            if port_file.exists():
                data = json.loads(port_file.read_text(encoding="utf-8"))
                # `localhost`, not `127.0.0.1`. The handlers build every
                # internal link as `http://localhost:<port>/...` and set the
                # sign-in cookie with `Domain=localhost`. Point the browser at
                # 127.0.0.1 and two things break at once: the cookie does not
                # apply, and the FeltWindow actor's match pattern -- derived
                # from the console address -- cannot match a callback served
                # from a different hostname, so the one-time token is never
                # scraped. See CONSOLE_CONTRACT.md in the fork.
                self.endpoints = ConsoleEndpoints(
                    console_url=f"http://localhost:{data['console_port']}",
                    sso_url=f"http://localhost:{data['sso_port']}",
                    cookie_name=data["cookie_name"],
                    cookie_value=data["cookie_value"],
                )
                return self.endpoints
            if self._proc.poll() is not None:
                err = (self._proc.stderr.read() if self._proc.stderr else b"").decode(
                    "utf-8", errors="replace"
                )
                raise RuntimeError(
                    f"the console servers exited before binding (rc="
                    f"{self._proc.returncode}):\n{err}"
                )
            time.sleep(0.2)

        self.stop()
        raise RuntimeError(
            f"the console servers did not bind within {BIND_TIMEOUT_S:.0f}s."
            " The servers bind port 0 and write the result back, so this means"
            " `mach python` itself never got far enough to import felt_tests --"
            " check that the checkout builds and that testing/enterprise is on"
            " PYTHONPATH."
        )

    def stop(self) -> None:
        """Terminate the servers; safe to call more than once."""
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None


def _inherited_env() -> dict[str, str]:
    """The environment to hand mach, minus anything that would mislead it."""
    import os

    env = dict(os.environ)
    # The console is being started so a *real* Felt session can run; a bypass
    # inherited from the caller would defeat that, and the fork's own harness
    # deletes it for the same reason.
    env.pop("MOZ_BYPASS_FELT", None)
    return env


def main() -> int:
    """Run the servers in the foreground, for manual use."""
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("firefox_root", type=Path)
    args = ap.parse_args()

    console = FeltConsole(args.firefox_root)
    endpoints = console.start()
    print(f"MOZ_ENTERPRISE_CONSOLE_URL={endpoints.console_url}")
    print(f"sso={endpoints.sso_url}")
    print(f"cookie={endpoints.cookie_name}={endpoints.cookie_value}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0
    finally:
        console.stop()


if __name__ == "__main__":
    sys.exit(main())
