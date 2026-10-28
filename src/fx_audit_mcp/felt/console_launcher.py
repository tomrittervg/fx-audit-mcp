#!/usr/bin/env python3
"""Start the fork's own mock console + SSO servers and report their ports.

Runs *inside* the Firefox checkout's `mach python` environment, because
`testing/enterprise/felt_tests.py` imports `requests`, `marionette_driver` and
`mozprofile`. fx-audit-mcp must not carry that stack, so the servers live in a
subprocess and only their ports cross back, through --port-file.

Everything served here is the fork's code. This file starts it and nothing
else: the moment it reimplements an endpoint, the endpoint stops being the one
the fork's own tests exercise, which is the entire reason for running it this
way. The contract this depends on is recorded in
`testing/enterprise/CONSOLE_CONTRACT.md` in the fork.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from multiprocessing import Process, Value
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port-file", required=True, type=Path)
    args = ap.parse_args()

    # Imported here, not at module scope: this only resolves under mach python.
    from felt_tests import (  # type: ignore[import-not-found]
        ConsoleHttpHandler,
        SharedString,
        SsoHttpHandler,
        serve,
    )

    console_port = Value("i", 0)
    sso_port = Value("i", 0)

    # The SSO server is what sets the sign-in cookie, at /auth. Felt collects
    # cookies after the callback and refuses to spawn the browser when it finds
    # none (FeltProcessParent: "Not enough cookies!!"), so both servers are
    # required -- the console alone is not enough.
    cookie_name = SharedString(str(uuid.uuid1()).split("-")[0])
    cookie_value = SharedString(str(uuid.uuid4()).split("-")[4])

    # `serve()` gives defaults only to the four `*_fail_request`/`signout_count`
    # knobs; everything else is set on the server *only if passed*. A handler
    # that writes one then raises AttributeError mid-response -- token
    # redemption assigns policy_access_token and policy_refresh_token, so
    # omitting them crashes the request after the one-time token has already
    # matched, and the browser reports "One-time-token redemption failed (401)"
    # for what is really a server-side crash. Mirror the harness's own
    # initial values rather than inventing any.
    shared = {
        "login_location": SharedString(""),
        "policy_signout_crash_action": SharedString(""),
        "policy_access_token": SharedString(""),
        "policy_refresh_token": SharedString(""),
        "posture_edr_agents": SharedString(""),
        "relaunch": SharedString(""),
        "policy_block_about_config": Value("b", 1),
        "policy_access_connector": Value("b", 0),
        "policy_extensions": Value("B", 0),
        "policy_watermark": Value("b", 0),
        "policy_disable_safe_mode": Value("b", -1),
        "policy_disable_third_party_module_blocking": Value("b", -1),
    }

    console = Process(
        target=serve,
        args=(ConsoleHttpHandler,),
        kwargs={
            "sso_port": sso_port,
            "console_port": console_port,
            "is_console": True,
            **shared,
        },
    )
    console.start()

    sso = Process(
        target=serve,
        args=(SsoHttpHandler,),
        kwargs={
            "sso_port": sso_port,
            "console_port": console_port,
            "is_console": False,
            "cookie_name": cookie_name,
            "cookie_value": cookie_value,
        },
    )
    sso.start()

    # serve() binds port 0 and writes the result back into the shared Value, so
    # both are zero until each server is actually listening.
    deadline = time.time() + 60
    while (console_port.value == 0 or sso_port.value == 0) and time.time() < deadline:
        if not console.is_alive() or not sso.is_alive():
            print("a server process exited before binding", file=sys.stderr)
            return 1
        time.sleep(0.1)
    if console_port.value == 0 or sso_port.value == 0:
        print("timed out waiting for the servers to bind", file=sys.stderr)
        return 1

    args.port_file.write_text(
        json.dumps(
            {
                "console_port": console_port.value,
                "sso_port": sso_port.value,
                "cookie_name": cookie_name.value,
                "cookie_value": cookie_value.value,
            }
        ),
        encoding="utf-8",
    )
    print(
        f"console=127.0.0.1:{console_port.value} sso=127.0.0.1:{sso_port.value}",
        file=sys.stderr,
        flush=True,
    )

    try:
        console.join()
        sso.join()
    except KeyboardInterrupt:
        pass
    finally:
        for proc in (console, sso):
            if proc.is_alive():
                proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
