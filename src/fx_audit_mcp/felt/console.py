#!/usr/bin/env python3
"""Mock Firefox Enterprise console + SSO, sufficient to establish a Felt session.

Endpoint contracts reproduced from the fork's own harness
(`testing/enterprise/felt_tests.py`), not invented. The flow a Felt UI drives:

  GET  /sso/login?deviceId=..&version=v2   -> 302 to the login page
  GET  /sso_url                            -> the login page (a form)
  GET  /sso/callback                       -> HTML carrying a script#token_data
                                              blob with one_time_token/user_id/
                                              email/posture
  POST /api/browser/sso/token              -> redeem one_time_token (single use)
                                              or refresh_token -> access/refresh
  GET  /api/browser/config                 -> unauthenticated; carries extra_prefs
  GET  /api/browser/key                    -> authed; the SQLite primarySecret
  GET  /api/browser/policies               -> authed; the policy set
  GET  /api/browser/whoami                 -> authed; identity

Every request is journalled so a run can be inspected afterwards.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

PRIMARY_SECRET = secrets.token_hex(32)
# The SSO cookie Felt requires. FeltProcessParent throws "Not enough cookies!!"
# and never spawns the browser if the sign-in flow set none, so this is
# load-bearing rather than decoration.
COOKIE_NAME = "fxe_sso_" + secrets.token_hex(4)
COOKIE_VALUE = secrets.token_hex(8)
USER_ID = "8f14e45f-ceea-467d-9a3e-000000000042"
EMAIL = "nobody@mozilla.org"

_LOCK = threading.Lock()


class State:
    one_time_token: str | None = None
    access_token: str = ""
    refresh_token: str = ""
    policies: ClassVar[dict] = {}


STATE = State()


def _posture() -> dict:
    """Minimal posture descriptor; the console folds this into token replies."""
    return {"edr_agents": [], "disk_encryption": [], "os_version": []}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockEnterpriseConsole/0"

    # -- plumbing ---------------------------------------------------------

    def _journal(self, method: str, body: bytes) -> None:
        entry = {
            "t": round(time.time(), 3),
            "method": method,
            "path": self.path,
            "authorization": self.headers.get("Authorization", ""),
            "body": body.decode("utf-8", errors="replace")[:2000],
        }
        with _LOCK, Path(self.server.journal).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        print(f"[console] {method} {self.path}", file=sys.stderr, flush=True)

    def _send(
        self, body: bytes, code: int = 200, ctype: str = "application/json"
    ) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: object, code: int = 200) -> None:
        self._send(json.dumps(obj).encode(), code)

    def _authed(self) -> bool:
        """Accept any Bearer token we have issued. Deliberately permissive."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and STATE.access_token:
            return True
        self._send(b"", 401, "text/plain")
        return False

    def log_message(self, fmt: str, *args: object) -> None:
        """Silenced; _journal already records every request."""

    # -- routes -----------------------------------------------------------

    def do_GET(self) -> None:
        self._journal("GET", b"")
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        port = self.server.server_address[1]

        if path == "/sso/login":
            # The client must identify the device and ask for v2; the harness
            # rejects anything else, so reproduce that rather than being lax.
            if "deviceId" not in query or query.get("version") != ["v2"]:
                self._send(b"", 403, "text/plain")
                return
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port}/sso_url")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/sso_url":
            # Stand-in for the identity provider. A real IdP that already has a
            # session for the user redirects straight back to the callback
            # rather than presenting a form, so do that: it keeps the number of
            # UI interactions the harness has to drive at exactly one (the Felt
            # sign-in button), instead of two.
            # The query string is load-bearing, not decoration. The FeltWindow
            # actor matches on ConsoleClient.ssoCallbackUriMatchPattern, which is
            # `<console>/sso/callback` with the port stripped and "?*" appended;
            # a WebExtensions MatchPattern of that shape does not match a URL
            # with no query at all, so the actor never attaches, DOMContentLoaded
            # is never handled and the one-time token is never scraped. The
            # fork's own harness redirects to "?foo" for this reason.
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port}/auth")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/auth":
            # Sets the SSO cookie and continues to the callback. Felt collects
            # cookies from the sign-in browsing context after the callback and
            # refuses to spawn the browser when it finds none, so this hop
            # cannot be skipped by redirecting straight to the callback.
            #
            # No Domain attribute: the fork's own harness sends
            # `Domain=localhost`, which would not apply to a 127.0.0.1 request.
            # Host-only is correct for whichever host actually served this.
            expires = time.strftime(
                "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 8 * 3600)
            )
            self.send_response(302)
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}={COOKIE_VALUE}; Path=/; "
                f"Expires={expires}; SameSite=Strict",
            )
            self.send_header("Location", f"http://127.0.0.1:{port}/sso/callback?auth=1")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/sso/callback":
            STATE.one_time_token = str(uuid.uuid4())
            blob = json.dumps(
                {
                    "one_time_token": STATE.one_time_token,
                    "user_id": USER_ID,
                    "email": EMAIL,
                    "posture": _posture(),
                }
            )
            self._send(
                f"""<html><head><title>Callback!</title>
                <script id="token_data" type="application/json">{blob}</script>
                </head><body><h1>Welcome!</h1></body></html>""".encode(),
                ctype="text/html",
            )
            return

        if path == "/api/browser/config":
            self._json(
                {
                    "learn_more_url": "",
                    "company_logo_url": "",
                    "policies": {"polling_frequency": 500},
                    "services": {
                        "push_url": "",
                        "remote_settings_url": "",
                        "tokenserver_url": "",
                    },
                    # marionette.port 0 lets the spawned browser pick a free port,
                    # so Felt UI and browser can both run Marionette at once.
                    "extra_prefs": [
                        ["marionette.port", 0],
                        ["telemetry.fog.init_on_shutdown", False],
                    ],
                }
            )
            return

        if path == "/api/browser/key":
            if not self._authed():
                return
            self._json({"data": PRIMARY_SECRET})
            return

        if path == "/api/browser/policies":
            if not self._authed():
                return
            self._json(STATE.policies)
            return

        if path == "/api/browser/whoami":
            if not self._authed():
                return
            self._json(
                {
                    "id": USER_ID,
                    "email": EMAIL,
                    "name": "moz user",
                    "picture": "",
                    "is_active": True,
                    "last_login_at": "2025-11-14T14:27:23.575030Z",
                    "created_at": "2025-10-31T15:11:50.735175Z",
                    "updated_at": "2025-11-14T14:27:23.602803Z",
                    "policy_roles_id": None,
                }
            )
            return

        if path.startswith("/api/browser/updates"):
            self._send(b'<?xml version="1.0"?><updates></updates>', ctype="text/xml")
            return

        if path == "/api/browser/forced_updates_count":
            self._json({"count": 0})
            return

        if path.startswith("/sso/get_device_posture"):
            self._json(_posture())
            return

        if path == "/sso/get_sso_os_version":
            self._json({"os_version": ""})
            return

        if path == "/api/v1/fpn/token":
            now = int(time.time())
            body = {
                "sub": "test",
                "aud": f"http://127.0.0.1:{port}",
                "iat": now,
                "nbf": now,
                "exp": now + 3600,
                "iss": "test",
            }
            enc = base64.b64encode(json.dumps(body).encode()).decode()
            self._json({"token": f"fxn.{enc}.token"})
            return

        self._json({}, 404)

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._journal("POST", body)
        path = urllib.parse.urlparse(self.path).path

        if path == "/api/browser/sso/token":
            try:
                payload = json.loads(body or b"{}")
            except ValueError:
                self._send(b"", 400, "text/plain")
                return
            grant = payload.get("grant_type")
            if grant == "one_time_token":
                if payload.get("one_time_token") != STATE.one_time_token:
                    self._send(b"", 401, "text/plain")
                    return
                STATE.one_time_token = None  # single use
            elif grant == "refresh_token":
                if payload.get("refresh_token") != STATE.refresh_token:
                    self._send(b"", 401, "text/plain")
                    return
            else:
                self._send(b"", 401, "text/plain")
                return
            STATE.access_token = str(uuid.uuid4())
            STATE.refresh_token = str(uuid.uuid4())
            self._json(
                {
                    "access_token": STATE.access_token,
                    "token_type": "Bearer",
                    "expires_in": 71999,
                    "refresh_token": STATE.refresh_token,
                    "posture": _posture(),
                }
            )
            return

        if path == "/api/browser/policies":
            if not self._authed():
                return
            self._json(STATE.policies)
            return

        self._json({}, 404)

    def do_PUT(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._journal("PUT", body)
        self._json({})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--journal", type=Path, required=True)
    ap.add_argument("--port-file", type=Path, required=True)
    ap.add_argument(
        "--policies",
        type=Path,
        default=None,
        help="JSON file with the policy set to serve",
    )
    args = ap.parse_args()

    if args.policies and args.policies.exists():
        STATE.policies = json.loads(args.policies.read_text())

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.journal = args.journal  # type: ignore[attr-defined]
    port = httpd.server_address[1]
    args.port_file.write_text(str(port), encoding="utf-8")
    print(f"[console] listening on 127.0.0.1:{port}", file=sys.stderr, flush=True)
    print(f"[console] primarySecret={PRIMARY_SECRET}", file=sys.stderr, flush=True)
    print(
        f"[console] ssoCookie={COOKIE_NAME}={COOKIE_VALUE}", file=sys.stderr, flush=True
    )
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
