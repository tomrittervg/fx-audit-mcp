#!/usr/bin/env python3
"""The fork's console handler, extended with what an audit needs.

Imports `felt_tests` at module scope, so this is only importable under the
checkout's `mach python` -- `console_launcher` is the only importer. The
decisions it makes live in `console_patch`, which is importable anywhere and
carries the tests.

Four additions, none of which the stock handler can express:

- `/api/browser/account`, which the stock console does not implement at all:
  `ConsoleClient._paths` declares ten endpoints and `felt_tests.py` answers
  eight. Without it `getFxAccountData()` rejects and every target behind
  account or Sync state dead-ends -- four did in one batch, and the only run
  that reached that surface got there by patching this console itself.

- `/api/browser/content-analysis-wasm/...`, which the stock console answers
  with 404. `WasmModuleBackend` then has nothing to fetch, so the whole DLP
  path is unreachable and a target on it cannot be exercised at all.
- `extra_prefs` in the config response, which the stock handler hardcodes.
  It is the only way a pref reaches the browser Felt spawns, because Felt
  chooses that browser's profile.
- extra entries in the policy response, which the stock handler renders from
  a fixed menu of `policy_*` toggles. SitePolicies and DataLossPrevention
  have no toggle, so without this a target gated on either cannot be reached
  at all -- the gap an audit run hit on `SitePolicyUtils.sys.mjs`.

Deliberately a subclass. Every other endpoint, and the entire session
handshake, stays the fork's own code -- the point of running their servers
rather than reimplementing them. This adds one route and edits one field.

The class is defined at module scope on purpose: it is handed to
multiprocessing.Process, and a class built inside a function cannot be
pickled if the start method is forkserver or spawn.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from console_patch import (  # type: ignore[import-not-found]
    ACCOUNT_ENV,
    DLP_WASM_ENV,
    POLICIES_ENV,
    PREFS_ENV,
    build_account_response,
    inject_extra_policies,
    inject_extra_prefs,
    parse_prefs_env,
    wants_account,
    wants_config,
    wants_dlp_wasm,
    wants_policies,
)
from felt_tests import ConsoleHttpHandler  # type: ignore[import-not-found]


class AuditConsoleHandler(ConsoleHttpHandler):  # type: ignore[misc]
    """ConsoleHttpHandler plus the DLP module route and injectable prefs."""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's dispatch name
        """Serve the DLP module; delegate everything else to the fork."""
        if wants_dlp_wasm(self.path):
            self._serve_dlp_wasm()
            return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's dispatch name
        """Serve the FxA account endpoint; delegate everything else."""
        if wants_account(self.path):
            self._serve_account()
            return
        super().do_POST()

    def reply(
        self,
        payload: str,
        code: int = 200,
        status: str = "Success",
        contentType: str | None = None,  # noqa: N803 - the fork's spelling
    ) -> None:
        """Add the run's prefs and policies on the way out.

        Overriding the shared reply helper rather than reimplementing
        `/api/browser/config` and `/api/browser/policies` keeps the fork
        responsible for the rest of those responses, which is most of what
        makes a session work.
        """
        if code == 200:
            if wants_config(self.path):
                payload = inject_extra_prefs(
                    payload, parse_prefs_env(os.environ.get(PREFS_ENV))
                )
            elif wants_policies(self.path):
                payload = inject_extra_policies(
                    payload, parse_prefs_env(os.environ.get(POLICIES_ENV))
                )
        super().reply(payload, code, status, contentType)

    def _serve_account(self) -> None:
        """Answer the account fetch with the run's FxA account data.

        Authenticated: `getFxAccountData` posts it with a bearer token, and
        the authenticated stock endpoints check it the same way. (Not all of
        them do -- `/api/browser/config` and the token endpoint do not -- but
        an account payload is the kind that should.)

        The body is read whether or not it parses. That is hygiene rather
        than a live requirement today: the fork's handler never raises
        `protocol_version`, so it stays HTTP/1.0 and closes every connection,
        and an unread body cannot desynchronise a next request that does not
        exist. It matters if that is ever raised to HTTP/1.1 -- note the
        `check_auth` rejection path returns without reading, so the handler
        would need revisiting as a whole rather than just here.
        """
        if not self.check_auth():
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw_body = self.rfile.read(length) if length > 0 else b""
        device_id = None
        if raw_body:
            # A body this does not understand is not fatal: device_id is an
            # optimisation (the browser only sends it once it has one), and
            # failing the whole request over it would reintroduce the 404.
            try:
                posted = json.loads(raw_body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                posted = None
            if isinstance(posted, dict):
                candidate = posted.get("device_id")
                if isinstance(candidate, str) and candidate:
                    device_id = candidate
        self.reply(
            build_account_response(os.environ.get(ACCOUNT_ENV), device_id),
            contentType="application/json",
        )

    def _serve_dlp_wasm(self) -> None:
        """Answer the module fetch with the configured WebAssembly bytes.

        Authenticated like its siblings: ConsoleClient fetches it with a
        bearer token, and answering an unauthenticated request would make this
        the one endpoint that does not, which is exactly the sort of
        divergence an audit should not introduce into its own harness.
        """
        if not self.check_auth():
            return
        configured = os.environ.get(DLP_WASM_ENV)
        if not configured:
            self.not_found(self.path)
            return
        path = Path(configured)
        if not path.is_file():
            self.not_found(self.path)
            return
        content = path.read_bytes()
        # Written straight to wfile: the inherited reply() encodes str as utf8
        # and would corrupt a binary body. Mirrors how the fork serves
        # /downloads/.
        self.send_response(200, "Success")
        self.send_header("Content-Type", "application/wasm")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)
