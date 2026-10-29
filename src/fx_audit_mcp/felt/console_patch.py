#!/usr/bin/env python3
"""The decisions the audit console handler makes, as pure functions.

Split out from the handler itself so they can be tested without a Firefox
checkout. `audit_handler` imports `felt_tests` at module scope and is therefore
only importable under `mach python`; everything here is importable anywhere,
and everything here is what can actually be got wrong.

What this exists to support is in `testing/enterprise/CONSOLE_CONTRACT.md` in
the fork, under the subclassing section.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

# The console endpoint whose JSON carries prefs to the *spawned* browser. Felt
# chooses that browser's profile, so prefs cannot be written to it directly;
# this response is the only delivery path.
CONFIG_PATH = "/api/browser/config"

# ConsoleClient builds this as
# /api/browser/content-analysis-wasm/update/<version>/<buildID>/0.0.0, so match
# the stable prefix rather than the whole thing -- the version and build id
# belong to whatever browser is asking.
DLP_WASM_PREFIX = "/api/browser/content-analysis-wasm/"

# Env vars carrying per-run configuration to the handler. Env rather than
# constructor arguments because the handler class is handed to
# multiprocessing.Process: a fork start method would carry the values anyway,
# but forkserver and spawn re-import the class and would lose them, and a
# silently un-applied pref is the failure this whole change exists to fix.
PREFS_ENV = "FXE_AUDIT_EXTRA_PREFS"
DLP_WASM_ENV = "FXE_AUDIT_DLP_WASM"


def wants_config(path: str) -> bool:
    """Whether a request path is the config endpoint."""
    return path.split("?", 1)[0] == CONFIG_PATH


def wants_dlp_wasm(path: str) -> bool:
    """Whether a request path is the DLP WebAssembly module fetch."""
    return path.split("?", 1)[0].startswith(DLP_WASM_PREFIX)


def inject_extra_prefs(payload: str, prefs: Mapping[str, object]) -> str:
    """Add `prefs` to the `extra_prefs` of a console config response.

    The fork builds the whole config and hardcodes `extra_prefs` to
    `marionette.port` and `telemetry.fog.init_on_shutdown`
    (`felt_tests.py`, `/api/browser/config`), with no parameter to extend it.
    Rewriting the rendered response leaves the fork authoritative for
    everything else, which matters because the rest of that object is what
    makes a session work at all.

    Entries are appended, never replaced: `marionette.port` in particular is
    how the spawned browser gets an addressable port that does not collide
    with the Felt UI's, and dropping it would cost the attach.

    Args:
        payload: The rendered JSON body.
        prefs: Preferences to add, as name -> value.

    Returns:
        The rewritten body, or `payload` unchanged if it is not an object or
        carries no `extra_prefs` list -- a response shape this does not
        recognise is one to leave alone rather than guess at.
    """
    if not prefs:
        return payload
    try:
        doc = json.loads(payload)
    except (ValueError, TypeError):
        return payload
    if not isinstance(doc, dict):
        return payload
    existing = doc.get("extra_prefs")
    if not isinstance(existing, list):
        return payload
    # The wire format is a list of [name, value] pairs, not an object.
    already = {e[0] for e in existing if isinstance(e, list) and e}
    for name, value in prefs.items():
        if name not in already:
            existing.append([name, value])
    return json.dumps(doc)


def parse_prefs_env(raw: str | None) -> dict[str, object]:
    """Decode the prefs env var, tolerating absence.

    Args:
        raw: The raw env value, or None.

    Returns:
        The decoded mapping, or an empty one if unset or unusable. A malformed
        value yields no prefs rather than an exception: the handler runs inside
        a server process whose traceback would surface as an unexplained 500
        mid-handshake.
    """
    if not raw:
        return {}
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return doc if isinstance(doc, dict) else {}
