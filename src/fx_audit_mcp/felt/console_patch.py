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

# The console endpoint carrying enterprise policy to the spawned browser.
# `build_policies_response` renders a fixed menu driven by the server's
# `policy_*` toggles -- BlockAboutConfig, AccessConnector, ExtensionSettings,
# DisableSafeMode, Watermark, SignOut -- with no way to supply any other
# policy. SitePolicies and DataLossPrevention have no toggle at all, so a
# target gated on one of those is unreachable through the stock console.
POLICIES_PATH = "/api/browser/policies"

# Env vars carrying per-run configuration to the handler. Env rather than
# constructor arguments because the handler class is handed to
# multiprocessing.Process: a fork start method would carry the values anyway,
# but forkserver and spawn re-import the class and would lose them, and a
# silently un-applied pref is the failure this whole change exists to fix.
PREFS_ENV = "FXE_AUDIT_EXTRA_PREFS"
DLP_WASM_ENV = "FXE_AUDIT_DLP_WASM"
POLICIES_ENV = "FXE_AUDIT_EXTRA_POLICIES"


def wants_config(path: str) -> bool:
    """Whether a request path is the config endpoint."""
    return path.split("?", 1)[0] == CONFIG_PATH


def wants_dlp_wasm(path: str) -> bool:
    """Whether a request path is the DLP WebAssembly module fetch."""
    return path.split("?", 1)[0].startswith(DLP_WASM_PREFIX)


def wants_policies(path: str) -> bool:
    """Whether a request path is the enterprise policy endpoint."""
    return path.split("?", 1)[0] == POLICIES_PATH


def inject_extra_policies(payload: str, policies: Mapping[str, object]) -> str:
    """Add `policies` to the `policies` object of a console policy response.

    The fork renders `{"policies": {...}}` from its own `policy_*` toggles and
    offers no way to add one that has no toggle. Merging into the rendered
    response keeps the fork authoritative for the policies it does model --
    and for `relaunch`, which sits alongside them -- while making the ones it
    does not reachable.

    Unlike `inject_extra_prefs`, a caller *may* replace an entry the fork
    already sent. The fork's values come from toggles this harness controls
    and are defaults rather than load-bearing wiring: nothing in the session
    handshake depends on them, where `marionette.port` is how the spawned
    browser is reached at all. A target whose whole subject is
    `Watermark` needs to state its own.

    Args:
        payload: The rendered JSON body.
        policies: Policies to add, as policy name -> value.

    Returns:
        The rewritten body, or `payload` unchanged if it is not an object or
        carries no `policies` object -- a shape this does not recognise is one
        to leave alone rather than guess at.
    """
    if not policies:
        return payload
    try:
        doc = json.loads(payload)
    except (ValueError, TypeError):
        return payload
    if not isinstance(doc, dict):
        return payload
    existing = doc.get("policies")
    if not isinstance(existing, dict):
        return payload
    existing.update(policies)
    return json.dumps(doc)


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
    """Decode a JSON-object env var, tolerating absence.

    Used for both PREFS_ENV and POLICIES_ENV; the name predates the second.

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
