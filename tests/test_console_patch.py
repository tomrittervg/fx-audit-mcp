"""Tests for felt/console_patch.py.

These cover the decisions the audit console handler makes. The handler itself
imports felt_tests and so only exists under `mach python`; everything that can
be got wrong is here.
"""

import json

from fx_audit_mcp.felt.console_patch import (
    ACCOUNT_EMAIL,
    ACCOUNT_PATH,
    ACCOUNT_UID,
    CONFIG_PATH,
    POLICIES_PATH,
    build_account_response,
    inject_extra_policies,
    inject_extra_prefs,
    parse_prefs_env,
    wants_account,
    wants_config,
    wants_dlp_wasm,
    wants_policies,
)

# The shape the fork sends, reduced to the field that matters.
STOCK_CONFIG = json.dumps(
    {
        "learn_more_url": "https://example.invalid/",
        "extra_prefs": [
            ["marionette.port", 0],
            ["telemetry.fog.init_on_shutdown", False],
        ],
    }
)


class TestPathMatching:
    def test_config_path_matches_with_and_without_query(self) -> None:
        assert wants_config(CONFIG_PATH)
        assert wants_config(f"{CONFIG_PATH}?cachebust=1")
        assert not wants_config("/api/browser/configuration")
        assert not wants_config("/api/browser/key")

    def test_dlp_wasm_matches_the_versioned_path(self) -> None:
        """ConsoleClient builds the path from the browser's own version."""
        assert wants_dlp_wasm(
            "/api/browser/content-analysis-wasm/update/161.0/20261029052345/0.0.0"
        )
        assert not wants_dlp_wasm("/api/browser/content-analysis")
        assert not wants_dlp_wasm("/api/browser/config")


class TestInjectExtraPrefs:
    def test_adds_without_dropping_the_forks_own(self) -> None:
        """marionette.port must survive: it is how the spawned browser is reached."""
        out = json.loads(inject_extra_prefs(STOCK_CONFIG, {"fuzzing.enabled": True}))
        names = [e[0] for e in out["extra_prefs"]]
        assert "marionette.port" in names
        assert "telemetry.fog.init_on_shutdown" in names
        assert ["fuzzing.enabled", True] in out["extra_prefs"]

    def test_leaves_the_rest_of_the_response_alone(self) -> None:
        out = json.loads(inject_extra_prefs(STOCK_CONFIG, {"a.b": 1}))
        assert out["learn_more_url"] == "https://example.invalid/"

    def test_does_not_override_an_entry_the_fork_already_sent(self) -> None:
        """A caller must not be able to retarget marionette.port by accident."""
        out = json.loads(inject_extra_prefs(STOCK_CONFIG, {"marionette.port": 9999}))
        ports = [e[1] for e in out["extra_prefs"] if e[0] == "marionette.port"]
        assert ports == [0]

    def test_no_prefs_is_byte_identical(self) -> None:
        assert inject_extra_prefs(STOCK_CONFIG, {}) == STOCK_CONFIG

    def test_unrecognised_payload_is_passed_through(self) -> None:
        """A response shape this does not understand is left alone, not guessed at."""
        for payload in ("not json", "[]", json.dumps({"no_extra_prefs": 1})):
            assert inject_extra_prefs(payload, {"x": 1}) == payload


class TestParsePrefsEnv:
    def test_round_trips(self) -> None:
        assert parse_prefs_env(json.dumps({"a": 1, "b": True})) == {"a": 1, "b": True}

    def test_absent_or_malformed_yields_nothing(self) -> None:
        """Never raise: this runs inside a server process mid-handshake, where a
        traceback surfaces as an unexplained 500."""
        for raw in (None, "", "not json", "[1,2]", "null"):
            assert parse_prefs_env(raw) == {}


STOCK_POLICIES = json.dumps(
    {
        "policies": {"BlockAboutConfig": True, "DisableSafeMode": False},
        "relaunch": {"delay": 5},
    }
)


class TestInjectExtraPolicies:
    def test_adds_a_policy_the_fork_cannot_express(self) -> None:
        """SitePolicies has no policy_* toggle; this is its only route."""
        site = {"Rules": [{"Match": ["https://example.com/*"], "Block": True}]}
        out = json.loads(inject_extra_policies(STOCK_POLICIES, {"SitePolicies": site}))
        assert out["policies"]["SitePolicies"] == site

    def test_keeps_the_forks_own_policies(self) -> None:
        out = json.loads(inject_extra_policies(STOCK_POLICIES, {"SitePolicies": {}}))
        assert out["policies"]["BlockAboutConfig"] is True
        assert out["policies"]["DisableSafeMode"] is False

    def test_leaves_relaunch_alone(self) -> None:
        """relaunch is a sibling of policies, not one of them."""
        out = json.loads(inject_extra_policies(STOCK_POLICIES, {"Watermark": {}}))
        assert out["relaunch"] == {"delay": 5}

    def test_may_replace_a_policy_the_fork_sent(self) -> None:
        """Unlike prefs: a target whose subject is Watermark must set its own.

        The fork's values come from toggles and are defaults; no part of the
        session handshake reads them.
        """
        out = json.loads(
            inject_extra_policies(STOCK_POLICIES, {"BlockAboutConfig": False})
        )
        assert out["policies"]["BlockAboutConfig"] is False

    def test_no_policies_is_byte_identical(self) -> None:
        assert inject_extra_policies(STOCK_POLICIES, {}) == STOCK_POLICIES

    def test_unrecognised_payload_is_passed_through(self) -> None:
        for payload in ("not json", "[]", json.dumps({"no_policies": 1})):
            assert inject_extra_policies(payload, {"x": 1}) == payload


class TestPolicyPathMatching:
    def test_matches_with_and_without_query(self) -> None:
        assert wants_policies(POLICIES_PATH)
        assert wants_policies(f"{POLICIES_PATH}?v=2")
        assert not wants_policies("/api/browser/policies/extra")
        assert not wants_policies(CONFIG_PATH)

    def test_config_and_policies_do_not_collide(self) -> None:
        """reply() dispatches on these two; an overlap would inject the wrong body."""
        assert not wants_config(POLICIES_PATH)
        assert not wants_policies(CONFIG_PATH)


class TestAccountPathMatching:
    """wants_account, which gates the endpoint the fork never implemented."""

    def test_matches_the_account_path(self) -> None:
        assert wants_account(ACCOUNT_PATH)

    def test_ignores_the_query_string(self) -> None:
        assert wants_account(f"{ACCOUNT_PATH}?device_id=abc")

    def test_rejects_siblings_and_prefixes(self) -> None:
        assert not wants_account(CONFIG_PATH)
        assert not wants_account(POLICIES_PATH)
        # A prefix match would swallow endpoints the fork does implement.
        assert not wants_account(f"{ACCOUNT_PATH}/devices")


class TestBuildAccountResponse:
    """The payload EnterpriseStorageManager caches for the whole session."""

    def test_carries_the_fields_fxa_requires(self) -> None:
        """`uid` is load-bearing: without it updateAccountData throws."""
        doc = json.loads(build_account_response(None))
        assert doc["uid"] == ACCOUNT_UID
        assert doc["email"] == ACCOUNT_EMAIL
        assert doc["verified"] is True

    def test_ships_no_session_token(self) -> None:
        """`hasLocalSession()` is `!!data.sessionToken`.

        Supplying one makes the browser claim an FxA session it does not
        have and start fetching profile, session-status and device
        registration from a console that serves none of `/api/fxa/*` -- a
        worse failure than the 404 this route replaced.
        """
        assert "sessionToken" not in json.loads(build_account_response(None))

    def test_uid_is_stable_across_processes(self) -> None:
        """A findings artifact is a reproduction recipe; this must not drift.

        Compares against the literal, not against `ACCOUNT_UID`: the
        self-referential form passes even if the constant becomes
        `uuid4().hex`, which is the regression that matters.
        """
        assert ACCOUNT_UID == "a0b1c2d3e4f5061728394a5b6c7d8e9f"
        assert len(ACCOUNT_UID) == 32
        assert build_account_response(None) == build_account_response(None)

    def test_constants_match_the_product_and_the_console(self) -> None:
        """Pinned against the other side, not against themselves.

        `ACCOUNT_PATH` must equal `ConsoleClient._paths.FXACCOUNT`, and
        `ACCOUNT_EMAIL` must equal the address `felt_tests.py` hardcodes in
        `/sso/callback` and `/api/browser/whoami`. Asserting
        `wants_account(ACCOUNT_PATH)` cannot see a typo in either; this can.
        """
        assert ACCOUNT_PATH == "/api/browser/account"
        assert ACCOUNT_EMAIL == "nobody@mozilla.org"

    def test_echoes_the_posted_device_id(self) -> None:
        doc = json.loads(build_account_response(None, device_id="dev-7"))
        assert doc["device"] == {"id": "dev-7"}

    def test_absent_device_id_adds_no_device(self) -> None:
        assert "device" not in json.loads(build_account_response(None))
        assert "device" not in json.loads(build_account_response(None, device_id=""))

    def test_caller_overrides_win_including_uid(self) -> None:
        """A run that needs a specific account must be able to state one."""
        raw = json.dumps({"uid": "f" * 32, "email": "her@example.invalid"})
        doc = json.loads(build_account_response(raw))
        assert doc["uid"] == "f" * 32
        assert doc["email"] == "her@example.invalid"
        # Unmentioned fixture fields survive.
        assert doc["verified"] is True

    def test_caller_device_beats_the_posted_id(self) -> None:
        raw = json.dumps({"device": {"id": "chosen"}})
        doc = json.loads(build_account_response(raw, device_id="posted"))
        assert doc["device"] == {"id": "chosen"}

    def test_malformed_override_falls_back_to_the_fixture(self) -> None:
        """A 500 mid-handshake is worse than ignoring an unusable value."""
        for raw in ("not json", "[1,2]", ""):
            assert json.loads(build_account_response(raw))["uid"] == ACCOUNT_UID

    def test_ships_no_sync_keys(self) -> None:
        """Documented limit: invented key material that cannot decrypt is
        worse than none, so a Sync target must supply its own."""
        assert "scopedKeys" not in json.loads(build_account_response(None))
