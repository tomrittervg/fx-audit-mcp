"""Tests for felt/evaluator.py.

`felt_browser_evaluator` itself needs a Firefox Enterprise build and the
fork's checkout, so it is `# pragma: no cover`; the decisions it makes that
can be got wrong without one are here.
"""

import inspect
from pathlib import Path
from typing import get_args, get_type_hints

import pytest
from ffpuppet.helpers import SANDBOX_ENV_VARS

from fx_audit_mcp.browser_evaluator import browser_evaluator
from fx_audit_mcp.felt.evaluator import (
    FELT_UI_REMOTE_TYPE_JS,
    OPEN_TESTCASE_IN_FELT_UI_JS,
    _managed_profile_port_file,
    _submit_idp_form,
    apply_sandbox_env,
    felt_browser_evaluator,
)


class TestApplySandboxEnv:
    def test_disabled_by_default_sets_every_variable(self) -> None:
        env: dict[str, str] = {}
        apply_sandbox_env(env, enable_sandbox=False)
        assert {k: env[k] for k in SANDBOX_ENV_VARS} == dict.fromkeys(
            SANDBOX_ENV_VARS, "1"
        )

    def test_enabled_removes_rather_than_zeroes(self) -> None:
        """Firefox checks by presence, so "0" would disable the sandbox."""
        env = dict.fromkeys(SANDBOX_ENV_VARS, "1")
        apply_sandbox_env(env, enable_sandbox=True)
        assert not [k for k in SANDBOX_ENV_VARS if k in env]

    def test_enabled_clears_an_inherited_variable(self) -> None:
        """The reason both branches write: `env` starts from os.environ.

        A MOZ_DISABLE_*_SANDBOX inherited from the container would otherwise
        unsandbox a run that asked for a sandbox, silently.
        """
        env = {"MOZ_DISABLE_CONTENT_SANDBOX": "1", "HOME": "/home/x"}
        apply_sandbox_env(env, enable_sandbox=True)
        assert "MOZ_DISABLE_CONTENT_SANDBOX" not in env

    def test_disabled_overrides_an_inherited_removal(self) -> None:
        env = {"HOME": "/home/x"}
        apply_sandbox_env(env, enable_sandbox=False)
        assert env["MOZ_DISABLE_CONTENT_SANDBOX"] == "1"

    def test_leaves_unrelated_variables_alone(self) -> None:
        for enable in (True, False):
            env = {"HOME": "/home/x", "MOZ_LOG": "console:5"}
            apply_sandbox_env(env, enable_sandbox=enable)
            assert env["HOME"] == "/home/x"
            assert env["MOZ_LOG"] == "console:5"

    def test_covers_every_process_type_ffpuppet_knows(self) -> None:
        """Imported, not retyped: a list that drifts is a silent regression."""
        env: dict[str, str] = {}
        apply_sandbox_env(env, enable_sandbox=False)
        assert set(env) == set(SANDBOX_ENV_VARS)
        assert len(SANDBOX_ENV_VARS) >= 7


def test_enable_sandbox_matches_browser_evaluator() -> None:
    """Same name, type and default, so a testcase can move between the two."""
    felt = inspect.signature(felt_browser_evaluator).parameters["enable_sandbox"]
    stock = inspect.signature(browser_evaluator).parameters["enable_sandbox"]
    assert felt.default is stock.default is False
    assert felt.annotation == stock.annotation


class TestMarionettePortTimeout:
    """The timeout that fired on 21 of 183 runs in one batch.

    It named no file, so 19 of those runs then guessed at log paths under
    /tmp and got "No such file" -- one diagnosable failure became two
    undiagnosable ones.
    """

    def test_names_the_logs_that_have_content(self, tmp_path: Path) -> None:
        logs = tmp_path / "logs"
        logs.mkdir()
        (logs / "log_stderr.txt").write_text("Not enough cookies!!\n")
        (logs / "log_console.txt").write_text("console output\n")
        (logs / "log_empty.txt").write_text("")

        with pytest.raises(TimeoutError) as exc_info:
            _managed_profile_port_file(tmp_path / "home", 0.01, log_dir=logs)

        message = str(exc_info.value)
        assert str(logs / "log_stderr.txt") in message
        assert str(logs / "log_console.txt") in message
        # An empty file is a dead end, not a lead.
        assert "log_empty.txt" not in message

    def test_says_so_when_nothing_was_written(self, tmp_path: Path) -> None:
        """No logs at all means the UI never started -- a different diagnosis."""
        logs = tmp_path / "logs"
        logs.mkdir()
        with pytest.raises(TimeoutError) as exc_info:
            _managed_profile_port_file(tmp_path / "home", 0.01, log_dir=logs)
        assert "none were written" in str(exc_info.value)

    def test_names_the_paths_it_searched(self, tmp_path: Path) -> None:
        with pytest.raises(TimeoutError) as exc_info:
            _managed_profile_port_file(tmp_path / "home", 0.01)
        message = str(exc_info.value)
        assert "firefoxenterprise" in message
        assert "MarionetteActivePort" in message

    def test_returns_the_port_file_when_it_appears(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        prof = home / ".mozilla" / "firefoxenterprise" / "enterprise-profile-x"
        prof.mkdir(parents=True)
        (prof / "MarionetteActivePort").write_text("12345")
        got = _managed_profile_port_file(home, 1.0, log_dir=None)
        assert got.read_text() == "12345"


class TestFeltUiAttackerPosition:
    """Loading the testcase where the Felt actors actually are.

    Felt actors register under `Services.felt?.isFeltUI()`, true only in the
    Felt UI process. From the spawned browser `getActor("FeltProcess")` raises
    NotFoundError, so a clean result there says nothing about the fork's actor
    surface.
    """

    def test_default_is_the_spawned_browser(self) -> None:
        """The new position is opt-in; most targets want ordinary browsing."""
        param = inspect.signature(felt_browser_evaluator).parameters["attacker_process"]
        assert param.default == "spawned"

    def test_only_the_two_positions_are_accepted(self) -> None:
        # get_type_hints, not the raw annotation: the module uses
        # `from __future__ import annotations`, so annotations are strings.
        hints = get_type_hints(felt_browser_evaluator)
        assert get_args(hints["attacker_process"]) == ("spawned", "felt_ui")

    def test_loads_the_portal_browser_not_the_signin_browser(self) -> None:
        """`#browser` holds the console sign-in document; replacing it ends
        the session this tool just established."""
        assert 'getElementById("portal-browser")' in OPEN_TESTCASE_IN_FELT_UI_JS
        assert 'getElementById("browser")' not in OPEN_TESTCASE_IN_FELT_UI_JS

    def test_mirrors_the_production_captive_portal_load(self) -> None:
        """This is CaptivePortal.showOverlay's load, not a harness invention.

        It must use fixupAndLoadURIString with a null principal carrying the
        private browsing id -- without the id the origin attributes do not
        match the docshell and the document does not land in the process a
        real portal page lands in.
        """
        assert "fixupAndLoadURIString" in OPEN_TESTCASE_IN_FELT_UI_JS
        assert "createNullPrincipal" in OPEN_TESTCASE_IN_FELT_UI_JS
        assert "privateBrowsingId" in OPEN_TESTCASE_IN_FELT_UI_JS

    def test_reads_the_id_from_the_fork_rather_than_hardcoding_it(self) -> None:
        """A hardcoded 1 would silently diverge if the fork changed it."""
        assert "FeltCommon.PRIVATE_BROWSING_ID" in OPEN_TESTCASE_IN_FELT_UI_JS
        assert "privateBrowsingId: 1" not in OPEN_TESTCASE_IN_FELT_UI_JS

    def test_does_not_assume_gbrowser(self) -> None:
        """felt.xhtml has no gBrowser -- that is why this is a separate script."""
        assert "gBrowser" not in OPEN_TESTCASE_IN_FELT_UI_JS
        assert "gBrowser" not in FELT_UI_REMOTE_TYPE_JS

    def test_the_probe_reports_where_the_document_landed(self) -> None:
        """remote_type is how a run proves it was web content, not an assumption."""
        assert "remoteType" in FELT_UI_REMOTE_TYPE_JS
        assert "portal-browser" in FELT_UI_REMOTE_TYPE_JS


class TestFeltUiWindowSurvival:
    """The two bugs that made attacker_process="felt_ui" fail 258/258.

    Both are about the Felt UI session still being usable after sign-in:
    the window has to still exist, and Marionette has to still be pointed at
    its chrome document.
    """

    def test_keep_window_pref_is_in_the_felt_ui_profile_writer(self) -> None:
        """It must be in the UI's own user.js, not the `prefs` parameter.

        `prefs` travels through the console's config response, which only the
        *spawned* browser fetches -- several runs tried that and reported it
        did not reach the Felt parent.
        """
        src = inspect.getsource(felt_browser_evaluator)
        assert "enterprise.felt_tests.should_not_close_window" in src
        marker = src.index("enterprise.felt_tests.should_not_close_window")
        # It belongs to the user.js write, alongside the Felt UI's own port.
        assert "marionette.port" in src[marker : marker + 400]

    def test_idp_form_restores_chrome_context(self) -> None:
        """_submit_idp_form switches to content and must switch back.

        The portal load reads `#portal-browser` off the chrome document, so a
        session left in content context finds nothing. Checked on both paths,
        which is why the restore is in a `finally`.
        """
        src = inspect.getsource(_submit_idp_form)
        assert 'set_context("content")' in src
        assert 'set_context("chrome")' in src
        assert "finally:" in src
        # The restore must come after the content switch, not before it.
        assert src.index('set_context("content")') < src.index("finally:")
