"""Tests for felt/evaluator.py.

`felt_browser_evaluator` itself needs a Firefox Enterprise build and the
fork's checkout, so it is `# pragma: no cover`; the decisions it makes that
can be got wrong without one are here.
"""

import inspect
from pathlib import Path

import pytest
from ffpuppet.helpers import SANDBOX_ENV_VARS

from fx_audit_mcp.browser_evaluator import browser_evaluator
from fx_audit_mcp.felt.evaluator import (
    _managed_profile_port_file,
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
