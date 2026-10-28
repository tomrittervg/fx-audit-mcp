"""Tests for felt/evaluator.py.

`felt_browser_evaluator` itself needs a Firefox Enterprise build and the
fork's checkout, so it is `# pragma: no cover`; the decisions it makes that
can be got wrong without one are here.
"""

import inspect

from ffpuppet.helpers import SANDBOX_ENV_VARS

from fx_audit_mcp.browser_evaluator import browser_evaluator
from fx_audit_mcp.felt.evaluator import apply_sandbox_env, felt_browser_evaluator


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
