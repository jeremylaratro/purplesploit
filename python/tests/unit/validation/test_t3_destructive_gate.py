"""T3 per-call runtime destructive-confirmation gate (base.py's
DestructiveConfirmationProvider / InteractiveDestructiveConfirmer /
NonInteractiveDestructiveConfirmer), tested in isolation from any executor --
this is the mechanism FORCE-CHANGE-PASSWORD, GENERIC-ALL's reset_password
pivot, and GPO-ABUSE all gate their irreversible/code-exec write through
(plan §4.1/§4.3).
"""
from __future__ import annotations

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
    InteractiveDestructiveConfirmer, NonInteractiveDestructiveConfirmer,
)


class _NullRunner(CommandRunner):
    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        return RunResult(0, stdout="")


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


# ======================================================================= NonInteractive
def test_noninteractive_confirmer_allows_only_when_explicitly_flagged():
    confirmer = NonInteractiveDestructiveConfirmer(allowed=True, warn_fn=lambda s: None)
    assert confirmer.confirm("gpo_abuse_immediate_task", {"gpo": "x"}) is True


def test_noninteractive_confirmer_fails_closed_by_default():
    confirmer = NonInteractiveDestructiveConfirmer(allowed=False, warn_fn=lambda s: None)
    assert confirmer.confirm("force_change_password", {"victim": "arya.stark"}) is False


def test_noninteractive_confirmer_always_warns_regardless_of_outcome():
    warnings = []
    for allowed in (True, False):
        confirmer = NonInteractiveDestructiveConfirmer(allowed=allowed, warn_fn=warnings.append)
        confirmer.confirm("op", {"k": "v"})
    assert len(warnings) == 2
    assert all("op" in w and "{'k': 'v'}" in w for w in warnings)


# ======================================================================= Interactive
def test_interactive_confirmer_proceeds_only_on_exact_yes():
    confirmer = InteractiveDestructiveConfirmer(prompt_fn=lambda _: "yes", warn_fn=lambda s: None)
    assert confirmer.confirm("force_change_password", {}) is True


def test_interactive_confirmer_refuses_anything_other_than_lowercase_yes():
    for answer in ("y", "Yes", "YES", "sure", ""):
        confirmer = InteractiveDestructiveConfirmer(prompt_fn=lambda _: answer,
                                                     warn_fn=lambda s: None)
        assert confirmer.confirm("op", {}) is False, repr(answer)


def test_interactive_confirmer_strips_surrounding_whitespace_around_yes():
    confirmer = InteractiveDestructiveConfirmer(prompt_fn=lambda _: "  yes  ",
                                                warn_fn=lambda s: None)
    assert confirmer.confirm("op", {}) is True


def test_interactive_confirmer_fails_closed_on_eof():
    def _raise_eof(_prompt):
        raise EOFError()
    confirmer = InteractiveDestructiveConfirmer(prompt_fn=_raise_eof, warn_fn=lambda s: None)
    assert confirmer.confirm("op", {}) is False


# ======================================================================= ExecutorContext default
def test_executor_context_defaults_to_failclosed_noninteractive_confirmer():
    cfg = _cfg()  # allow_destructive defaults to False
    ctx = ExecutorContext(cfg, runner=_NullRunner(), authorizer=AuthorizedLabProvider(True),
                          output_dir=".")
    assert isinstance(ctx.destructive_confirmer, NonInteractiveDestructiveConfirmer)
    assert ctx.destructive_confirmer.confirm("any_op", {}) is False


def test_executor_context_honors_allow_destructive_when_no_confirmer_injected():
    cfg = _cfg(allow_destructive=True)
    ctx = ExecutorContext(cfg, runner=_NullRunner(), authorizer=AuthorizedLabProvider(True),
                          output_dir=".")
    assert ctx.destructive_confirmer.confirm("any_op", {}) is True


def test_executor_context_never_overrides_an_injected_confirmer():
    cfg = _cfg(allow_destructive=True)
    injected = NonInteractiveDestructiveConfirmer(allowed=False, warn_fn=lambda s: None)
    ctx = ExecutorContext(cfg, runner=_NullRunner(), authorizer=AuthorizedLabProvider(True),
                          output_dir=".", destructive_confirmer=injected)
    assert ctx.destructive_confirmer is injected
    assert ctx.destructive_confirmer.confirm("any_op", {}) is False
