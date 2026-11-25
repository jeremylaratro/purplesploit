"""ValidationExecutor registry: technique -> executor class.

Fully implemented: RBCD (``rbcd.py``), KERBEROAST + ASREP (``roast.py``), LAPS
(``laps.py``), CONSTRAINED-DELEG-PT (``constrained_deleg.py``), OPENSHARES-WRITE
(``openshares.py``), SHADOW-CREDS (``shadow_creds.py``), ADCS-ESC1
(``adcs_esc1.py``). The remaining three techniques are importable stubs
(``stubs.py``) carrying their #66146 recipe and raising ``StubNotImplemented`` on
execute. The orchestrator looks executors up here by the technique the finding
mapper attached.
"""
from __future__ import annotations

from typing import Optional

from .base import (ValidationExecutor, ExecutorContext, CommandRunner,
                   SubprocessRunner, AuthorizationProvider, AuthorizedLabProvider,
                   ValidationPlan, StepRecord, RunResult, StubNotImplemented,
                   redact_argv)
from .rbcd import RBCDExecutor
from .roast import KerberoastExecutor, ASREPExecutor
from .laps import LAPSExecutor
from .constrained_deleg import ConstrainedDelegExecutor
from .openshares import OpenSharesExecutor
from .shadow_creds import ShadowCredsExecutor
from .adcs_esc1 import ADCSESC1Executor
from .stubs import STUB_EXECUTORS

# Full executors win over any stub key of the same technique.
_FULL: tuple[type[ValidationExecutor], ...] = (
    RBCDExecutor, KerberoastExecutor, ASREPExecutor, LAPSExecutor,
    ConstrainedDelegExecutor, OpenSharesExecutor, ShadowCredsExecutor,
    ADCSESC1Executor,
)

# Technique -> executor class.
REGISTRY: dict[str, type[ValidationExecutor]] = {
    **STUB_EXECUTORS, **{cls.technique: cls for cls in _FULL},
}

# Techniques whose recipe is fully wired end-to-end (not a stub).
IMPLEMENTED: frozenset[str] = frozenset(cls.technique for cls in _FULL)


def get_executor(technique: Optional[str]) -> Optional[ValidationExecutor]:
    """Instantiate the executor for ``technique``, or ``None`` if unregistered."""
    cls = REGISTRY.get(technique or "")
    return cls() if cls is not None else None


def is_implemented(technique: Optional[str]) -> bool:
    return technique in IMPLEMENTED


__all__ = [
    "ValidationExecutor", "ExecutorContext", "CommandRunner", "SubprocessRunner",
    "AuthorizationProvider", "AuthorizedLabProvider", "ValidationPlan", "StepRecord",
    "RunResult", "StubNotImplemented", "redact_argv", "RBCDExecutor",
    "KerberoastExecutor", "ASREPExecutor", "LAPSExecutor",
    "ConstrainedDelegExecutor", "OpenSharesExecutor", "ShadowCredsExecutor",
    "ADCSESC1Executor",
    "REGISTRY", "IMPLEMENTED", "get_executor", "is_implemented",
]
