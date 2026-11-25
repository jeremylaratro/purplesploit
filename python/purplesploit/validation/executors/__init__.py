"""ValidationExecutor registry: technique -> executor class.

RBCD is fully implemented (the vertical slice, ``rbcd.py``); the other ten
techniques are importable stubs (``stubs.py``) carrying their #66146 recipe and
raising ``StubNotImplemented`` on execute. The orchestrator looks executors up
here by the technique the finding mapper attached.
"""
from __future__ import annotations

from typing import Optional

from .base import (ValidationExecutor, ExecutorContext, CommandRunner,
                   SubprocessRunner, AuthorizationProvider, AuthorizedLabProvider,
                   ValidationPlan, StepRecord, RunResult, StubNotImplemented,
                   redact_argv)
from .rbcd import RBCDExecutor
from .stubs import STUB_EXECUTORS

# Technique -> executor class. The full RBCD executor wins over any stub key.
REGISTRY: dict[str, type[ValidationExecutor]] = {**STUB_EXECUTORS,
                                                 RBCDExecutor.technique: RBCDExecutor}

# Techniques whose recipe is fully wired end-to-end (not a stub).
IMPLEMENTED: frozenset[str] = frozenset({RBCDExecutor.technique})


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
    "REGISTRY", "IMPLEMENTED", "get_executor", "is_implemented",
]
