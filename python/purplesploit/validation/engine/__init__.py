"""Modular chaining engine (PLAN-C): compose validated techniques into a
capability-state graph that reaches Domain Admin by SEARCH, not a script.

Public surface:
    ChainEngine   -- search + execute a path seed -> goal, with verified teardown.
    ChainReport   -- the public outcome (names + receipts + teardown, no payloads).
    default_edges -- every IMPLEMENTED executor that carries pre/eff annotations.
    da_in_minutes -- convenience: build the engine from the default edges and run.
"""
from __future__ import annotations

from typing import Any

from .. import states
from ..executors import IMPLEMENTED, get_executor
from ..executors.base import ExecutorContext, ValidationExecutor
from .chain_engine import ChainEngine, ChainReport, FindingFor, OPERATOR_SEED

__all__ = [
    "ChainEngine", "ChainReport", "FindingFor", "OPERATOR_SEED",
    "default_edges", "da_in_minutes",
]


def default_edges() -> list[ValidationExecutor]:
    """Every implemented executor instance -- the engine keeps only those with a
    non-empty ``pre`` AND ``eff`` (annotated for C), so a newly-annotated edge
    participates automatically with no engine change."""
    return [e for e in (get_executor(t) for t in sorted(IMPLEMENTED)) if e is not None]


def da_in_minutes(base_ctx: ExecutorContext, finding_for: FindingFor, *,
                  goal: str = states.S_DA,
                  allow_crack: bool = False,
                  allow_destructive: bool = False) -> ChainReport:
    """Find and execute the shortest viable path from operator creds to Domain
    Admin on the already-enumerated domain, threading each edge's product into the
    next and tearing down every mutation (verified). ``finding_for(edge)`` returns
    the finding that edge acts on (from the enumeration), or ``None`` to skip it.
    """
    engine = ChainEngine(default_edges(), goal=goal,
                         allow_crack=allow_crack, allow_destructive=allow_destructive)
    return engine.run(base_ctx, finding_for)
