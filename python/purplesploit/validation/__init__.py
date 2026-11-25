"""Operator-driven AD validation automation (PLAN-003).

Consumes aranum's structured findings (detection), offers the operator per-issue
opt-in validation with recommended-default + overridable parameters, runs
parameterized executors that encode the PROVEN per-technique recipes
(claude-mem #66146), and emits ``adlab.plan003.proof.v1`` receipts scored by
ad-lab-harness ``score_proof`` (proved / not-proved / inconclusive).

Flow: enumerate -> plan -> confirm -> execute -> score
(see :class:`purplesploit.validation.orchestrator.ValidationOrchestrator`).

Architecture doc: ``docs/plans/PLAN-validation-automation-24NOV2026.md``.
Specs: claude-mem #66142 (UX), #66146 (recipes), #66119 / #66120 (proof scope).
"""
from __future__ import annotations

from .config import ValidationConfig
from .findings import NormalizedFinding, load_findings, map_finding, validatable
from .orchestrator import ValidationOrchestrator

__all__ = [
    "ValidationConfig",
    "NormalizedFinding",
    "load_findings",
    "map_finding",
    "validatable",
    "ValidationOrchestrator",
]
