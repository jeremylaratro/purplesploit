"""Capability discovery: probe EVERY technique from the operator's creds + scope, report
per-technique viability, and (opt-in) auto-exploit the ELIGIBLE set.

Closes the audit's "scan identifies only 18/29" gap: probing every technique directly
surfaces the probe-detectable edges (BRONZE-BIT/S4U2SELF/ESC8/ESC11/CERTIFRIED) the aranum
findings-mapper misses.

SAFETY (plan-reviewed):
- Discovery itself is READ-ONLY (precondition probes are non-destructive reads).
- Auto-exploit eligibility (ALL must hold): implemented + ``verified_recipe`` ∧ probe
  ``viable ∧ ¬unknown`` ∧ required params complete ∧ (``¬mutating ∧ ¬destructive`` ∨
  ``allow_destructive``). Everything else is REPORTED, never fired.
- Candidate ``entity`` is empty: the position-based probes read ``cfg.username`` directly,
  so no selector is ever set to the operator's own identity (no self-as-victim mutation).
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Optional

from .findings import NormalizedFinding
from .executors import IMPLEMENTED, get_executor, is_implemented
from .executors.base import ExecutorContext
from . import probes as probes_mod

# A viability probe is a cheap read; bound its per-op time so one slow/hanging read
# cannot stall a whole-fleet discovery scan (the default tool timeout is minutes).
_PROBE_TIMEOUT_CAP = 30


def candidate_findings(cfg, hosts) -> list[NormalizedFinding]:
    """One synthetic finding per IMPLEMENTED technique × scope host. ``entity={}`` --
    position-based probes read ``cfg.username``; no selector is set to the operator."""
    host_list = [h for h in (hosts or []) if h] or ([cfg.dc_ip] if cfg.dc_ip else [""])
    out: list[NormalizedFinding] = []
    for host in host_list:
        for tech in sorted(IMPLEMENTED):
            ex = get_executor(tech)
            out.append(NormalizedFinding(
                source={}, finding_id=f"discover-{tech}", host=host,
                technique=tech, technique_class=ex.technique_class, entity={}))
    return out


def _missing_required(ctx, executor, finding) -> list[str]:
    """Required executor params not auto-filled from globals+finding (a target selector
    the operator must supply) -- an incomplete candidate is non-executable."""
    try:
        specs = executor.param_specs(ctx, finding)
    except Exception:
        return ["<param_specs_error>"]
    return [s.name for s in specs if s.required and (s.recommended in (None, ""))]


@dataclass
class TechniqueVerdict:
    technique: str
    technique_class: str
    host: str
    viable: bool
    unknown: bool
    reason: str                       # the probe's crafted, non-secret reason (never raw exc text)
    evidence: dict
    implemented: bool
    verified_recipe: bool
    mutating: bool
    destructive: bool
    missing_params: list              # required selectors not auto-filled (non-executable if non-empty)
    eligible_for_autoexploit: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique, "class": self.technique_class, "host": self.host,
            "viable": self.viable, "unknown": self.unknown, "reason": self.reason,
            "evidence": self.evidence, "implemented": self.implemented,
            "verified_recipe": self.verified_recipe, "mutating": self.mutating,
            "destructive": self.destructive, "missing_params": self.missing_params,
            "eligible_for_autoexploit": self.eligible_for_autoexploit,
        }


def _eligible(executor, viable: bool, unknown: bool, missing: list, allow_destructive: bool) -> bool:
    """The auto-exploit gate (plan review): only a determined-viable, complete, verified,
    non-mutating (unless allowed) technique is auto-fired."""
    if not is_implemented(executor.technique):
        return False
    if not executor.verified_recipe:                     # AutoConfirm parity: verified only
        return False
    if not viable or unknown:                            # review #2: determined viable only
        return False
    if missing:                                          # review #3: complete target only
        return False
    if (executor.mutating or getattr(executor, "destructive", False)) and not allow_destructive:
        return False                                     # review #1: no AD mutation without opt-in
    return True


def _probe_ctx(ctx, probe_timeout: int):
    """A context whose tool timeout is capped for the probe phase (fast viability reads),
    leaving the caller's full-timeout ctx for the exploit phase."""
    cap = max(1, min(int(getattr(ctx.config, "tool_timeout_s", 300)), int(probe_timeout)))
    if cap >= int(getattr(ctx.config, "tool_timeout_s", 300)):
        return ctx
    pctx = ExecutorContext(config=dataclasses.replace(ctx.config, tool_timeout_s=cap),
                           runner=ctx.runner, authorizer=ctx.authorizer,
                           output_dir=ctx.output_dir, proc_manager=ctx.proc_manager,
                           destructive_confirmer=ctx.destructive_confirmer)
    pctx._private_errors = ctx._private_errors            # aggregate probe errors upward
    return pctx


def build_verdicts(ctx, hosts, allow_destructive: bool = False,
                   probe_timeout: int = _PROBE_TIMEOUT_CAP) -> list[TechniqueVerdict]:
    """Probe every technique over the scope (READ-ONLY) and classify each. Runs the probes
    directly (NOT through orchestrator.plan, which drops incomplete findings -- review #3),
    so every technique appears in the report even when its target selector is missing.
    Probes run under a capped timeout so one slow read can't stall the scan."""
    allow = bool(getattr(ctx.config, "allow_destructive", False) or allow_destructive)
    cands = candidate_findings(ctx.config, hosts)
    results = probes_mod.run_probes(_probe_ctx(ctx, probe_timeout), cands)
    verdicts: list[TechniqueVerdict] = []
    for finding, pr in zip(cands, results):
        ex = get_executor(finding.technique)
        missing = _missing_required(ctx, ex, finding)
        viable = pr.viable if pr is not None else True
        unknown = pr.unknown if pr is not None else True     # no probe -> unknown (never auto-fire)
        reason = pr.reason if pr is not None else "no probe registered"
        evidence = pr.evidence if pr is not None else {}
        verdicts.append(TechniqueVerdict(
            technique=finding.technique, technique_class=finding.technique_class, host=finding.host,
            viable=viable, unknown=unknown, reason=reason, evidence=evidence,
            implemented=is_implemented(finding.technique), verified_recipe=ex.verified_recipe,
            mutating=ex.mutating, destructive=getattr(ex, "destructive", False),
            missing_params=missing,
            eligible_for_autoexploit=_eligible(ex, viable, unknown, missing, allow)))
    return verdicts


def summarize(verdicts: list[TechniqueVerdict]) -> dict[str, Any]:
    return {
        "techniques": len({v.technique for v in verdicts}),
        "rows": len(verdicts),
        "viable": sum(1 for v in verdicts if v.viable and not v.unknown),
        "not_viable": sum(1 for v in verdicts if not v.viable and not v.unknown),
        "unknown": sum(1 for v in verdicts if v.unknown),
        "eligible_for_autoexploit": sum(1 for v in verdicts if v.eligible_for_autoexploit),
        "need_target": sorted({v.technique for v in verdicts if v.missing_params and v.viable}),
        "need_allow_destructive": sorted({v.technique for v in verdicts
                                          if (v.mutating or v.destructive) and v.viable and not v.unknown
                                          and not v.missing_params}),
    }
