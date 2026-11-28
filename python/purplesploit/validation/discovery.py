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
import re
from dataclasses import dataclass, field
from typing import Any, Optional

# certipy-ad find CA classification. A CA is CONFIRMED present only on CA *details*
# (a bare "Certificate Authorities" header prints even with 0 CAs); CONFIRMED absent only
# on an explicit 0/none marker from a clean run; anything else (error/inconclusive) -> None.
_CA_PRESENT = re.compile(r"(CA Name\s*:|DNS Name\s*:|Web Enrollment)", re.I)
# Absence must name AUTHORITIES specifically -- certipy logs template counts separately,
# so a generic "found 0" (e.g. "0 certificate templates") must NOT read as "no CA".
_CA_ABSENT = re.compile(r"(0 (enabled )?certificate authorit|no certificate authorit|no (enabled )?CAs?\b)", re.I)
# The nxc ldap --query genuine-result marker: an error that merely echoes the query's
# sAMAccountName must NOT be mistaken for a real account read.
_LDAP_RESULT = re.compile(r"Response for object", re.I)
_CERTIPY_ERR = re.compile(
    r"(got error|traceback|could not|connection (failed|refused|timed out)|\[-\]|exception|denied)", re.I)

from .findings import NormalizedFinding
from .executors import IMPLEMENTED, get_executor, is_implemented
from .executors.base import ExecutorContext
from . import probes as probes_mod
from .probes import (_ldap_query, _certipy_find, _extract_attr, _account_read_ok,
                     _text, _tool_errored)

# A viability probe is a cheap read; bound its per-op time so one slow/hanging read
# cannot stall a whole-fleet discovery scan (the default tool timeout is minutes).
_PROBE_TIMEOUT_CAP = 30


def discover_posture(ctx, finding):
    """Phase 4a variant: posture only, one already-fenced finding at a time.

    No shared recon, implicit target, credential read, executor dispatch, generic
    probe registry, or exception log. Caller supplies the admission/fence runner.
    Raw reasons and evidence are runtime-only; the planner exports fixed events.
    """
    if not finding.host:
        return probes_mod.ProbeResult(viable=False, unknown=True, reason="empty_scope")
    return probes_mod.non_secret_probe(ctx, finding)


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


@dataclass
class _Recon:
    """Cheap SHARED facts read ONCE, used to gate whole groups of techniques before
    their (often expensive) per-technique probes run. Each is True/False/None -- None
    means the fact could not be read, so it NEVER gates (fail-safe: run the probe)."""
    has_delegation: Optional[bool]    # the operator account holds msDS-AllowedToDelegateTo
    has_spn: Optional[bool]           # the operator account has a servicePrincipalName
    is_computer: bool                 # the operator account is a computer account (name ends '$')
    has_ca: Optional[bool]            # an ADCS Certificate Authority is reachable
    has_forge_key: bool               # a forging signing key is configured (--forge-key-file)

    def to_dict(self):
        return {"has_delegation": self.has_delegation, "has_spn": self.has_spn,
                "is_computer": self.is_computer, "has_ca": self.has_ca,
                "has_forge_key": self.has_forge_key}


def _nonempty(v: Optional[str]) -> bool:
    return bool(v and v.strip().lower() not in ("", "(not set)", "<not set>", "none", "-", "n/a"))


def recon(ctx) -> _Recon:
    """Read the shared prerequisites ONCE (the operator account's delegation/SPN, whether
    an ADCS CA exists, whether a forge key is supplied) so discovery can skip groups of
    techniques whose prerequisite is definitively absent -- cheaper than, and the gate
    for, the per-technique probes."""
    cfg = ctx.config
    user = cfg.username or ""
    is_computer = user.endswith("$")
    has_del = has_spn = None
    try:
        res = _ldap_query(ctx, f"(sAMAccountName={user})",
                          ["sAMAccountName", "msDS-AllowedToDelegateTo", "servicePrincipalName"])
        text = _text(res)
        rc = getattr(res, "returncode", None)
        # Infer absence ONLY from a GENUINE, clean account read -- not from an error that
        # happens to echo the sAMAccountName filter (which would pass _account_read_ok).
        genuine = (_account_read_ok(res, text) and rc in (0, None)
                   and not _tool_errored(res) and bool(_LDAP_RESULT.search(text)))
        if genuine:
            has_del = _nonempty(_extract_attr(text, "msDS-AllowedToDelegateTo"))
            has_spn = _nonempty(_extract_attr(text, "servicePrincipalName"))
    except Exception:
        pass
    has_ca = None
    try:
        res = _certipy_find(ctx)
        text = _text(res)
        rc = getattr(res, "returncode", None)
        clean = (text.strip() and not _tool_errored(res) and rc in (0, None)
                 and not _CERTIPY_ERR.search(text))
        if _CA_PRESENT.search(text):
            has_ca = True                                   # CA details -> CONFIRMED present
        elif clean and _CA_ABSENT.search(text):
            has_ca = False                                  # clean run + explicit 0/none -> CONFIRMED absent
        # else -> None: a failed / errored / inconclusive read NEVER gates ADCS (fail-safe)
    except Exception:
        pass
    return _Recon(has_delegation=has_del, has_spn=has_spn, is_computer=is_computer,
                  has_ca=has_ca, has_forge_key=bool(getattr(cfg, "forge_key", None)))


def _prereq_gate(technique: str, r: _Recon) -> tuple[Optional[bool], str]:
    """``(met, what)``: ``met is False`` -> the prerequisite is DEFINITIVELY absent, so
    skip the probe (mark not-viable). ``True``/``None`` -> run the probe (met or unknown)."""
    if technique in ("CONSTRAINED-DELEG-PT", "BRONZE-BIT"):
        return r.has_delegation, "msDS-AllowedToDelegateTo on the operator account"
    if technique == "S4U2SELF":
        return (True, "") if r.is_computer else (r.has_spn, "a servicePrincipalName / computer account")
    if technique in ("ADCS-ESC1", "ESC8", "ESC11", "CERTIFRIED", "SHADOW-CREDS"):
        return r.has_ca, "an ADCS Certificate Authority"
    if technique in ("GOLDEN-TICKET", "DIAMOND-TICKET", "SAPPHIRE-TICKET", "SILVER-TICKET"):
        return (r.has_forge_key if r.has_forge_key else False), "a forging signing key (--forge-key-file)"
    return None, ""                                           # no shared prerequisite -> run the probe


def _make_verdict(ctx, finding, viable, unknown, reason, evidence, allow) -> TechniqueVerdict:
    ex = get_executor(finding.technique)
    missing = _missing_required(ctx, ex, finding)
    return TechniqueVerdict(
        technique=finding.technique, technique_class=finding.technique_class, host=finding.host,
        viable=viable, unknown=unknown, reason=reason, evidence=evidence,
        implemented=is_implemented(finding.technique), verified_recipe=ex.verified_recipe,
        mutating=ex.mutating, destructive=getattr(ex, "destructive", False),
        missing_params=missing,
        eligible_for_autoexploit=_eligible(ex, viable, unknown, missing, allow))


def build_verdicts(ctx, hosts, allow_destructive: bool = False,
                   probe_timeout: int = _PROBE_TIMEOUT_CAP) -> list[TechniqueVerdict]:
    """SMART discovery: read the shared prerequisites ONCE, then for each technique either
    SKIP it (its prerequisite is definitively absent -> a fast, explained not-viable) or run
    its per-technique probe. Every technique still appears in the report (review #3); probes
    run under a capped timeout. A definitively-absent prerequisite is the only thing that
    skips a probe -- an unreadable prerequisite falls through to the probe (fail-safe)."""
    allow = bool(getattr(ctx.config, "allow_destructive", False) or allow_destructive)
    pctx = _probe_ctx(ctx, probe_timeout)
    r = recon(pctx)                                          # shared, once
    cands = candidate_findings(ctx.config, hosts)
    verdicts: list[Optional[TechniqueVerdict]] = [None] * len(cands)
    to_probe: list[int] = []
    for i, finding in enumerate(cands):
        met, what = _prereq_gate(finding.technique, r)
        if met is False:                                    # prerequisite DEFINITIVELY absent -> skip
            verdicts[i] = _make_verdict(
                ctx, finding, viable=False, unknown=False,
                reason=f"prerequisite absent ({what}) -- skipped before probing",
                evidence={"prerequisite_absent": what}, allow=allow)
        else:
            to_probe.append(i)
    results = probes_mod.run_probes(pctx, [cands[i] for i in to_probe])
    for j, i in enumerate(to_probe):
        pr = results[j]
        verdicts[i] = _make_verdict(
            ctx, cands[i],
            viable=(pr.viable if pr is not None else True),
            unknown=(pr.unknown if pr is not None else True),     # no probe -> unknown (never auto-fire)
            reason=(pr.reason if pr is not None else "no probe registered"),
            evidence=(pr.evidence if pr is not None else {}), allow=allow)
    return [v for v in verdicts if v is not None]


def summarize(verdicts: list[TechniqueVerdict]) -> dict[str, Any]:
    return {
        "techniques": len({v.technique for v in verdicts}),
        "rows": len(verdicts),
        "viable": sum(1 for v in verdicts if v.viable and not v.unknown),
        "not_viable": sum(1 for v in verdicts if not v.viable and not v.unknown),
        "unknown": sum(1 for v in verdicts if v.unknown),
        "skipped_prereq": sorted({v.technique for v in verdicts
                                  if "prerequisite_absent" in (v.evidence or {})}),
        "eligible_for_autoexploit": sum(1 for v in verdicts if v.eligible_for_autoexploit),
        "need_target": sorted({v.technique for v in verdicts if v.missing_params and v.viable}),
        "need_allow_destructive": sorted({v.technique for v in verdicts
                                          if (v.mutating or v.destructive) and v.viable and not v.unknown
                                          and not v.missing_params}),
    }
