"""The operator-driven validation orchestrator: enum -> plan -> confirm -> execute -> score.

Implements the UX of claude-mem #66142:

1. The operator sets all inputs up front (:class:`ValidationConfig`).
2. :meth:`enumerate` drives aranum (``aranum run`` -> ``aranum report``) and
   parses ``findings.json`` into normalized, technique-mapped findings.
3. :meth:`plan` presents the discovered, validatable issues, each with a
   recommended-default parameter set the operator can override.
4. :meth:`confirm` asks the operator, per issue, whether to validate it (opt-in)
   and collects any parameter overrides.
5. :meth:`execute` runs the chosen executors; each emits an
   ``adlab.plan003.proof.v1`` receipt (with a verified rollback if mutating).
6. :meth:`score` hands the receipts to ad-lab-harness ``score_proof`` and reports
   proved / not-proved / inconclusive.

Enumeration and scoring are injected (:class:`AranumRunner`, :class:`ProofScorer`)
so the pipeline is testable without a lab or the harness on PATH, and so a
missing detection input or scorer degrades gracefully rather than crashing.
"""
from __future__ import annotations

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .config import ValidationConfig
from .findings import NormalizedFinding, load_findings, validatable
from . import proof
from .probes import ProbeResult, run_probes
from .executors import (ExecutorContext, CommandRunner, SubprocessRunner,
                        AuthorizationProvider, AuthorizedLabProvider, ValidationPlan,
                        ProcessManager, SubprocessProcessManager,
                        DestructiveConfirmationProvider, InteractiveDestructiveConfirmer,
                        NonInteractiveDestructiveConfirmer,
                        get_executor, is_implemented)


# ------------------------------------------------------------------ enumeration
class AranumRunner(ABC):
    """Produces an aranum ``findings.json`` path for the configured target."""

    @abstractmethod
    def findings_path(self, config: ValidationConfig) -> Path:
        ...


class CliAranumRunner(AranumRunner):
    """Drive the real aranum CLI: ``aranum run -i <nmap> -o <out>`` then ``report``.

    If ``config.findings_json`` is set it is used directly (enumeration skipped).
    Requires ``config.nmap_input`` otherwise (aranum run consumes an nmap file).
    """

    def __init__(self, timeout: int = 1800):
        self.timeout = timeout

    def findings_path(self, config: ValidationConfig) -> Path:
        if config.findings_json is not None:
            return config.findings_json
        if config.nmap_input is None:
            raise ValueError("enumeration needs config.nmap_input (aranum run -i) "
                             "or a pre-existing config.findings_json")
        out = config.output_dir / "enum"
        out.mkdir(parents=True, exist_ok=True)
        run_argv = [config.aranum_bin, "run", "-i", str(config.nmap_input),
                    "-o", str(out), "--domain", config.domain, "--dc-ip", config.dc_ip]
        if config.username:
            run_argv += ["-u", config.username]
        if config.password is not None:
            run_argv += ["-p", config.password]
        subprocess.run(run_argv, check=False, timeout=self.timeout)
        subprocess.run([config.aranum_bin, "report", "-o", str(out)],
                       check=False, timeout=self.timeout)
        return out / "findings.json"


# ------------------------------------------------------------------ scoring
class ProofScorer(ABC):
    """Scores a set of proof.v1 receipts -> proved/not-proved/inconclusive."""

    @abstractmethod
    def score(self, config: ValidationConfig, receipt_paths: list[Path],
              result_path: Path) -> dict:
        ...


class CliProofScorer(ProofScorer):
    """Invoke ad-lab-harness ``score_proof`` via ``config.score_proof_cmd``.

    Returns the parsed score-result JSON. When no scorer/truth is configured the
    orchestrator skips this and reports the raw receipts instead.
    """

    def score(self, config, receipt_paths, result_path) -> dict:
        if not config.score_proof_cmd or config.proof_truth is None:
            raise ValueError("score_proof_cmd and proof_truth must be configured")
        argv = list(config.score_proof_cmd) + ["--proof-truth", str(config.proof_truth)]
        for rp in receipt_paths:
            argv += ["--proof", str(rp)]
        argv += ["--result", str(result_path)]
        subprocess.run(argv, check=False, timeout=config.tool_timeout_s)
        return json.loads(Path(result_path).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ confirmation
@dataclass
class Choice:
    """An operator's per-issue decision."""
    validate: bool
    overrides: dict[str, Any] = field(default_factory=dict)


class ConfirmationProvider(ABC):
    """Asks the operator whether to validate each planned issue and for overrides."""

    @abstractmethod
    def confirm(self, plan: ValidationPlan) -> Choice:
        ...


class AutoConfirm(ConfirmationProvider):
    """Accept every validatable plan with its recommended defaults (no prompt).

    For non-interactive runs (``config.auto_confirm``) and tests. By default it
    skips *unverified-recipe* plans and non-implemented (stub) techniques; pass
    ``include_unverified``/``include_stubs`` to force them.
    """

    def __init__(self, include_unverified: bool = False, include_stubs: bool = False):
        self.include_unverified = include_unverified
        self.include_stubs = include_stubs

    def confirm(self, plan: ValidationPlan) -> Choice:
        if not self.include_stubs and not is_implemented(plan.technique):
            return Choice(validate=False)
        if not self.include_unverified and not plan.verified_recipe:
            return Choice(validate=False)
        return Choice(validate=True)


class DeclineAll(ConfirmationProvider):
    def confirm(self, plan: ValidationPlan) -> Choice:
        return Choice(validate=False)


# ------------------------------------------------------------------ result record
@dataclass
class PlannedValidation:
    finding: NormalizedFinding
    executor: Any
    plan: ValidationPlan
    implemented: bool
    # ADR-002 D1 precondition-probe verdict (None if no probe registered for the
    # technique). A probe returning viable=False SKIPS the finding; viable=True and
    # unknown=True both proceed (unknown carries its reason into the plan).
    probe: Optional[ProbeResult] = None

    @property
    def skipped_by_probe(self) -> bool:
        """Skip ONLY on a CONFIDENT not-viable determination. An ``unknown`` result
        (the probe could not determine) NEVER skips -- even if a probe also set
        ``viable=False`` -- so the fail-safe does not depend on a probe honouring
        the "unknown implies viable" invariant (defence in depth)."""
        return (self.probe is not None
                and not self.probe.viable
                and not self.probe.unknown)


@dataclass
class ValidationOutcome:
    technique: str
    finding_id: str
    receipt_path: Optional[Path]
    receipt: dict
    overrides: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------ orchestrator
class ValidationOrchestrator:
    def __init__(self, config: ValidationConfig, *,
                 runner: Optional[CommandRunner] = None,
                 authorizer: Optional[AuthorizationProvider] = None,
                 confirmer: Optional[ConfirmationProvider] = None,
                 aranum: Optional[AranumRunner] = None,
                 scorer: Optional[ProofScorer] = None,
                 proc_manager: Optional[ProcessManager] = None,
                 destructive_confirmer: Optional[DestructiveConfirmationProvider] = None):
        self.config = config
        self.runner = runner or SubprocessRunner(default_timeout=config.tool_timeout_s)
        self.authorizer = authorizer or AuthorizedLabProvider(config.authorized)
        self.confirmer = confirmer or (AutoConfirm() if config.auto_confirm else DeclineAll())
        self.aranum = aranum or CliAranumRunner()
        self.scorer = scorer or CliProofScorer()
        # ADR-001 chassis extension: the shared background listener manager for
        # the listener-based executors (COERCION, NTLM-RELAY, UNCONSTRAINED-DELEG).
        self.proc_manager = proc_manager or SubprocessProcessManager()
        # T3: an INTERACTIVE run (not config.auto_confirm, the human-in-the-loop
        # default) always gets the press-yes prompt; a NON-INTERACTIVE run
        # (config.auto_confirm=True, e.g. CI/automation) gets the fail-closed,
        # explicit-flag-only path -- never a prompt that would hang forever.
        self.destructive_confirmer = destructive_confirmer or (
            NonInteractiveDestructiveConfirmer(allowed=config.allow_destructive)
            if config.auto_confirm else InteractiveDestructiveConfirmer())
        self.receipts_dir = config.output_dir / "receipts"
        self.context = ExecutorContext(config=config, runner=self.runner,
                                       authorizer=self.authorizer,
                                       output_dir=config.output_dir,
                                       proc_manager=self.proc_manager,
                                       destructive_confirmer=self.destructive_confirmer)

    # -- step 2 -----------------------------------------------------------
    def enumerate(self) -> list[NormalizedFinding]:
        """Run detection (or load a provided findings.json) -> mapped findings."""
        path = self.aranum.findings_path(self.config)
        return load_findings(path)

    # -- step 3 (+ ADR-002 D1 precondition probing) -----------------------
    def plan(self, findings: list[NormalizedFinding]) -> list[PlannedValidation]:
        """Build a plan for every validatable finding that has a registered executor,
        and attach its non-destructive precondition-probe verdict (ADR-002 D1).

        Probes run concurrently and independently before planning is returned;
        ``confirm`` then skips any finding whose probe returned ``viable=False``.
        ``unknown=True`` and ``viable=True`` both proceed, and a technique with no
        registered probe proceeds exactly as before (no regression)."""
        candidates: list[tuple[NormalizedFinding, Any, ValidationPlan]] = []
        for finding in validatable(findings):
            executor = get_executor(finding.technique)
            if executor is None:
                continue
            try:
                vp = executor.plan(self.context, finding)
            except Exception:
                continue  # a plan failure must never abort the whole run
            candidates.append((finding, executor, vp))
        # Fan out the non-destructive probes concurrently (ADR-002 D1).
        probe_results = run_probes(self.context, [c[0] for c in candidates])
        return [PlannedValidation(
                    finding=finding, executor=executor, plan=vp,
                    implemented=is_implemented(finding.technique), probe=probe)
                for (finding, executor, vp), probe in zip(candidates, probe_results)]

    # -- step 4 -----------------------------------------------------------
    def confirm(self, plans: list[PlannedValidation]) -> list[tuple[PlannedValidation, Choice]]:
        """Ask the operator per issue; keep the ones opted-in to validate.

        A finding whose precondition probe returned ``viable=False`` is SKIPPED
        here (never offered, never executed) -- it is reported under ``skipped``.
        ``unknown``/``viable`` findings (and techniques with no probe) proceed."""
        chosen: list[tuple[PlannedValidation, Choice]] = []
        for pv in plans:
            if pv.skipped_by_probe:
                continue  # positive not-viable determination -> do not execute
            choice = self.confirmer.confirm(pv.plan)
            if choice.validate:
                chosen.append((pv, choice))
        return chosen

    # -- step 5 -----------------------------------------------------------
    def execute(self, chosen: list[tuple[PlannedValidation, Choice]]) -> list[ValidationOutcome]:
        """Run each chosen executor; write its proof.v1 receipt."""
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        outcomes: list[ValidationOutcome] = []
        for index, (pv, choice) in enumerate(chosen):
            receipt = pv.executor.run(self.context, pv.finding, choice.overrides)
            name = f"{index:02d}_{pv.finding.technique}_{pv.finding.finding_id or 'na'}.json"
            path = proof.write_receipt(receipt, self.receipts_dir / name)
            outcomes.append(ValidationOutcome(
                technique=pv.finding.technique, finding_id=pv.finding.finding_id,
                receipt_path=path, receipt=receipt, overrides=choice.overrides))
        return outcomes

    # -- step 6 -----------------------------------------------------------
    def score(self, outcomes: list[ValidationOutcome]) -> dict:
        """Score receipts via ad-lab-harness, or report receipts if no scorer set."""
        receipt_paths = [o.receipt_path for o in outcomes if o.receipt_path]
        if not (self.config.score_proof_cmd and self.config.proof_truth) or not receipt_paths:
            return {"scored": False, "reason": "no scorer/truth configured or no receipts",
                    "receipts": [str(p) for p in receipt_paths]}
        result_path = self.config.output_dir / "proof-score.json"
        try:
            result = self.scorer.score(self.config, receipt_paths, result_path)
        except Exception as exc:
            self.context._private_errors.append(str(exc))
            return {"scored": False, "reason": "scoring_error",
                    "receipts": [str(p) for p in receipt_paths]}
        return {"scored": True, "result_path": str(result_path), "result": result}

    # -- full pipeline ----------------------------------------------------
    def run(self) -> dict:
        """Run the whole pipeline and return an operator-facing report.

        ``planned`` lists the issues that proceed (probe viable/unknown or no
        probe), each annotated with its ``probe`` verdict so the operator sees any
        uncertainty an ``unknown`` probe carries. ``skipped`` lists the issues a
        precondition probe positively determined non-viable, each with the reason
        and evidence (ADR-002 D1, "explain every skip")."""
        findings = self.enumerate()
        plans = self.plan(findings)
        chosen = self.confirm(plans)
        outcomes = self.execute(chosen)
        score = self.score(outcomes)
        return {
            "config": self.config.redacted(),
            "findings_total": len(findings),
            "validatable": [f.summary() for f in validatable(findings)],
            "planned": [self._planned_entry(pv) for pv in plans
                        if not pv.skipped_by_probe],
            "skipped": [self._skip_entry(pv) for pv in plans if pv.skipped_by_probe],
            "executed": [{"technique": o.technique, "finding_id": o.finding_id,
                          "receipt": str(o.receipt_path),
                          "complete": o.receipt.get("complete"),
                          "terminal": bool(o.receipt.get("terminal_fact"))}
                         for o in outcomes],
            "score": score,
        }

    # -- report helpers ---------------------------------------------------
    @staticmethod
    def _planned_entry(pv: PlannedValidation) -> dict:
        """The plan preview, annotated with the probe verdict (if any)."""
        entry = pv.plan.to_dict()
        if pv.probe is not None:
            entry["probe"] = pv.probe.to_dict()
        return entry

    @staticmethod
    def _skip_entry(pv: PlannedValidation) -> dict:
        """One entry for the run report's ``skipped`` list."""
        pr = pv.probe
        return {"technique": pv.finding.technique, "finding_id": pv.finding.finding_id,
                "reason": pr.reason if pr else "",
                "evidence": pr.evidence if pr else {}}
