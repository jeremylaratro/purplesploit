"""Open-RW-share write-readback validation executor -- FULL (T1b).

Encodes the PROVEN OPENSHARES-WRITE recipe (claude-mem #66146), parameterized
and *mutating* (a file is written to the share, so a VERIFIED rollback is
required):

    smbclient //<host>/<share> -U '<dom>\\<user>%<pass>' -c 'put  <local> <canary>'
    smbclient //<host>/<share> -U '<dom>\\<user>%<pass>' -c 'get  <canary> <readback>'
        -> compare sha256(written) == sha256(readback)        (terminal proof)
    ROLLBACK:
    smbclient //<host>/<share> -U ... -c 'rm <canary>'
    smbclient //<host>/<share> -U ... -c 'get <canary> <absent>'   (must NOT find it)

The executor does REAL local file I/O: it writes a uniquely-named canary with
known random content, computes its sha256, uploads it, downloads it to a second
path, reads that back and compares hashes. The terminal
``file_write_readback.ok`` is ``write succeeded AND readback hash == written
hash`` -- not a return code. The write is a mutating, gated op; a denied gate
yields an incomplete receipt the harness reads as ``inconclusive``.

The canary content is not a credential, but it is kept out of the receipt all the
same; the terminal fact's token is over public identifiers only (technique, host,
share, canary name). Rollback deletes the canary and verifies read-back returns
not-found; an unverified rollback is flagged (``rollback_unverified``) and the
scorer then returns ``inconclusive``, never ``proved``.

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): OPENSHARES-WRITE
keys on ``{host_id, share}``. ``target_identity`` merges the resolved host
identity (via ``config.host_aliases``) with the share so the receipt target
carries both.

UNVERIFIED ASSUMPTION (pin against the real tool during the lab run, mirroring
laps.py): the smbclient auth form ``-U 'DOM\\user%pass'`` and its ``put`` / ``get``
/ ``rm`` output markers (``putting file`` / ``getting file`` /
``NT_STATUS_OBJECT_NAME_NOT_FOUND``). If the real wording differs, a step gets no
positive predicate and the chain honestly reports not-proved/inconclusive -- it
never fabricates a write-readback.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)


# smbclient output markers (UNVERIFIED -- see module docstring).
_RE_PUT_OK = re.compile(r"putting file", re.I)
_RE_GET_OK = re.compile(r"getting file", re.I)
# Any smbclient/SMB error marker that means the op did not succeed.
_RE_SMB_ERROR = re.compile(r"NT_STATUS_[A-Z_]+", re.I)
_RE_NOT_FOUND = re.compile(
    r"(NT_STATUS_OBJECT_NAME_NOT_FOUND|NT_STATUS_NO_SUCH_FILE|"
    r"NT_STATUS_OBJECT_PATH_NOT_FOUND)", re.I)


def _share_from_finding(finding) -> str:
    entity = finding.entity or {}
    return entity.get("share") or ""


class OpenSharesExecutor(ValidationExecutor):
    technique = "OPENSHARES-WRITE"
    technique_class = "openshares"
    terminal_kind = "file_write_readback"
    mutating = True
    verified_recipe = True
    recipe_ref = ("#66146 OPENSHARES-WRITE = smbclient //<host>/<share> put canary ; "
                  "get + sha256 compare ; ROLLBACK rm + readback-absent verify "
                  "(PROVED srv02/srv03 all+public)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        return [
            ParamSpec(
                name="share", kind="share",
                description="The writable (RW) share the canary is written to and "
                            "read back from.",
                recommended=_share_from_finding(finding),
                rationale="The share aranum flagged as non-default RW; override to "
                          "target a specific share (#66142 override model).",
                required=True,
            ),
            ParamSpec(
                name="canary_name", kind="free",
                description="Unique file name for the write-readback canary.",
                recommended=f"vrcheck_{secrets.token_hex(4)}.txt",
                rationale="A random, uniquely-named canary avoids collisions and is "
                          "trivially identifiable for cleanup.",
                validator=lambda value: (None if isinstance(value, str) and value.strip()
                                         and "/" not in value and "\\" not in value
                                         else "must be a bare file name (no path separators)"),
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # OPENSHARES-WRITE facet keys on {host_id, share}.
        host = finding.host or ""
        share = (params["share"].value if "share" in params else None) \
            or _share_from_finding(finding)
        identity = dict(ctx.config.resolve_target_identity(host)) if host else dict(finding.entity)
        identity["share"] = share
        return identity

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        host = finding.host or "<host>"
        unc = f"//{host}/{v['share']}"
        return [
            f"smbclient {unc} -U '<dom>\\<user>%***' -c 'put <local> {v['canary_name']}'",
            f"smbclient {unc} -U ... -c 'get {v['canary_name']} <readback>'  (sha256 compare)",
            f"ROLLBACK: smbclient {unc} -U ... -c 'rm {v['canary_name']}'",
            f"ROLLBACK verify: smbclient {unc} -U ... -c 'get {v['canary_name']} <absent>'  (must be NOT_FOUND)",
        ]

    # ---------------------------------------------------------------- auth value
    def _smb_user(self, cfg) -> str:
        """The ``DOMAIN\\user%password`` value for smbclient ``-U`` (password
        masked by :func:`redact_argv` in any stored argv)."""
        user = cfg.username or ""
        secret = cfg.password if cfg.password is not None else ""
        return f"{cfg.domain}\\{user}%{secret}"

    def _smb_argv(self, unc: str, smb_user: str, command: str) -> list[str]:
        return ["smbclient", unc, "-U", smb_user, "-c", command]

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        share = v["share"]
        canary_name = v["canary_name"]
        host = finding.host or ""
        unc = f"//{host}/{share}"
        smb_user = self._smb_user(cfg)
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

        def record_local(name, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=[],
                                    returncode=None, note=note))

        # 0) build the local canary (known random content; not a secret, but kept
        #    out of the receipt). Compute the written hash locally.
        canary_content = secrets.token_hex(16)
        local_canary = out_dir / canary_name
        local_canary.write_text(canary_content, encoding="utf-8")
        written_hash = hashlib.sha256(canary_content.encode("utf-8")).hexdigest()
        readback_path = out_dir / f"{canary_name}.readback"
        absent_path = out_dir / f"{canary_name}.absent"

        # 1) write the canary (mutating, gated) ------------------------------
        verdict = ctx.authorizer.authorize("openshares_write",
                                           {"host": host, "share": share,
                                            "canary": canary_name})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "openshares_write"
            errors.append("gate_denied:openshares_write")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "openshares_write"

        put_argv = self._smb_argv(unc, smb_user, f"put {local_canary} {canary_name}")
        res = ctx.runner.run(put_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        put_out = (res.stdout or "") + (res.stderr or "")
        put_ok = bool(_RE_PUT_OK.search(put_out)) and not _RE_SMB_ERROR.search(put_out)
        record("smb_put", put_argv, res, put_ok, note="written" if put_ok else "write failed")
        if not put_ok:
            errors.append("smb_put_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True

        # 2) read the canary back --------------------------------------------
        get_argv = self._smb_argv(unc, smb_user, f"get {canary_name} {readback_path}")
        res = ctx.runner.run(get_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        get_out = (res.stdout or "") + (res.stderr or "")
        get_ok = (bool(_RE_GET_OK.search(get_out)) and not _RE_SMB_ERROR.search(get_out)
                  and readback_path.exists())
        record("smb_readback_get", get_argv, res, get_ok,
               note="read back" if get_ok else "readback failed")

        # 3) hash compare (local, deciding predicate) ------------------------
        readback_hash = (hashlib.sha256(readback_path.read_bytes()).hexdigest()
                         if readback_path.exists() else None)
        hash_ok = bool(get_ok and readback_hash is not None and readback_hash == written_hash)
        record_local("hash_compare", hash_ok,
                      note="sha256 match" if hash_ok else "sha256 mismatch / no readback")
        if not hash_ok:
            errors.append("readback_hash_mismatch")

        write_proved = put_ok and hash_ok
        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=write_proved,
            predicate=(f"wrote canary {canary_name} to //{host}/{share}, read it "
                       f"back, and sha256(written) == sha256(readback)"),
            proof_token=proof.proof_token("OPENSHARES-WRITE", host, share,
                                          canary_name, "write_readback"),
            extra={"share": share, "canary_name": canary_name},
        )

        # 4) rollback (always, since we wrote) + verify read-back absent ------
        self._rollback(ctx, unc, smb_user, canary_name, absent_path, mutation,
                       steps, errors, record)

        complete = write_proved and mutation["rollback"]["performed"]
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, unc, smb_user, canary_name, absent_path, mutation,
                  steps, errors, record) -> None:
        """Delete the canary and verify a read-back returns not-found (gated)."""
        if not mutation["applied"]:
            return
        if ctx.authorizer.authorize("rollback", {"canary": canary_name}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "smbclient rm + readback-absent verify"

        rm_argv = self._smb_argv(unc, smb_user, f"rm {canary_name}")
        res = ctx.runner.run(rm_argv, timeout=ctx.config.tool_timeout_s)
        rm_out = (res.stdout or "") + (res.stderr or "")
        # rm succeeds when it reports no error (smbclient rm is silent on success).
        delete_ok = not _RE_SMB_ERROR.search(rm_out)
        record("rollback_rm", rm_argv, res, delete_ok,
               note="deleted" if delete_ok else "delete failed")

        verify_argv = self._smb_argv(unc, smb_user, f"get {canary_name} {absent_path}")
        res = ctx.runner.run(verify_argv, timeout=ctx.config.tool_timeout_s)
        verify_out = (res.stdout or "") + (res.stderr or "")
        # Absent = the canary can no longer be fetched (explicit not-found, or no
        # successful get and no local file written).
        absent_ok = bool(_RE_NOT_FOUND.search(verify_out)) or (
            not _RE_GET_OK.search(verify_out) and not Path(absent_path).exists())
        record("rollback_verify_absent", verify_argv, res, absent_ok,
               note="canary gone" if absent_ok else "canary still present")

        mutation["rollback"]["verified"] = bool(delete_ok and absent_ok)
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
