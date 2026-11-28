"""SIGNING-RELAY: SMB/LDAP signing-posture + relay/reflection exposure (read-only).

A signing-REQUIRED target collapses the NTLM relay/reflection class; this edge reads the
posture and classifies where signing is NOT enforced (relayable) -- the control the 2025
CVEs hinge on. exit 0 is never proof: the posture parsed from the tool output decides.
"""
from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (ExecutorContext, CommandRunner, RunResult,
                                                     AuthorizedLabProvider)
from purplesploit.validation.executors.process_manager import ProcessManager


class _UnusedPM(ProcessManager):
    def start(self, argv, *, env=None, cwd=None):
        raise AssertionError("external actions must not start a listener")

    def read(self, handle):
        raise AssertionError("external actions must not read a listener")

    def poll(self, handle):
        raise AssertionError("external actions must not poll a listener")

    def stop(self, handle):
        raise AssertionError("external actions must not stop a listener")


class _Runner(CommandRunner):
    """Scripted nxc: smb_out keyed per host, ldap_out keyed per host."""
    def __init__(self, smb=None, ldap=None, trigger=None):
        self.smb, self.ldap = smb or {}, ldap or {}
        self.trigger = trigger if trigger is not None else RunResult(1, stdout="ERROR_BAD_NETPATH")
        self.calls = []
    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        if argv[:2] == ["nxc", "smb"]:
            return RunResult(returncode=0, stdout=self.smb.get(argv[2], ""))
        if argv[:2] == ["nxc", "ldap"]:
            return RunResult(returncode=0, stdout=self.ldap.get(argv[2], ""))
        if argv[:2] == ["coercer", "coerce"]:
            return self.trigger
        return RunResult(returncode=0, stdout="")


def _cfg(**kw):
    base = dict(domain="north.sevenkingdoms.local", dc_ip="192.168.56.11",
                username="jon.snow", password="pw")
    base.update(kw)
    return ValidationConfig(**base)


def _ctx(cfg, runner, tmp_path):
    return ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                           output_dir=tmp_path, proc_manager=_UnusedPM())


def _finding(host="braavos"):
    return map_finding({"finding_id": "SR", "host": host, "category": "relay",
                        "severity": "high", "line": f"signing on {host}"})


SMB_OFF = "SMB braavos 445 BRAAVOS [*] Windows Server 2016 (name:BRAAVOS) (signing:False) (SMBv1:True)"
SMB_ON = "SMB castelblack 445 CASTELBLACK [*] Windows Server 2019 (signing:True) (SMBv1:None)"
LDAP_NONE = "LDAP dc 389 WINTERFELL [*] Windows Server 2019 (signing:None) (channel binding:Never)"
LDAP_ENFORCED = "LDAP dc 389 DC [*] Windows (signing:Required) (channel binding:Always)"


def test_smb_signing_off_is_relay_exposed(tmp_path):
    r = _Runner(smb={"braavos": SMB_OFF}, ldap={"braavos": LDAP_ENFORCED})
    res = get_executor("SIGNING-RELAY").run(_ctx(_cfg(), r, tmp_path), _finding("braavos"))
    tf = res["terminal_fact"]
    assert tf["ok"] is True and res["complete"] is True
    assert "smb_relay" in tf["exposed_classes"] and "braavos" in tf["exposed_hosts"]
    assert tf["per_host"][0]["smb_signing_required"] is False


def test_signing_enforced_not_exposed(tmp_path):
    r = _Runner(smb={"castelblack": SMB_ON}, ldap={"castelblack": LDAP_ENFORCED})
    res = get_executor("SIGNING-RELAY").run(_ctx(_cfg(), r, tmp_path), _finding("castelblack"))
    tf = res["terminal_fact"]
    assert tf["ok"] is False and tf["exposed_classes"] == []
    assert "enforce signing" in tf["predicate"]


def test_ldap_signing_none_is_relay_exposed(tmp_path):
    r = _Runner(smb={"winterfell": SMB_ON}, ldap={"winterfell": LDAP_NONE})
    res = get_executor("SIGNING-RELAY").run(_ctx(_cfg(), r, tmp_path), _finding("winterfell"))
    tf = res["terminal_fact"]
    assert tf["ok"] is True and "ldap_relay" in tf["exposed_classes"]
    assert tf["per_host"][0]["ldap_signing_required"] is False


def test_multi_host_mix(tmp_path):
    r = _Runner(smb={"braavos": SMB_OFF, "castelblack": SMB_ON},
                ldap={"braavos": LDAP_ENFORCED, "castelblack": LDAP_ENFORCED})
    res = get_executor("SIGNING-RELAY").run(
        _ctx(_cfg(), r, tmp_path), _finding("braavos"), overrides={"hosts": "braavos,castelblack"})
    tf = res["terminal_fact"]
    assert tf["ok"] is True and tf["exposed_hosts"] == ["braavos"]   # only braavos exposed


def test_ldap_channel_binding_unknown_is_not_exposed(tmp_path):
    # review HIGH: nxc emits "Unknown" on a failed LDAP read -> must stay INCONCLUSIVE,
    # never a false ldap_relay. signing Enforced + CB Unknown -> NOT exposed.
    r = _Runner(smb={"dc": SMB_ON},
                ldap={"dc": "LDAP dc 389 DC [*] (signing:Enforced) (channel binding:Unknown)"})
    res = get_executor("SIGNING-RELAY").run(_ctx(_cfg(), r, tmp_path), _finding("dc"))
    tf = res["terminal_fact"]
    assert tf["ok"] is False and "ldap_relay" not in tf["exposed_classes"]
    assert tf["per_host"][0]["ldap_signing_required"] is True            # explicit value kept


def test_ldap_when_supported_cb_is_exposed(tmp_path):
    # signing Required but channel binding "When Supported" (bypassable) -> ldap_relay.
    r = _Runner(smb={"dc": SMB_ON},
                ldap={"dc": "LDAP dc 389 DC [*] (signing:Required) (channel binding:When Supported)"})
    res = get_executor("SIGNING-RELAY").run(_ctx(_cfg(), r, tmp_path), _finding("dc"))
    assert res["terminal_fact"]["ok"] is True
    assert "ldap_relay" in res["terminal_fact"]["exposed_classes"]


def test_creds_not_in_receipt(tmp_path):
    r = _Runner(smb={"braavos": SMB_OFF}, ldap={"braavos": LDAP_NONE})
    res = get_executor("SIGNING-RELAY").run(_ctx(_cfg(password="S3cr3t!"), r, tmp_path), _finding("braavos"))
    assert "S3cr3t!" not in json.dumps(res)                          # operator password masked/absent


def test_unreachable_host(tmp_path):
    r = _Runner(smb={}, ldap={})                                    # nxc returns nothing
    res = get_executor("SIGNING-RELAY").run(_ctx(_cfg(), r, tmp_path), _finding("ghost"))
    assert res["terminal_fact"]["ok"] is False
    assert any(e.startswith("unreachable:") for e in res["errors"])


def test_run_dispatch_binds(tmp_path):
    from purplesploit.validation.inputs import finding_from_inputs, TARGET_PARAM
    assert TARGET_PARAM["SIGNING-RELAY"] == "hosts"
    f = finding_from_inputs(_ctx(_cfg(), _Runner(), tmp_path), get_executor("SIGNING-RELAY"),
                            target="braavos,castelblack")
    assert f.technique == "SIGNING-RELAY" and f.host == "braavos,castelblack"


ACTIONS = ("dump", "escalate", "shell", "crawl")


def test_explicit_detect_preserves_receipt_and_preview(tmp_path):
    executor = get_executor("SIGNING-RELAY")
    runner = _Runner(smb={"braavos": SMB_OFF}, ldap={"braavos": LDAP_NONE})
    ctx = _ctx(_cfg(), runner, tmp_path)
    expected = executor.run(ctx, _finding())
    receipt = executor.run(ctx, _finding(), overrides={
        "action": "detect", "external_listener": "10.0.0.250",
        "coerce_victim": "dc02", "shell_cmd": "whoami"})
    assert receipt == expected
    assert executor.plan(ctx, _finding()).steps_preview == executor.plan(
        ctx, _finding(), overrides={"action": "detect"}).steps_preview
    assert all(c[0] == "nxc" for c in runner.calls)


@pytest.mark.parametrize("action,shell_cmd", [
    ("dump", ""), ("escalate", ""), ("shell", ""), ("shell", "whoami /all"), ("crawl", ""),
])
def test_external_action_preview_and_dispatch(tmp_path, action, shell_cmd):
    executor = get_executor("SIGNING-RELAY")
    runner = _Runner(smb={"braavos": SMB_OFF}, ldap={"braavos": LDAP_NONE})
    ctx = _ctx(_cfg(password="PreviewSecret!"), runner, tmp_path)
    overrides = {"action": action, "external_listener": "10.0.0.250:1445", "shell_cmd": shell_cmd}
    plan = executor.plan(ctx, _finding(), overrides)
    assert runner.calls == []
    assert "PreviewSecret!" not in " ".join(plan.steps_preview)
    listener = next(s for s in plan.steps_preview if "impacket-ntlmrelayx -t" in s)
    argv = shlex.split(listener.split(": ", 1)[1])
    protocol = "ldap" if action == "escalate" else "smb"
    assert argv[:3] == ["impacket-ntlmrelayx", "-t", f"{protocol}://braavos"]
    assert "-smb2support" in argv and "--no-http-server" in argv
    assert argv[argv.index("--smb-port") + 1] == "1445"
    if action == "dump":
        assert argv[argv.index("-l") + 1] == str(tmp_path / "loot")
    elif action == "escalate":
        assert "--delegate-access" in argv
    elif action == "shell":
        if shell_cmd:
            assert argv[argv.index("-c") + 1] == shell_cmd
        else:
            assert "-i" in argv and "-c" not in argv
    else:
        assert "-socks" in argv and "SHARE-LOOT" in " ".join(plan.steps_preview)
    if action != "dump":
        assert "-l" not in argv
    coercion = next(s for s in plan.steps_preview if "coercer coerce" in s)
    assert "-l 10.0.0.250:1445 -t braavos" in coercion

    receipt = executor.run(ctx, _finding(), overrides)
    tf = receipt["terminal_fact"]
    assert tf["kind"] == "relay_exposure"
    assert tf["classification"] == "coercion_dispatched_external"
    assert tf["action"] == action and tf["ok"] is False and receipt["complete"] is False
    assert receipt["errors"] == ["coercion_dispatched_external"]
    assert "10.0.0.250:1445" in tf["predicate"]
    assert [s["name"] for s in receipt["steps"]] == [
        "nxc_smb_signing", "nxc_ldap_signing", "external_listener", "coerce_trigger"]
    assert all(s["ok"] for s in receipt["steps"])
    assert [c[:2] for c in runner.calls] == [["nxc", "smb"], ["nxc", "ldap"], ["coercer", "coerce"]]
    trigger = runner.calls[-1]
    assert trigger[trigger.index("-l") + 1] == "10.0.0.250:1445"
    assert trigger[trigger.index("-t") + 1] == "braavos"
    assert receipt["mutation"]["applied"] is False


@pytest.mark.parametrize("action", ACTIONS)
def test_action_requires_external_listener(tmp_path, action):
    runner = _Runner(smb={"braavos": SMB_OFF}, ldap={"braavos": LDAP_NONE})
    receipt = get_executor("SIGNING-RELAY").run(
        _ctx(_cfg(), runner, tmp_path), _finding(), overrides={"action": action})
    tf = receipt["terminal_fact"]
    assert tf["classification"] == "external_listener_required"
    assert tf["kind"] == "relay_exposure" and tf["ok"] is False
    assert "Start ntlmrelayx" in tf["predicate"] and "external_listener=<ip>" in tf["predicate"]
    assert receipt["complete"] is False and receipt["errors"] == ["external_listener_required"]
    assert all(c[0] == "nxc" for c in runner.calls)


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("endpoint", ["", "10.0.0.250"])
def test_action_refuses_signing_enforced_target(tmp_path, action, endpoint):
    runner = _Runner(smb={"braavos": SMB_ON}, ldap={"braavos": LDAP_ENFORCED})
    receipt = get_executor("SIGNING-RELAY").run(
        _ctx(_cfg(), runner, tmp_path), _finding(),
        overrides={"action": action, "external_listener": endpoint})
    tf = receipt["terminal_fact"]
    assert tf["classification"] == "not_relay_exposed"
    assert tf["kind"] == "relay_exposure" and tf["ok"] is False and receipt["complete"] is False
    assert receipt["errors"] == ["not_relay_exposed"]
    assert all(c[0] == "nxc" for c in runner.calls)


@pytest.mark.parametrize("action", ACTIONS)
def test_action_requires_its_own_channel(tmp_path, action):
    # Another channel's exposure cannot qualify this action.
    runner = _Runner(smb={"braavos": SMB_OFF if action == "escalate" else SMB_ON},
                     ldap={"braavos": LDAP_ENFORCED if action == "escalate" else LDAP_NONE})
    receipt = get_executor("SIGNING-RELAY").run(
        _ctx(_cfg(), runner, tmp_path), _finding(),
        overrides={"action": action, "external_listener": "10.0.0.250"})
    assert receipt["terminal_fact"]["classification"] == "not_relay_exposed"
    assert all(c[0] == "nxc" for c in runner.calls)


@pytest.mark.parametrize("action", ACTIONS)
def test_action_selected_host_and_coerce_victim(tmp_path, action):
    runner = _Runner(smb={"selected": SMB_OFF, "braavos": SMB_ON},
                     ldap={"selected": LDAP_NONE, "braavos": LDAP_ENFORCED})
    ctx = _ctx(_cfg(extra_targets=["braavos"]), runner, tmp_path)
    executor = get_executor("SIGNING-RELAY")
    overrides = {"action": action, "hosts": "selected", "coerce_victim": "dc02",
                 "external_listener": "10.0.0.250"}
    plan = executor.plan(ctx, _finding(), overrides)
    assert "-t dc02" in " ".join(plan.steps_preview)
    receipt = executor.run(ctx, _finding(), overrides)
    assert receipt["terminal_fact"]["classification"] == "coercion_dispatched_external"
    assert receipt["terminal_fact"]["relay_target"] == "selected"
    assert receipt["target"] == ctx.config.resolve_target_identity("selected")
    trigger = runner.calls[-1]
    assert trigger[trigger.index("-t") + 1] == "dc02"


def test_action_does_not_switch_to_another_exposed_host(tmp_path):
    runner = _Runner(smb={"braavos": SMB_ON, "other": SMB_OFF},
                     ldap={"braavos": LDAP_ENFORCED, "other": LDAP_NONE})
    receipt = get_executor("SIGNING-RELAY").run(
        _ctx(_cfg(), runner, tmp_path), _finding(),
        overrides={"action": "dump", "hosts": "braavos,other", "external_listener": "10.0.0.250"})
    assert receipt["terminal_fact"]["classification"] == "not_relay_exposed"
    assert all(c[0] == "nxc" for c in runner.calls)


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("fired", [True, False])
def test_action_secret_guard_and_failed_trigger(tmp_path, action, fired):
    tokens = []
    for payload in ("actionSecretOne deadbeef", "actionSecretTwo cafebabe"):
        trigger = RunResult(1 if fired else None, stdout=payload, stderr=payload,
                            error=None if fired else payload, timed_out=not fired)
        runner = _Runner(smb={"braavos": SMB_OFF}, ldap={"braavos": LDAP_NONE}, trigger=trigger)
        receipt = get_executor("SIGNING-RELAY").run(
            _ctx(_cfg(password="OperatorSecret!"), runner, tmp_path), _finding(),
            overrides={"action": action, "external_listener": "10.0.0.250"})
        classification = "coercion_dispatched_external" if fired else "coerce_not_fired"
        assert receipt["terminal_fact"]["classification"] == classification
        assert receipt["terminal_fact"]["ok"] is False and receipt["complete"] is False
        assert receipt["errors"] == [classification]
        assert receipt["steps"][-1]["ok"] is fired
        blob = json.dumps(receipt)
        assert all(secret not in blob for secret in payload.split())
        assert "OperatorSecret!" not in blob
        tokens.append(receipt["terminal_fact"]["proof_token"])
    assert tokens[0] == tokens[1]


@pytest.mark.parametrize("action", ACTIONS)
def test_action_preserves_relay_authorization_gate(tmp_path, action):
    runner = _Runner(smb={"braavos": SMB_OFF}, ldap={"braavos": LDAP_NONE})
    ctx = _ctx(_cfg(), runner, tmp_path)
    ctx.authorizer = AuthorizedLabProvider(False)
    receipt = get_executor("SIGNING-RELAY").run(
        ctx, _finding(), overrides={"action": action, "external_listener": "10.0.0.250"})
    assert receipt["gate"] == {"classifier": "denied", "op": "relay"}
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "gate_denied:relay" in receipt["errors"]
    assert all(c[0] == "nxc" for c in runner.calls)
