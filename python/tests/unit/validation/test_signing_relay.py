"""SIGNING-RELAY: SMB/LDAP signing-posture + relay/reflection exposure (read-only).

A signing-REQUIRED target collapses the NTLM relay/reflection class; this edge reads the
posture and classifies where signing is NOT enforced (relayable) -- the control the 2025
CVEs hinge on. exit 0 is never proof: the posture parsed from the tool output decides.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (ExecutorContext, CommandRunner, RunResult,
                                                     AuthorizedLabProvider)


class _Runner(CommandRunner):
    """Scripted nxc: smb_out keyed per host, ldap_out keyed per host."""
    def __init__(self, smb=None, ldap=None):
        self.smb, self.ldap = smb or {}, ldap or {}
        self.calls = []
    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        if argv[:2] == ["nxc", "smb"]:
            return RunResult(returncode=0, stdout=self.smb.get(argv[2], ""))
        if argv[:2] == ["nxc", "ldap"]:
            return RunResult(returncode=0, stdout=self.ldap.get(argv[2], ""))
        return RunResult(returncode=0, stdout="")


def _cfg(**kw):
    base = dict(domain="north.sevenkingdoms.local", dc_ip="192.168.56.11",
                username="jon.snow", password="pw")
    base.update(kw)
    return ValidationConfig(**base)


def _ctx(cfg, runner, tmp_path):
    return ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                           output_dir=tmp_path)


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
