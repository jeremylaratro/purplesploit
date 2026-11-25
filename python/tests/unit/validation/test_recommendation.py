"""Recommendation / parameter-defaulting logic (no lab needed).

Covers the #66142 "recommended default + operator-overridable" model and the
RBCD vertical slice end-to-end with a scripted fake runner, asserting the
emitted receipt is a well-formed ``adlab.plan003.proof.v1`` that the harness
scorer would read as *proved* (correct schema, all steps ok, verified rollback,
non-secret terminal fact, no secret leakage).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from purplesploit.validation.config import ValidationConfig, principal_base
from purplesploit.validation.recommend import (
    ParamSpec, resolve_params, params_preview,
    escalation_test_user, delegation_computer, recommended_spn,
    validate_sam_name, sam_name_warning, ParamValidationError,
)
from purplesploit.validation.findings import NormalizedFinding, map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
)
from purplesploit.validation import proof


# ----------------------------------------------------------------- derivation
def test_principal_base_strips_domain_forms():
    assert principal_base("joe") == "joe"
    assert principal_base("NORTH\\joe") == "joe"
    assert principal_base("joe@north.sevenkingdoms.local") == "joe"
    assert principal_base(None) == "op"


def test_owner_worked_example_defaults():
    # The #66142 worked example, verbatim: joe -> joe_escalation_test / joe_cmp_delegation.
    assert escalation_test_user("joe") == "joe_escalation_test"
    assert delegation_computer("joe") == "joe_cmp_delegation"
    assert recommended_spn("cifs", "winterfell") == "cifs/winterfell"


# ----------------------------------------------------------------- validators
def test_sam_validator_hard_and_soft_limits():
    assert validate_sam_name("joe_cmp_delegation") is None          # 18 chars: valid sAM
    assert sam_name_warning("joe_cmp_delegation") is not None       # > 15: advisory only
    assert sam_name_warning("shortpc") is None
    assert validate_sam_name("way_too_long_computer_name") is not None  # > 20: hard error
    assert validate_sam_name("bad\\name") is not None               # illegal char
    assert validate_sam_name("") is not None


# ----------------------------------------------------------------- resolve_params
def _specs():
    return [
        ParamSpec("new_computer", "computer_name", "new computer",
                  recommended="joe_cmp_delegation", rationale="owner example",
                  validator=validate_sam_name, advisory=sam_name_warning),
        ParamSpec("impersonate", "escalation_target", "principal to impersonate",
                  recommended="Administrator", rationale="high-value default"),
    ]


def test_resolve_defaults_when_no_override():
    resolved = resolve_params(_specs())
    assert resolved["new_computer"].value == "joe_cmp_delegation"
    assert resolved["new_computer"].source == "recommended"
    assert resolved["new_computer"].overridden is False
    # The over-15-char default still surfaces its advisory (not an error).
    assert resolved["new_computer"].warning is not None
    assert resolved["impersonate"].value == "Administrator"


def test_operator_override_wins_and_is_marked():
    resolved = resolve_params(_specs(), {"impersonate": "joe", "new_computer": "shortpc"})
    assert resolved["impersonate"].value == "joe"
    assert resolved["impersonate"].source == "operator-override"
    assert resolved["impersonate"].overridden is True
    assert resolved["new_computer"].value == "shortpc"
    assert resolved["new_computer"].warning is None   # short name: no advisory


def test_override_is_validated():
    with pytest.raises(ParamValidationError):
        resolve_params(_specs(), {"new_computer": "way_too_long_computer_name"})


def test_unknown_override_rejected():
    with pytest.raises(ParamValidationError):
        resolve_params(_specs(), {"nope": "x"})


def test_params_preview_shape():
    preview = params_preview(resolve_params(_specs()))
    row = {p["name"]: p for p in preview}["new_computer"]
    assert row["recommended"] == "joe_cmp_delegation"
    assert row["source"] == "recommended"
    assert "rationale" in row and "description" in row


# ----------------------------------------------------------------- RBCD param specs
def _config(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.10",
                username="joe", password="Winter2022!",
                host_aliases={"winterfell.north.sevenkingdoms.local": {"host_id": "dc01"}})
    base.update(kw)
    return ValidationConfig(**base)


def _rbcd_finding(host="winterfell.north.sevenkingdoms.local") -> NormalizedFinding:
    return map_finding({
        "finding_id": "AR-abc123", "logical_id": "AR-L-abc", "host": host,
        "category": "delegation", "severity": "high",
        "line": "msDS-AllowedToActOnBehalfOfOtherIdentity writable on dc01",
    })


def test_rbcd_param_specs_defaults_from_config():
    cfg = _config()
    finding = _rbcd_finding()
    assert finding.technique == "RBCD" and finding.technique_class == "delegation"
    ctx = ExecutorContext(cfg, runner=_StubRunner({}), authorizer=AuthorizedLabProvider(),
                          output_dir=Path("/tmp"))
    specs = {s.name: s for s in get_executor("RBCD").param_specs(ctx, finding)}
    assert specs["new_computer"].recommended == "joe_cmp_delegation"   # <user>_cmp_delegation
    assert specs["delegate_to"].recommended == finding.host
    assert specs["impersonate"].recommended == "Administrator"
    assert specs["target_spn"].recommended == "cifs/winterfell.north.sevenkingdoms.local"


# ----------------------------------------------------------------- fake runner
class _StubRunner(CommandRunner):
    """Return a scripted stdout keyed on the tool + action in the argv."""

    def __init__(self, script: dict[str, RunResult]):
        self.script = script
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        key = self._key(argv)
        return self.script.get(key, RunResult(returncode=0, stdout=""))

    @staticmethod
    def _key(argv) -> str:
        tool = Path(argv[0]).name
        action = ""
        if "-action" in argv:
            action = argv[argv.index("-action") + 1]
        elif "-delete" in argv:
            action = "delete"
        elif tool == "nxc":
            action = "smb"
        elif tool == "impacket-getST":
            action = "getst"
        return f"{tool}:{action}" if action else tool


def _proved_script() -> dict:
    return {
        "impacket-addcomputer": RunResult(0, stdout="[*] Successfully added machine account joe_cmp_delegation$"),
        "impacket-rbcd:write": RunResult(0, stdout="[*] Delegation rights modified successfully!"),
        "impacket-getST:getst": RunResult(0, stdout="[*] Saving ticket in Administrator.ccache"),
        "nxc:smb": RunResult(0, stdout="SMB  winterfell  445  [+] north\\Administrator (Pwn3d!)"),
        "impacket-rbcd:flush": RunResult(0, stdout="[*] Delegation rights flushed successfully"),
        "impacket-rbcd:read": RunResult(0, stdout="[*] Accounts allowed to act: (none)"),
        "impacket-addcomputer:delete": RunResult(0, stdout="[*] Successfully deleted machine account joe_cmp_delegation$"),
    }


# ----------------------------------------------------------------- RBCD end-to-end
def test_rbcd_executor_emits_proved_shaped_receipt(tmp_path):
    cfg = _config()
    finding = _rbcd_finding()
    runner = _StubRunner(_proved_script())
    ctx = ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    receipt = get_executor("RBCD").run(ctx, finding)

    # proof.v1 shape the scorer requires for a 'proved' verdict.
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "RBCD" and receipt["class"] == "delegation"
    assert receipt["target"].get("host_id") == "dc01"       # scored against the facet's host_id
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "rbcd_access" and tf["ok"] is True
    assert tf["proof_token"] and tf["impersonated"] == "Administrator"
    assert "rollback_unverified" not in receipt["errors"]

    # The chain ran the full recipe incl. verified rollback (addcomputer deleted).
    tools = [Path(c[0]).name for c in runner.calls]
    assert tools.count("impacket-addcomputer") == 2   # create + delete
    assert "nxc" in tools


def test_rbcd_operator_override_changes_impersonation_and_computer(tmp_path):
    cfg = _config()
    finding = _rbcd_finding()
    runner = _StubRunner(_proved_script())
    ctx = ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    get_executor("RBCD").run(ctx, finding, overrides={"impersonate": "joe", "new_computer": "testpc"})
    getst = next(c for c in runner.calls if Path(c[0]).name == "impacket-getST")
    assert "joe" in getst and getst[getst.index("-impersonate") + 1] == "joe"
    addc = next(c for c in runner.calls if Path(c[0]).name == "impacket-addcomputer")
    assert "testpc$" in addc


def test_rbcd_no_secret_in_receipt(tmp_path):
    cfg = _config(password="SuperSecret123!")
    runner = _StubRunner(_proved_script())
    ctx = ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                          output_dir=tmp_path)
    receipt = get_executor("RBCD").run(ctx, _rbcd_finding())
    import json as _json
    blob = _json.dumps(receipt)
    assert "SuperSecret123!" not in blob          # operator password never stored
    assert ".ccache" not in blob                   # ticket path is secret-marked, dropped


def test_rbcd_gate_denied_yields_inconclusive_not_proof(tmp_path):
    class _Deny(AuthorizedLabProvider):
        def authorize(self, op, detail):
            return "denied"
    cfg = _config()
    runner = _StubRunner(_proved_script())
    ctx = ExecutorContext(cfg, runner=runner, authorizer=_Deny(True), output_dir=tmp_path)
    receipt = get_executor("RBCD").run(ctx, _rbcd_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False
    assert receipt["terminal_fact"] is None         # no proof when the gate denied the op
