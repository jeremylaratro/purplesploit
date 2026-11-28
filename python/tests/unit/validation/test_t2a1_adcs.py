"""ADCS T2 A1: fake-tool request chains, private credentials and write recovery."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from purplesploit.validation import proof
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    AuthorizedLabProvider, CommandRunner, Credential, ExecutorContext, RunResult,
    redact_argv,
)
from purplesploit.validation.findings import map_finding
from purplesploit.validation.probes import get_probe, POSTURE_PROBES, PROBE_REGISTRY


TECHNIQUES = ["ADCS-ESC2", "ADCS-ESC3", "ADCS-ESC6"]
NT_HASH = "0123456789abcdef0123456789abcdef"
LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
PFX_BYTES = b"private-issued-pfx-payload"
CACHE_BYTES = b"private-ticket-payload"
HOST = "ca.example.test"


def _finding(technique):
    esc = technique.removeprefix("ADCS-")
    return map_finding({
        "finding_id": f"A1-{esc}", "host": HOST, "category": "adcs",
        "rule_id": "promoted-adcs-tpl",
        "line": f"AD CS CA EXAMPLE-CA AD CS template {esc}-Template ({esc})",
    })


class _Runner(CommandRunner):
    def __init__(self, *, fail=None, stop=None, failure=KeyboardInterrupt,
                 create_files=True, req_output=None, req_rc=0, nt_hash=NT_HASH,
                 pfx_name="private-victim.pfx"):
        self.fail, self.stop, self.failure = fail, stop, failure
        self.create_files = create_files
        self.req_output, self.req_rc = req_output, req_rc
        self.nt_hash, self.pfx_name = nt_hash, pfx_name
        self.calls, self.envs, self.obligations = [], [], []
        self.requests = 0
        self.ctx = None

    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        self.envs.append(env)
        if argv[:2] == ["certipy-ad", "req"]:
            self.requests += 1
            stage = f"req{self.requests}"
            assert self.ctx._pending_teardown is not None  # before EVERY write
            self.obligations.append(self.ctx._pending_teardown)
            is_agent = self.ctx._a1_technique == "ADCS-ESC3" and self.requests == 1
            path = Path(cwd) / ("private-agent.pfx" if is_agent else self.pfx_name)
            if self.create_files and self.fail != stage:
                path.write_bytes(PFX_BYTES)
            if self.stop == stage:
                raise self.failure("secret text must stay private")
            if self.fail == stage:
                return RunResult(1, stdout="[-] Request denied")
            output = ("[*] Successfully requested certificate\n"
                      f"[*] Request ID is {self.requests}\n"
                      "[*] Certificate serial number: AABBCC001122\n"
                      f"[*] Saved certificate and private key to '{path.name}'\n")
            return RunResult(self.req_rc, stdout=(
                output if self.req_output is None else self.req_output))
        if argv[:2] == ["certipy-ad", "auth"]:
            assert argv[argv.index("-pfx") + 1] == str(Path(cwd) / self.pfx_name)
            assert self.ctx._pending_teardown is not None
            if self.create_files:
                (Path(cwd) / "private-victim.ccache").write_bytes(CACHE_BYTES)
            if self.stop == "auth":
                raise self.failure("secret auth text")
            if self.fail == "auth":
                return RunResult(1, stdout="[-] KDC_ERR_CLIENT_NOT_TRUSTED")
            return RunResult(0, stdout=(
                "[*] Got TGT\n"
                "[*] Saved credential cache to 'private-victim.ccache'\n"
                f"[*] Got hash for 'victim@example.test': {LM_HASH}:{self.nt_hash}\n"))
        if argv[0] == "nxc":
            if self.fail == "nxc":
                return RunResult(1, stdout="[-] access denied")
            return RunResult(0, stdout="SMB server.example.test [+] victim (Pwn3d!)")
        raise AssertionError(f"unexpected tool: {argv[0]}")


class _Deny(AuthorizedLabProvider):
    def __init__(self, op, *, request_number=1):
        super().__init__(True)
        self.op, self.request_number, self.requests = op, request_number, 0

    def authorize(self, op, detail):
        if op == "adcs_cert_request":
            self.requests += 1
        return ("denied" if op == self.op and (
            op != "adcs_cert_request" or self.requests == self.request_number)
                else "not_required")


def _setup(tmp_path, technique, runner=None, authorizer=None):
    cfg = ValidationConfig(
        domain="example.test", dc_ip="192.0.2.1", username="operator",
        password="private-operator-password", host_aliases={HOST: {"host_id": "ca01"}})
    runner = runner or _Runner()
    ctx = ExecutorContext(cfg, runner, authorizer or AuthorizedLabProvider(True), tmp_path)
    runner.ctx = ctx
    ctx._a1_technique = technique
    return get_executor(technique), ctx, _finding(technique), runner


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_registration_mapping_defaults_and_preview(tmp_path, technique):
    ex, ctx, finding, runner = _setup(tmp_path, technique)
    assert is_implemented(technique)
    assert finding.technique == technique and finding.technique_class == "adcs"
    assert finding.verified_signal is False
    assert ex.mutating and ex.recovers_credentials and ex.verified_recipe is False
    plan = ex.plan(ctx, finding)
    assert plan.terminal_kind == "cert_issued_and_used"
    assert plan.params["template"].value == technique.removeprefix("ADCS-") + "-Template"
    assert {"ca", "ca_host", "impersonate", "target_host", "ldap_scheme"} <= plan.params.keys()
    assert runner.calls == []
    assert len(plan.steps_preview) == (5 if technique == "ADCS-ESC3" else 4)
    if technique == "ADCS-ESC3":
        assert plan.params["on_behalf_template"].value == "User"
        assert "-on-behalf-of" in plan.steps_preview[1]


@pytest.mark.parametrize("technique,default", zip(TECHNIQUES, ["ESC2", "ESC3", "User"]))
def test_template_fallback(tmp_path, technique, default):
    ex, ctx, finding, _ = _setup(tmp_path, technique)
    finding.entity.pop("template")
    assert ex.plan(ctx, finding).params["template"].value == default


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_request_auth_access_and_verified_destruction(tmp_path, technique):
    ex, ctx, finding, runner = _setup(tmp_path, technique)
    result = ex.run_composable(ctx, finding, {"impersonate": "victim"})
    receipt = result.receipt
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == technique and receipt["class"] == "adcs"
    assert receipt["target"]["host_id"] == "ca01" and receipt["target"]["domain"] == "example.test"
    assert receipt["executor"]["verified_recipe"] is False
    assert result.complete and receipt["complete"]
    expected = ["cert_request", "cert_auth", "nxc_access", "destroy_key_material"]
    if technique == "ADCS-ESC3":
        expected.insert(0, "enrollment_agent_request")
    assert [s["name"] for s in receipt["steps"]] == expected
    assert all(s["ok"] for s in receipt["steps"])
    assert receipt["terminal_fact"]["ok"] is True
    assert receipt["terminal_fact"]["kind"] == "cert_issued_and_used"
    assert receipt["terminal_fact"]["proof_token"]
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["dirty"] is False
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert "destroy issued-cert key material" in receipt["mutation"]["rollback"]["method"]
    assert not list(tmp_path.glob("*.pfx")) and not list(tmp_path.glob("*.ccache"))
    assert ctx._pending_teardown is None and result.teardown_obligation is None
    assert runner.envs[-1] == {"KRB5CCNAME": str(tmp_path / "private-victim.ccache")}
    assert "-k" in runner.calls[-1]
    creds = [cap for cap in result.capabilities if isinstance(cap, Credential)]
    assert len(creds) == 1
    assert creds[0].value == NT_HASH and creds[0].channel == "nt_hash"
    assert creds[0].principal == "victim@example.test"
    assert creds[0].source_technique == technique and creds[0].secret
    blob = json.dumps(receipt)
    for secret in (NT_HASH, LM_HASH, PFX_BYTES.decode(), CACHE_BYTES.decode(),
                   "private-operator-password", "private-victim.pfx", "private-agent.pfx",
                   "private-victim.ccache"):
        assert secret not in blob
    for call in runner.calls:
        display = redact_argv(call)
        for flag in ("-pfx", "-p", "-hashes"):
            if flag in call:
                assert display[display.index(flag) + 1] == "***"


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_public_token_independent_of_secrets(tmp_path, technique):
    tokens = []
    for i, nt_hash in enumerate((NT_HASH, "f" * 32)):
        out = tmp_path / str(i)
        ex, ctx, finding, _ = _setup(out, technique, _Runner(
            nt_hash=nt_hash, pfx_name=f"private-{i}.pfx"))
        receipt = ex.run(ctx, finding, {"impersonate": "victim"})
        tokens.append(receipt["terminal_fact"]["proof_token"])
    assert tokens[0] == tokens[1]


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_overrides_and_operator_hash_are_forwarded_privately(tmp_path, technique):
    ex, ctx, finding, runner = _setup(tmp_path, technique)
    ctx.config.password = None
    ctx.config.nt_hash = "e" * 32
    overrides = {"template": "CustomTemplate", "ca": "CUSTOM-CA",
                 "ca_host": "other.example.test", "target_host": "server.example.test",
                 "impersonate": "OTHER\\victim", "ldap_scheme": "ldap"}
    if technique == "ADCS-ESC3":
        overrides["on_behalf_template"] = "CustomUser"
    receipt = ex.run(ctx, finding, overrides)
    requests = [c for c in runner.calls if c[:2] == ["certipy-ad", "req"]]
    for req in requests:
        assert req[req.index("-ca") + 1] == "CUSTOM-CA"
        assert req[req.index("-target") + 1] == "other.example.test"
        assert req[req.index("-ldap-scheme") + 1] == "ldap"
        assert req[req.index("-hashes") + 1] == "e" * 32
    assert requests[0][requests[0].index("-template") + 1] == "CustomTemplate"
    if technique == "ADCS-ESC3":
        assert requests[1][requests[1].index("-on-behalf-of") + 1] == "OTHER\\victim"
        assert requests[1][requests[1].index("-template") + 1] == "CustomUser"
    else:
        assert requests[0][requests[0].index("-upn") + 1] == "victim@OTHER"
    assert runner.calls[-1][2] == "server.example.test"
    assert "e" * 32 not in json.dumps(receipt)


def test_esc3_two_requests_use_agent_then_victim_pfx(tmp_path):
    ex, ctx, finding, runner = _setup(tmp_path, "ADCS-ESC3")
    ex.run(ctx, finding, {"impersonate": "victim@example.test"})
    first, second, auth, _ = runner.calls
    assert first[:2] == second[:2] == ["certipy-ad", "req"]
    assert "-pfx" not in first and "-upn" not in first
    assert "-upn" not in second
    assert second[second.index("-on-behalf-of") + 1] == "example.test\\victim"
    assert second[second.index("-pfx") + 1] == str(tmp_path / "private-agent.pfx")
    assert auth[auth.index("-pfx") + 1] == str(tmp_path / "private-victim.pfx")
    assert runner.obligations[0] is runner.obligations[1]


@pytest.mark.parametrize("technique", TECHNIQUES)
@pytest.mark.parametrize("failure", ["req1", "auth", "nxc"])
def test_failed_step_never_fabricates_proof(tmp_path, technique, failure):
    ex, ctx, finding, runner = _setup(tmp_path, technique, _Runner(fail=failure))
    receipt = ex.run(ctx, finding)
    assert not (receipt["terminal_fact"] or {}).get("ok")
    if failure == "req1":
        assert receipt["terminal_fact"] is None and receipt["complete"] is False
        assert len(runner.calls) == 1
        assert receipt["mutation"]["applied"] and receipt["mutation"]["dirty"]
    if failure == "auth":
        assert not any(c[0] == "nxc" for c in runner.calls)
        assert receipt["mutation"]["rollback"]["verified"] is True
    assert not list(tmp_path.glob("*.pfx"))


def test_esc3_second_request_failure_still_destroys_agent(tmp_path):
    ex, ctx, finding, runner = _setup(tmp_path, "ADCS-ESC3", _Runner(fail="req2"))
    receipt = ex.run(ctx, finding)
    assert receipt["terminal_fact"] is None and receipt["complete"] is False
    assert len(runner.calls) == 2
    assert "cert_request_failed" in receipt["errors"]
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert not (tmp_path / "private-agent.pfx").exists()


@pytest.mark.parametrize("technique", TECHNIQUES)
@pytest.mark.parametrize("output,rc", [("new unknown wording", 0),
                                      ("Successfully requested certificate", 1)])
def test_unrecognized_or_failed_issue_is_not_positive(tmp_path, technique, output, rc):
    ex, ctx, finding, runner = _setup(tmp_path, technique, _Runner(req_output=output, req_rc=rc))
    receipt = ex.run(ctx, finding)
    assert receipt["terminal_fact"] is None and receipt["complete"] is False
    assert len(runner.calls) == 1
    assert not receipt["steps"][0]["ok"]


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_request_gate_denial_has_no_mutation(tmp_path, technique):
    ex, ctx, finding, runner = _setup(tmp_path, technique,
                                    authorizer=_Deny("adcs_cert_request"))
    receipt = ex.run(ctx, finding)
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["terminal_fact"] is None and not receipt["complete"]
    assert not receipt["mutation"]["applied"]
    assert not runner.calls and ctx._pending_teardown is None


def test_esc3_second_gate_denial_recovers_first_request(tmp_path):
    ex, ctx, finding, runner = _setup(tmp_path, "ADCS-ESC3", authorizer=_Deny(
        "adcs_cert_request", request_number=2))
    receipt = ex.run(ctx, finding)
    assert len(runner.calls) == 1 and receipt["terminal_fact"] is None
    assert receipt["mutation"]["applied"]
    assert receipt["mutation"]["rollback"]["verified"]
    assert not list(tmp_path.glob("*.pfx"))


@pytest.mark.parametrize("technique", TECHNIQUES)
@pytest.mark.parametrize("mode", ["absent", "undeletable", "denied"])
def test_unverified_cleanup_stays_dirty(tmp_path, technique, mode):
    runner = _Runner(create_files=mode != "absent")
    ex, ctx, finding, _ = _setup(tmp_path, technique, runner,
                               _Deny("rollback") if mode == "denied" else None)
    if mode == "undeletable":
        (tmp_path / "private-victim.pfx").mkdir()
        # Keep the directory in place while other fake outputs are writable.
        original = runner.run

        def run(argv, **kwargs):
            if argv[:2] == ["certipy-ad", "req"]:
                runner.create_files = False
            else:
                runner.create_files = True
            return original(argv, **kwargs)
        runner.run = run
    receipt = ex.run(ctx, finding)
    assert receipt["terminal_fact"]["ok"] is True
    assert receipt["mutation"]["applied"] and receipt["mutation"]["dirty"]
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert ctx._pending_teardown is not None
    assert "gate_denied:rollback" in receipt["errors"] if mode == "denied" else (
        "rollback_unverified" in receipt["errors"])


@pytest.mark.parametrize("technique,stage", [
    ("ADCS-ESC2", "req1"), ("ADCS-ESC3", "req1"),
    ("ADCS-ESC3", "req2"), ("ADCS-ESC6", "req1"),
    *[(t, "auth") for t in TECHNIQUES],
])
@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("create_files", [False, True])
def test_interrupted_write_recovery(tmp_path, technique, stage, failure, create_files):
    unrelated = tmp_path / "unrelated.ccache"
    unrelated.write_bytes(b"preserve unrelated credential")
    runner = _Runner(stop=stage, failure=failure, create_files=create_files)
    ex, ctx, finding, _ = _setup(tmp_path, technique, runner)
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            ex.run(ctx, finding)
    else:
        receipt = ex.run(ctx, finding)
        assert receipt["complete"] is False and receipt["terminal_fact"] is None
        assert "secret text" not in json.dumps(receipt)
    artifact = ctx._last_artifact
    assert artifact["mutation"]["applied"] is True
    assert artifact["mutation"]["dirty"] is (not create_files)
    assert artifact["mutation"]["rollback"]["verified"] is create_files
    assert (ctx._pending_teardown is None) is create_files
    assert not list(tmp_path.glob("*.pfx"))
    assert list(tmp_path.glob("*.ccache")) == [unrelated]


class _FindRunner(CommandRunner):
    def __init__(self, output, rc=0):
        self.output, self.rc, self.calls = output, rc, []

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        assert argv[:2] == ["certipy-ad", "find"]
        assert "-vulnerable" in argv
        return RunResult(self.rc, stdout=self.output)


@pytest.mark.parametrize("technique", TECHNIQUES)
@pytest.mark.parametrize("mode", ["positive", "negative", "unknown", "error"])
def test_precondition_probes(tmp_path, technique, mode):
    ex, ctx, finding, _ = _setup(tmp_path, technique)
    esc = technique.removeprefix("ADCS-")
    text = {"positive": f"Certificate Templates\n{esc}-Template\n[!] {esc}",
            "negative": "Certipy\nFound 0 certificate authorities",
            "unknown": "Certificate Templates\nOther-Template ESC1",
            "error": f"Certificate Templates\n{esc}-Template\n{esc}"}[mode]
    runner = ctx.runner = _FindRunner(text, int(mode == "error"))
    assert technique in PROBE_REGISTRY and technique not in POSTURE_PROBES
    result = get_probe(technique).check(ctx, finding)
    assert result.viable is (mode != "negative")
    assert result.unknown is (mode in {"unknown", "error"})
    assert len(runner.calls) == 1
    assert "private-operator-password" not in json.dumps(result.to_dict())


@pytest.mark.parametrize("technique", TECHNIQUES)
def test_no_vulnerable_templates_probe_semantics(tmp_path, technique):
    ex, ctx, finding, _ = _setup(tmp_path, technique)
    ctx.runner = _FindRunner("Certificate Authorities\nFound 0 vulnerable templates")
    result = get_probe(technique).check(ctx, finding)
    assert result.viable is (technique == "ADCS-ESC6")
    assert result.unknown is (technique == "ADCS-ESC6")


def test_esc6_probe_ca_san_flag(tmp_path):
    ex, ctx, finding, _ = _setup(tmp_path, "ADCS-ESC6")
    ctx.runner = _FindRunner("Certificate Authorities\nUser Specified SAN : Enabled\nESC6-Template")
    result = get_probe("ADCS-ESC6").check(ctx, finding)
    assert result.viable and not result.unknown
