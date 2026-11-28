"""Phase 4a adversarial gates. All tools are injected; no network calls."""
from __future__ import annotations

import json
import signal

import pytest

from purplesploit.validation import autopwn, cli, discovery, probes, states
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.credential_store import CredentialStore
from purplesploit.validation.executors import IMPLEMENTED, get_executor
from purplesploit.validation.executors.base import Credential, RunResult, CAP_PASSWORD


DC = "dc.lab.example"
HOST = "member.lab.example"
OUT = "outside.other.example"
SECRET = "NEVER-PRINT-password-93a21"


class RecordingRunner:
    def __init__(self, hook=None):
        self.calls = []
        self.timeouts = []
        self.hook = hook

    def run(self, argv, *, timeout=None):
        self.calls.append(list(argv))
        self.timeouts.append(timeout)
        if self.hook:
            return self.hook(argv)
        return RunResult(0, stdout=(
            "[+] Response for object: CN=svc\n"
            "sAMAccountName svc\nuserAccountControl 4194304\n"
            "msDS-SupportedEncryptionTypes 4\n"
            "msDS-AllowedToDelegateTo cifs/member.lab.example\n"
            "servicePrincipalName cifs/member.lab.example\n"
            "ms-DS-MachineAccountQuota 10\nmsDS-Behavior-Version 7\n"
            "signing:False\n" + SECRET), stderr=SECRET)


def config(tmp_path, **kwargs):
    opts = dict(domain="lab.example", dc_ip=DC, username="operator", password=SECRET,
                output_dir=tmp_path, extra_targets=[HOST])
    opts.update(kwargs)
    return ValidationConfig(**opts)


def run_plan(tmp_path, runner=None, **kwargs):
    return autopwn.plan(config(tmp_path), scope=[f"{DC},{HOST}"],
                        runner=runner or RecordingRunner(), **kwargs)


def audit_text(tmp_path):
    return '\n'.join(p.read_text() for p in tmp_path.glob("autopwn-*.jsonl"))


def forbid(*args, **kwargs):
    raise AssertionError("forbidden execution or secret read")


def only(monkeypatch, *techniques):
    monkeypatch.setattr(autopwn, "IMPLEMENTED", set(techniques))


@pytest.fixture(autouse=True)
def no_real_tools(monkeypatch):
    # Any accidentally un-injected production runner is a test failure.
    monkeypatch.setattr(autopwn.SubprocessRunner, "run", forbid)


def test_default_never_executes_or_reads_secret(tmp_path, monkeypatch, caplog, capsys):
    forbidden_calls = []
    def record_forbidden(*args, **kwargs):
        forbidden_calls.append(type(args[0]).__name__ if args else "forbidden")
        raise AssertionError("forbidden execution or secret read")
    for technique in IMPLEMENTED:
        cls = type(get_executor(technique))
        for method in ("run", "execute", "produce", "plan", "steps_preview", "revealed_secrets"):
            monkeypatch.setattr(cls, method, record_forbidden, raising=False)
    monkeypatch.setattr(probes.LapsProbe, "check", record_forbidden)
    monkeypatch.setattr(probes.CoercionProbe, "check", record_forbidden)
    monkeypatch.setattr(probes, "_certipy_find", record_forbidden)
    monkeypatch.setattr(discovery, "recon", record_forbidden)
    monkeypatch.setattr(discovery, "candidate_findings", record_forbidden)
    monkeypatch.setattr(CredentialStore, "load", record_forbidden)
    runner = RecordingRunner()
    report = run_plan(tmp_path, runner, params={"ASREP": {"principal": "svc"},
                                              "KERBEROAST": {"principal": "svc"}})
    assert report["status"] == "empty_frontier"
    assert forbidden_calls == []
    assert runner.calls
    assert all(c[0] in ("nxc", "impacket-dacledit") for c in runner.calls)
    for call in runner.calls:
        if call[0] == "nxc":
            assert call[1] in ("ldap", "smb")
            assert call[2] in (DC, HOST)
            if "--query" in call:
                assert set(call[-1].lower().split()) <= autopwn.POSTURE_ATTRIBUTES
        else:
            assert call[1:3] == ["-action", "read"]
        assert not any(flag in call for flag in ("--laps", "--ntds", "-x", "-X", "--sam"))
    assert any(h["technique"] == "ASREP" and h["would_gain_credential"]
               for h in report["projected_path"])
    assert not report["goal_reached"]
    assert report["goal_status"] == "not_established"
    assert SECRET not in json.dumps(report) + audit_text(tmp_path) + caplog.text + capsys.readouterr().out


def test_new_generic_secret_probe_not_opted_into_planner(tmp_path, monkeypatch):
    class SecretProbe(probes.PreconditionProbe):
        technique = "SIGNING-RELAY"
        check = forbid
    monkeypatch.setitem(probes.PROBE_REGISTRY, "SIGNING-RELAY", SecretProbe)
    only(monkeypatch, "SIGNING-RELAY")
    report = run_plan(tmp_path)
    assert report["projected_path"]


@pytest.mark.parametrize("args", [[], ["--scope", HOST], ["--yes", "--allow-destructive", "--scope", HOST]])
def test_execute_always_hard_errors_before_config(args, monkeypatch, capsys):
    monkeypatch.setattr(cli, "build_config", forbid)
    with pytest.raises(SystemExit) as exc:
        cli.main(["autopwn", "--execute", *args])
    assert exc.value.code == 2
    assert "execution not yet supported (Phase 4b)" in capsys.readouterr().err


@pytest.mark.parametrize("option", ["--as-cred", "--forge-key-file", "--forge-key-nt-file"])
def test_cli_never_loads_secret_files_or_store(option, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_read_key", forbid)
    monkeypatch.setattr(cli, "credential_scope", forbid)
    monkeypatch.setattr(CredentialStore, "load", forbid)
    with pytest.raises(SystemExit) as exc:
        cli.main(["autopwn", "--domain", "lab.example", "--dc-ip", DC,
                  "--scope", DC, option, "private-file-or-selector"])
    assert exc.value.code == 2
    assert SECRET not in capsys.readouterr().err


def test_cli_public_output_and_no_orchestrator(tmp_path, monkeypatch, capsys):
    only(monkeypatch, "ASREP")
    runner = RecordingRunner()
    monkeypatch.setattr(autopwn, "SubprocessRunner", lambda: runner)
    monkeypatch.setattr(cli, "ValidationOrchestrator", forbid)
    monkeypatch.setattr(cli, "_read_key", forbid)
    monkeypatch.setattr(cli, "credential_scope", forbid)
    status = cli.main(["--domain", "lab.example", "--dc-ip", DC, "--user", "operator",
                       "--password", SECRET, "--output", str(tmp_path), "autopwn",
                       "--scope", DC, "--param", "ASREP.principal=svc"])
    assert status == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["header"]["mode"] == "dry_run"
    assert report["projected_path"][0]["would_gain_credential"]
    assert SECRET not in output + audit_text(tmp_path)


@pytest.mark.parametrize("host,expected", [
    ("MEMBER.LAB.EXAMPLE.", True), ("x.sub.lab.example", True),
    ("evillab.example", False), ("x.lab.example.evil", False),
    ("lab.example", False), ("192.0.2.1", False),
    ("https://member.lab.example", False), ("--target", False),
])
def test_domain_membership_is_lexical_boundary(host, expected):
    fence = autopwn.ScopeFence.parse(domains=["LAB.EXAMPLE."])
    assert fence.contains(host) is expected


def test_explicit_fence_and_targets_materialize(tmp_path, monkeypatch):
    only(monkeypatch, "SIGNING-RELAY")
    runner = RecordingRunner()
    cfg = config(tmp_path, extra_targets=[HOST, OUT])
    report = autopwn.plan(cfg, scope=[f"{DC},{HOST}"], runner=runner)
    assert report["header"]["fence"]["hosts"] == [DC, HOST]
    assert any(e["outcome"] == "skipped_out_of_scope" and e["target"] == OUT for e in report["events"])
    assert all(h["target"] != OUT for h in report["projected_path"])


def test_domain_form_with_explicit_target(tmp_path, monkeypatch):
    only(monkeypatch, "ASREP")
    runner = RecordingRunner()
    report = autopwn.plan(config(tmp_path), scope_domain=["lab.example"], runner=runner,
                          params={"ASREP": {"principal": "svc"}})
    assert report["header"]["fence"]["domains"] == ["lab.example"]
    assert report["projected_path"][0]["target"] == HOST
    assert all(c[2] == DC for c in runner.calls)


def test_enumerate_form_materializes_before_discovery(tmp_path, monkeypatch):
    only(monkeypatch, "SIGNING-RELAY")
    def response(argv):
        assert argv[-3:] == ["--query", "(objectClass=computer)", "dNSHostName"]
        return RunResult(0, stdout=(f"[+] Response for object: CN=DC\ndNSHostName {DC}\n"
                                    f"dNSHostName: {HOST}\ndNSHostName {OUT}\n"
                                    f"[+] domain\\user:{SECRET} dNSHostName banner.lab.example\n"))
    runner = RecordingRunner(response)
    report = autopwn.plan(config(tmp_path, extra_targets=[]), scope_enumerate=["lab.example"], runner=runner)
    fence = report["header"]["fence"]
    assert fence == {"hosts": [DC, HOST], "domains": [], "enumerated_hosts": [DC, HOST],
                     "enumeration_endpoints": [DC]}
    assert len(runner.calls) == 1
    assert {h["target"] for h in report["projected_path"]} == {DC, HOST}
    assert SECRET not in audit_text(tmp_path)


def test_enumerate_ip_requires_explicit_bootstrap_fence(tmp_path):
    runner = RecordingRunner()
    report = autopwn.plan(config(tmp_path, dc_ip="192.0.2.1", extra_targets=[]),
                          scope_enumerate=["lab.example"], runner=runner)
    assert not runner.calls
    assert not report["projected_path"]
    assert any(e["outcome"] == "skipped_out_of_scope" for e in report["events"])


def test_enumerate_ip_with_explicit_bootstrap(tmp_path, monkeypatch):
    only(monkeypatch, "SIGNING-RELAY")
    runner = RecordingRunner(lambda argv: RunResult(0, stdout=f"dNSHostName {HOST}"))
    report = autopwn.plan(config(tmp_path, dc_ip="192.0.2.1", extra_targets=[]),
                          scope=["192.0.2.1"], scope_enumerate=["lab.example"], runner=runner)
    assert runner.calls[0][2] == "192.0.2.1"
    assert HOST in report["header"]["fence"]["enumerated_hosts"]


@pytest.mark.parametrize("kwargs", [dict(), dict(scope_domain=["other.example"]),
                                     dict(scope_enumerate=["lab.example"])])
def test_empty_scope_never_falls_back_to_dc(tmp_path, kwargs):
    runner = RecordingRunner(lambda argv: RunResult(0, stdout="0 computers"))
    report = autopwn.plan(config(tmp_path, extra_targets=[]), runner=runner, **kwargs)
    assert report["status"] == "empty_scope"
    assert not report["projected_path"]
    assert len(runner.calls) == (1 if "scope_enumerate" in kwargs else 0)


@pytest.mark.parametrize("technique,overrides", [
    ("ASREP", {"principal": "svc", "reauth_target": OUT}),
    ("COERCION", {"listener_host": OUT}),
    ("NTLM-RELAY", {"relay_target": OUT, "listener_host": HOST}),
    ("NTLM-RELAY", {"victim_dc": OUT, "listener_host": HOST}),
    ("NTLM-RELAY", {"listener_host": HOST, "external_listener": OUT}),
    ("ESC8", {"ca_host": OUT, "listener_host": HOST}),
    ("CONSTRAINED-DELEG-PT", {"target_spn": "cifs/" + OUT}),
    ("SIGNING-RELAY", {"coerce_victim": OUT}),
    ("SIGNING-RELAY", {"hosts": HOST + ',' + OUT}),
])
def test_every_resolved_secondary_destination_is_fenced(tmp_path, monkeypatch, technique, overrides):
    only(monkeypatch, technique)
    runner = RecordingRunner()
    report = run_plan(tmp_path, runner, params={technique: overrides})
    assert not runner.calls
    assert not report["projected_path"]
    assert any(e["outcome"] == "skipped_out_of_scope" for e in report["events"])


@pytest.mark.parametrize("field", ["dc_ip", "kdc_host", "dns_server"])
def test_infrastructure_outside_fence_never_dispatched(tmp_path, monkeypatch, field):
    only(monkeypatch, "ASREP")
    runner = RecordingRunner()
    report = autopwn.plan(config(tmp_path, **{field: OUT}), scope=[DC, HOST], runner=runner,
                          params={"ASREP": {"principal": "svc"}})
    assert not runner.calls
    assert not report["projected_path"]
    assert any(e["outcome"] == "skipped_out_of_scope" and e["target"] == OUT for e in report["events"])


def test_discovered_spn_outside_fence_not_followed_or_projected(tmp_path, monkeypatch):
    only(monkeypatch, "CONSTRAINED-DELEG-PT")
    runner = RecordingRunner(lambda argv: RunResult(0, stdout=(
        "[+] Response for object: CN=op\nsAMAccountName op\n"
        f"msDS-AllowedToDelegateTo cifs/{OUT}\nuserAccountControl 16777216")))
    report = run_plan(tmp_path, runner)
    assert runner.calls and all(call[2] == DC for call in runner.calls)
    assert not report["projected_path"]
    assert any(e["outcome"] == "skipped_out_of_scope" for e in report["events"])


@pytest.mark.parametrize("technique", ["COERCION", "NTLM-RELAY", "ESC8", "ESC11", "UNCONSTRAINED-DELEG"])
def test_runtime_selected_callback_is_not_implicitly_in_scope(tmp_path, monkeypatch, technique):
    only(monkeypatch, technique)
    runner = RecordingRunner()
    report = run_plan(tmp_path, runner)
    assert not runner.calls
    assert not report["projected_path"]


def test_audit_public_allowlist_even_with_secret_result(tmp_path, monkeypatch, caplog, capsys):
    only(monkeypatch, "ASREP")
    credential = Credential(state=states.S_ACL_CRED, channel=CAP_PASSWORD, value=SECRET, principal="svc")
    monkeypatch.setattr(probes, "non_secret_probe", lambda ctx, finding:
        probes.ProbeResult(viable=True, reason=SECRET,
            evidence={"value": SECRET, "produced_credentials": [credential],
                      "teardown": {"password": SECRET}, "exception": SECRET}))
    report = run_plan(tmp_path, params={"ASREP": {"principal": "svc"}})
    assert report["projected_path"]
    rows = [json.loads(line) for line in audit_text(tmp_path).splitlines()]
    assert rows[0] == {"header": report["header"]}
    fields = {"outcome", "technique", "target", "classification", "principal", "in_scope"}
    assert all(set(e) == fields for e in report["events"])
    assert all(set(row) == fields for row in rows[1:-1])
    assert SECRET not in json.dumps(report) + audit_text(tmp_path) + caplog.text + capsys.readouterr().out


def test_exception_messages_never_reach_audit_or_private_logs(tmp_path, monkeypatch, caplog):
    only(monkeypatch, "ASREP")
    contexts = []
    original = autopwn.ExecutorContext
    def context(*args, **kwargs):
        ctx = original(*args, **kwargs)
        contexts.append(ctx)
        return ctx
    monkeypatch.setattr(autopwn, "ExecutorContext", context)
    def explode(argv):
        raise RuntimeError(SECRET)
    report = run_plan(tmp_path, RecordingRunner(explode), params={"ASREP": {"principal": "svc"}})
    assert not report["projected_path"]
    assert all(not c._private_errors for c in contexts)
    assert SECRET not in json.dumps(report) + audit_text(tmp_path) + caplog.text


@pytest.mark.parametrize("suffix", [["--laps"], ["-x", "whoami"],
    ["--query", "(objectClass=*)", "ms-Mcs-AdmPwd"],
    ["--query", "(objectClass=*)", "msLAPS-Password"], ["--query", "(objectClass=*)", "*"]])
def test_tool_boundary_denies_new_secret_or_mutating_options(tmp_path, monkeypatch, suffix):
    only(monkeypatch, "ASREP")
    class BadProbe:
        def check(self, ctx, finding):
            ctx.runner.run(["nxc", "ldap", DC, *probes._nxc_auth(ctx.config), *suffix])
            return probes.ProbeResult(viable=True)
    monkeypatch.setitem(probes.POSTURE_PROBES, "ASREP", BadProbe)
    runner = RecordingRunner()
    report = run_plan(tmp_path, runner, params={"ASREP": {"principal": "svc"}})
    assert not runner.calls
    assert not report["projected_path"]


def test_tool_boundary_fences_destination_even_if_probe_chooses_another_host(tmp_path, monkeypatch):
    only(monkeypatch, "ASREP")
    class EscapingProbe:
        def check(self, ctx, finding):
            ctx.runner.run(["nxc", "smb", OUT, *probes._nxc_auth(ctx.config)])
    monkeypatch.setitem(probes.POSTURE_PROBES, "ASREP", EscapingProbe)
    runner = RecordingRunner()
    report = run_plan(tmp_path, runner, params={"ASREP": {"principal": "svc"}})
    assert not runner.calls
    assert any(e["outcome"] == "skipped_out_of_scope" and e["target"] == OUT for e in report["events"])


def test_kill_file_mid_plan_stops_before_next_expansion(tmp_path, monkeypatch):
    only(monkeypatch, "ASREP", "SIGNING-RELAY")
    sentinel = tmp_path / "STOP"
    def stop(argv):
        sentinel.touch()
        return RunResult(0)
    runner = RecordingRunner(stop)
    report = run_plan(tmp_path, runner, kill_file=sentinel, params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "kill_file"
    assert len(runner.calls) == 1
    assert not report["projected_path"]
    assert report["status"] in audit_text(tmp_path)


def test_kill_file_between_tools_in_same_expansion(tmp_path, monkeypatch):
    only(monkeypatch, "NTLM-RELAY")
    sentinel = tmp_path / "STOP"
    def stop(argv):
        sentinel.touch()
        return RunResult(0, stdout="signing:True")  # would otherwise launch LDAP fallback
    runner = RecordingRunner(stop)
    report = run_plan(tmp_path, runner, kill_file=sentinel,
                      params={"NTLM-RELAY": {"listener_host": HOST}})
    assert report["status"] == "kill_file"
    assert len(runner.calls) == 1


def test_sigint_stops_cleanly_and_restores_handler(tmp_path, monkeypatch):
    only(monkeypatch, "ASREP")
    previous = signal.getsignal(signal.SIGINT)
    def interrupt(argv):
        signal.raise_signal(signal.SIGINT)
        return RunResult(0)
    runner = RecordingRunner(interrupt)
    report = run_plan(tmp_path, runner, params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "interrupted"
    assert len(runner.calls) == 1
    assert signal.getsignal(signal.SIGINT) == previous
    assert 'interrupted' in audit_text(tmp_path)


@pytest.mark.parametrize("kwargs,status", [(dict(max_hops=0), "max_hops"),
    (dict(max_time=0), "max_time")])
def test_zero_budget_before_any_read(tmp_path, kwargs, status):
    runner = RecordingRunner()
    report = run_plan(tmp_path, runner, **kwargs)
    assert report["status"] == status
    assert not runner.calls


def test_max_hops_bounds_candidate_expansions(tmp_path, monkeypatch):
    only(monkeypatch, "ASREP", "SIGNING-RELAY")
    runner = RecordingRunner()
    report = run_plan(tmp_path, runner, max_hops=1, params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "max_hops"
    assert len(runner.calls) == 1
    assert len(report["projected_path"]) == 1


def test_max_time_during_read_stops_and_caps_tool_timeout(tmp_path, monkeypatch):
    only(monkeypatch, "ASREP", "SIGNING-RELAY")
    now = [0.0]
    def expire(argv):
        now[0] = 10.0
        return RunResult(0)
    runner = RecordingRunner(expire)
    report = run_plan(tmp_path, runner, max_time=1, clock=lambda: now[0],
                      params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "max_time"
    assert len(runner.calls) == 1
    assert 0 < runner.timeouts[0] <= 1


def test_projection_does_not_claim_credential_or_goal_observed(tmp_path, monkeypatch):
    only(monkeypatch, "DCSYNC")
    monkeypatch.setattr(probes, "non_secret_probe", lambda ctx, finding: probes.ProbeResult(viable=True, reason="posture"))
    report = run_plan(tmp_path, goal="DA")
    assert report["goal_status"] == "projected"
    assert report["goal_reached"] is False
    assert report["projected_path"][0]["would_reach_goal"]


def test_audits_never_overwrite_prior_run(tmp_path, monkeypatch):
    only(monkeypatch, "SIGNING-RELAY")
    run_plan(tmp_path)
    first = next(tmp_path.glob("autopwn-*.jsonl"))
    contents = first.read_bytes()
    run_plan(tmp_path)
    assert len(list(tmp_path.glob("autopwn-*.jsonl"))) == 2
    assert first.read_bytes() == contents


@pytest.mark.parametrize("technique", ["SIGNING-RELAY", "SHARE-LOOT"])
def test_implicit_extra_targets_are_fenced_even_with_hosts_override(tmp_path, monkeypatch, technique):
    only(monkeypatch, technique)
    runner = RecordingRunner()
    report = autopwn.plan(config(tmp_path, extra_targets=[OUT]), scope=[DC, HOST], runner=runner,
                          params={technique: {"hosts": HOST}})
    assert not runner.calls
    assert not report["projected_path"]
    assert any(e["technique"] == technique and e["outcome"] == "skipped_out_of_scope"
               and e["target"] == OUT for e in report["events"])


def test_audit_header_written_before_first_posture_launch(tmp_path, monkeypatch):
    only(monkeypatch, "ASREP")
    observations = []
    def inspect(argv):
        observations.append([json.loads(line) for line in audit_text(tmp_path).splitlines()])
        return RunResult(0)
    runner = RecordingRunner(inspect)
    run_plan(tmp_path, runner, params={"ASREP": {"principal": "svc"}})
    assert runner.calls
    assert all(rows[0]["header"]["fence"]["hosts"] == [DC, HOST] for rows in observations)


def test_existing_kill_file_prevents_enumeration(tmp_path):
    sentinel = tmp_path / "STOP"
    sentinel.touch()
    runner = RecordingRunner()
    report = autopwn.plan(config(tmp_path), scope_enumerate=["lab.example"],
                          kill_file=sentinel, runner=runner)
    assert report["status"] == "kill_file"
    assert not runner.calls


def test_empty_scope_cli_has_clear_halt_message(tmp_path, capsys):
    status = cli.main(["autopwn", "--domain", "lab.example", "--dc-ip", DC,
                       "--target", DC, "--output", str(tmp_path)])
    captured = capsys.readouterr()
    assert status == 2
    assert json.loads(captured.out)["status"] == "empty_scope"
    assert "empty in-scope set; planning halted" in captured.err


def test_probe_exception_text_is_discarded_without_generic_error_log(tmp_path, monkeypatch, caplog):
    only(monkeypatch, "ASREP")
    class BrokenProbe:
        def check(self, ctx, finding):
            assert not ctx._private_errors
            raise RuntimeError(SECRET)
    monkeypatch.setitem(probes.POSTURE_PROBES, "ASREP", BrokenProbe)
    report = run_plan(tmp_path, params={"ASREP": {"principal": "svc"}})
    assert not report["projected_path"]
    assert SECRET not in json.dumps(report) + audit_text(tmp_path) + caplog.text
