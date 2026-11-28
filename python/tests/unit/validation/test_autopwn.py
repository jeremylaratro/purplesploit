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


# ============================================================ Phase 4b gate (CLI)
@pytest.mark.parametrize("combo", [
    [],                                              # no gate flags
    ["--scope", HOST],                               # fence only
    ["--yes"],                                        # --yes only
    ["--allow-destructive"],                          # --allow-destructive only
    ["--yes", "--allow-destructive"],                 # both flags, NO fence
    ["--yes", "--scope", HOST],                       # missing --allow-destructive
    ["--allow-destructive", "--scope", HOST],         # missing --yes
    ["--dangerous", "--yes", "--scope", HOST],        # --dangerous never substitutes a flag
])
def test_execute_gate_blocks_when_any_flag_missing(combo, monkeypatch, capsys):
    # The gate rejects BEFORE build_config (no secret-file read) and never reaches execute().
    monkeypatch.setattr(cli, "build_config", forbid)
    monkeypatch.setattr(autopwn, "execute", forbid)
    with pytest.raises(SystemExit) as exc:
        cli.main(["autopwn", "--domain", "lab.example", "--dc-ip", DC, "--execute", *combo])
    assert exc.value.code == 2
    assert "autopwn --execute requires" in capsys.readouterr().err


def test_execute_all_gate_flags_present_dispatches(monkeypatch, tmp_path, capsys):
    recorded = {}
    def fake_execute(cfg, **kwargs):
        recorded.update(kwargs)
        recorded["cfg"] = cfg
        return {"status": "empty_frontier", "header": {"mode": "execute"}, "events": [],
                "executed_path": [], "goal_status": "not_established", "goal_reached": False}
    monkeypatch.setattr(autopwn, "execute", fake_execute)
    status = cli.main(["autopwn", "--domain", "lab.example", "--dc-ip", DC, "--user", "operator",
                       "--password", SECRET, "--output", str(tmp_path), "--execute", "--yes",
                       "--allow-destructive", "--dangerous", "--scope", DC])
    assert status == 0
    assert recorded["dangerous"] is True and recorded["scope"] == [DC]
    assert recorded["cfg"].allow_destructive is True
    out = capsys.readouterr().out
    assert json.loads(out)["header"]["mode"] == "execute"
    assert SECRET not in out


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


# ========================================================= Phase 4b execute loop
# Each gate is driven by a fake runner recording calls; NO network is touched.
# The real executors (ASREP/DCSYNC/RBCD) run against the fake runner so the
# verified-rollback, fence, kill-switch and secret-safety gates are RED-provable.
EXEC_SECRET = "NEVER-leak-start-pw-7f31a"
CRACKED = "NEVER-leak-cracked-pw-c0ffee"


class ExecRunner:
    """A call-recording runner accepting the full executor signature (env/cwd)."""
    def __init__(self, hook=None):
        self.calls = []
        self.hook = hook

    def run(self, argv, *, env=None, timeout=None, cwd=None):
        self.calls.append(list(argv))
        return self.hook(argv) if self.hook else RunResult(0, stdout="")


class Verdict:
    """A discovery verdict stub (duck-typed like TechniqueVerdict for the loop)."""
    def __init__(self, technique, host, eligible=True):
        self.technique = technique
        self.host = host
        self.eligible_for_autoexploit = eligible


def exec_cfg(tmp_path, **kwargs):
    opts = dict(domain="lab.example", dc_ip=DC, username="operator", password=EXEC_SECRET,
                output_dir=tmp_path, extra_targets=[HOST], allow_destructive=True,
                authorized=True, tool_timeout_s=30)
    opts.update(kwargs)
    return ValidationConfig(**opts)


def run_exec(tmp_path, discover, runner=None, **kwargs):
    kwargs.setdefault("dangerous", True)
    kwargs.setdefault("warn_fn", lambda s: None)
    return autopwn.execute(exec_cfg(tmp_path, **kwargs.pop("cfg_kwargs", {})),
                           scope=[f"{DC},{HOST}"], runner=runner or ExecRunner(),
                           discover=discover, **kwargs)


def _asrep_hook(argv):
    """Drive the real ASREP recipe: roast -> crack -> show -> reauth; svc cred."""
    tool = argv[0]
    if tool == "impacket-GetNPUsers":
        return RunResult(0, stdout="$krb5asrep$23$svc@LAB:aaaa$bbbb")
    if tool == "hashcat" and "--show" in argv:
        return RunResult(0, stdout=CRACKED)
    if tool == "hashcat":
        return RunResult(0, stdout="")
    if tool == "nxc" and len(argv) > 1 and argv[1] == "smb":
        return RunResult(0, stdout="SMB [+] lab\\svc (Pwn3d!)")
    if tool == "impacket-secretsdump":
        return RunResult(0, stdout="krbtgt:502:aad3b435b51404eeaad3b435b51404ee:"
                                   "0123456789abcdef0123456789abcdef:::")
    return RunResult(0, stdout="")


def _rbcd_hook(verify):
    """Drive the real RBCD recipe; ``verify`` controls whether the rollback's
    read-back confirms (verified) or returns nothing (dirty)."""
    def hook(argv):
        tool = argv[0]
        if tool == "impacket-addcomputer":
            return RunResult(0, stdout="Successfully deleted computer account"
                             if "-delete" in argv else "Successfully added computer account")
        if tool == "impacket-rbcd":
            action = argv[argv.index("-action") + 1]
            if action == "write":
                return RunResult(0, stdout="Delegation rights modified successfully")
            if action == "flush":
                return RunResult(0, stdout="Delegation rights flushed")
            return RunResult(0, stdout="Accounts allowed to act on behalf" if verify else "")
        if tool == "impacket-getST":
            return RunResult(0, stdout="Saving ticket in Administrator.ccache")
        return RunResult(0, stdout="SMB [+] auth success")
    return hook


# ------------------------------------------------------------ acceptance / warning
def test_execute_requires_typed_acceptance_without_dangerous(tmp_path):
    runner = ExecRunner()
    report = autopwn.execute(exec_cfg(tmp_path), scope=[f"{DC},{HOST}"], runner=runner,
                             discover=lambda ctx, hosts: [Verdict("ASREP", HOST)],
                             params={"ASREP": {"principal": "svc"}}, dangerous=False,
                             warn_fn=lambda s: None, prompt_fn=lambda prompt: "nope")
    assert report["status"] == "acceptance_declined"
    assert report["header"]["accept_mode"] is None
    assert not runner.calls                      # nothing dispatched after a decline
    assert not report["executed_path"]


def test_typed_acceptance_proceeds_and_records_mode(tmp_path):
    report = autopwn.execute(exec_cfg(tmp_path), scope=[f"{DC},{HOST}"], runner=ExecRunner(),
                             discover=lambda ctx, hosts: [], dangerous=False,
                             warn_fn=lambda s: None, prompt_fn=lambda prompt: autopwn.ACCEPT_PHRASE)
    assert report["status"] == "empty_frontier"
    assert report["header"]["accept_mode"] == "interactive"
    assert "ONLY boundary" in report["header"]["warning"]
    assert DC in report["header"]["warning"]      # the warning names the fence


def test_dangerous_records_header_and_bypasses_prompt(tmp_path):
    # prompt_fn would raise if consulted -- --dangerous must not consult it.
    report = autopwn.execute(exec_cfg(tmp_path), scope=[f"{DC},{HOST}"], runner=ExecRunner(),
                             discover=lambda ctx, hosts: [], dangerous=True,
                             warn_fn=lambda s: None, prompt_fn=forbid)
    assert report["header"]["accept_mode"] == "dangerous"
    assert report["header"]["mode"] == "execute"


# ------------------------------------------------------------ verified-rollback gate
def test_dirty_rollback_halts_the_loop(tmp_path):
    runner = ExecRunner(_rbcd_hook(verify=False))
    report = run_exec(tmp_path, lambda ctx, hosts: [Verdict("RBCD", HOST)], runner,
                      params={"RBCD": {"new_computer": "testpc", "delegate_to": HOST}})
    assert report["status"] == "rollback_halt"
    assert report["executed_path"][0]["rollback"] == "dirty"
    assert any(e["outcome"] == "rollback_dirty_halt" for e in report["events"])
    assert report["status"] in audit_text(tmp_path)


def test_verified_rollback_advances(tmp_path):
    runner = ExecRunner(_rbcd_hook(verify=True))
    report = run_exec(tmp_path, lambda ctx, hosts: [Verdict("RBCD", HOST)], runner,
                      params={"RBCD": {"new_computer": "testpc", "delegate_to": HOST}})
    assert report["status"] == "empty_frontier"           # advanced, not halted
    assert report["executed_path"][0]["rollback"] == "verified"
    assert not any(e["outcome"] == "rollback_dirty_halt" for e in report["events"])


# ------------------------------------------------------------ full-destination fence
@pytest.mark.parametrize("technique,overrides", [
    ("ASREP", {"principal": "svc", "reauth_target": OUT}),          # reauth target
    ("NTLM-RELAY", {"relay_target": OUT, "listener_host": HOST}),    # relay target
    ("NTLM-RELAY", {"victim_dc": OUT, "listener_host": HOST}),       # coercion victim
    ("NTLM-RELAY", {"listener_host": HOST, "external_listener": OUT}),  # callback
    ("CONSTRAINED-DELEG-PT", {"target_spn": "cifs/" + OUT}),         # SPN host
])
def test_resolved_destination_fenced_mid_loop_never_dispatched(tmp_path, technique, overrides):
    runner = ExecRunner()
    report = run_exec(tmp_path, lambda ctx, hosts: [Verdict(technique, HOST)], runner,
                      params={technique: overrides})
    assert not runner.calls                      # the hop is never dispatched
    assert not report["executed_path"]
    assert any(e["outcome"] == "skipped_out_of_scope" and e["target"] == OUT
               for e in report["events"])


@pytest.mark.parametrize("field", ["dc_ip", "kdc_host", "dns_server"])
def test_out_of_fence_infrastructure_skips_identity(tmp_path, field):
    runner = ExecRunner()
    report = autopwn.execute(exec_cfg(tmp_path, **{field: OUT}), scope=[DC, HOST], runner=runner,
                             discover=lambda ctx, hosts: [Verdict("ASREP", HOST)],
                             params={"ASREP": {"principal": "svc"}}, dangerous=True,
                             warn_fn=lambda s: None)
    assert not runner.calls
    assert not report["executed_path"]
    assert any(e["outcome"] == "skipped_out_of_scope" and e["target"] == OUT
               for e in report["events"])


def test_tool_boundary_refuses_out_of_fence_host(tmp_path):
    # A hop whose executor reaches an unexpected out-of-fence host mid-run is
    # refused at the tool boundary (defense in depth) and never dispatched there.
    fence = autopwn.ScopeFence.parse([DC])
    events = []
    runner = autopwn.ExecuteRunner(ExecRunner(), fence, autopwn.Admission(),
                                   lambda outcome, **kw: events.append((outcome, kw.get("target"))),
                                   [None])
    res = runner.run(["nxc", "smb", OUT, "-u", "x"])
    assert res.error == "out_of_scope"
    assert ("skipped_out_of_scope", OUT) in events


# ------------------------------------------------------------ kill-switch + budget
def test_kill_file_stops_before_next_hop(tmp_path):
    # The first hop (operator's ASREP) completes; the kill-file is set on its last
    # tool, so the loop halts before the NEXT identity's hop is ever discovered/run.
    sentinel = tmp_path / "STOP"
    def hook(argv):
        res = _asrep_hook(argv)
        if argv[0] == "nxc" and len(argv) > 1 and argv[1] == "smb":   # ASREP's last tool
            sentinel.touch()
        return res
    def discover(ctx, hosts):
        return ([Verdict("ASREP", HOST)] if ctx.config.username == "operator"
                else [Verdict("DCSYNC", DC)])
    runner = ExecRunner(hook)
    report = run_exec(tmp_path, discover, runner, kill_file=str(sentinel),
                      params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "kill_file"
    assert not any(c[0] == "impacket-secretsdump" for c in runner.calls)  # next hop never ran
    assert report["status"] in audit_text(tmp_path)


def test_kill_file_stops_before_next_tool_launch(tmp_path):
    # The kill-file is set on the FIRST tool; the loop halts before the second
    # tool launch within the same hop (mid-hop admission).
    sentinel = tmp_path / "STOP"
    def hook(argv):
        sentinel.touch()
        return _asrep_hook(argv)
    runner = ExecRunner(hook)
    report = run_exec(tmp_path, lambda ctx, hosts: [Verdict("ASREP", HOST)], runner,
                      kill_file=str(sentinel), params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "kill_file"
    assert len(runner.calls) == 1


def test_existing_kill_file_stops_before_any_hop(tmp_path):
    sentinel = tmp_path / "STOP"
    sentinel.touch()
    runner = ExecRunner()
    report = run_exec(tmp_path, lambda ctx, hosts: [Verdict("ASREP", HOST)], runner,
                      kill_file=str(sentinel), params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "kill_file"
    assert not runner.calls


def test_sigint_mid_hop_halts_after_hardened_rollback(tmp_path):
    def hook(argv):
        if argv[0] == "impacket-rbcd" and "write" in argv:
            raise KeyboardInterrupt("sigint during the delegation write")
        if argv[0] == "impacket-addcomputer":
            return RunResult(0, stdout="Successfully deleted computer account"
                             if "-delete" in argv else "Successfully added computer account")
        if argv[0] == "impacket-rbcd" and "flush" in argv:
            return RunResult(0, stdout="Delegation rights flushed")
        return RunResult(0, stdout="")
    runner = ExecRunner(hook)
    report = run_exec(tmp_path, lambda ctx, hosts: [Verdict("RBCD", HOST)], runner,
                      params={"RBCD": {"new_computer": "testpc", "delegate_to": HOST}})
    assert report["status"] == "interrupted"
    assert any(e["outcome"] == "hop_interrupted" for e in report["events"])
    # the hardened rollback ran during the interrupt (computer deletion attempted)
    assert any("-delete" in c for c in runner.calls)


def test_max_hops_bounds_executed_hops(tmp_path):
    runner = ExecRunner(_asrep_hook)
    report = run_exec(tmp_path, lambda ctx, hosts: [Verdict("ASREP", HOST), Verdict("ASREP", DC)],
                      runner, max_hops=1, params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "max_hops"
    assert len(report["executed_path"]) == 1


def test_max_time_stops_before_next_tool_launch(tmp_path):
    now = [0.0]
    def hook(argv):
        now[0] = 10.0
        return _asrep_hook(argv)
    runner = ExecRunner(hook)
    report = run_exec(tmp_path, lambda ctx, hosts: [Verdict("ASREP", HOST)], runner,
                      max_time=1, clock=lambda: now[0], params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "max_time"
    assert len(runner.calls) == 1


def test_zero_max_hops_stops_before_acceptance(tmp_path):
    warned = []
    report = autopwn.execute(exec_cfg(tmp_path), scope=[f"{DC},{HOST}"], runner=ExecRunner(),
                             discover=lambda ctx, hosts: [], max_hops=0, dangerous=True,
                             warn_fn=lambda s: warned.append(s))
    assert report["status"] == "max_hops"
    assert not warned                            # halted before the warning was printed


# ------------------------------------------------------------ full loop + visited
def test_full_loop_gain_rescope_reach_goal_and_visited(tmp_path):
    seen = []
    def discover(ctx, hosts):
        seen.append(ctx.config.username)
        user = ctx.config.username
        if user == "operator":
            return [Verdict("ASREP", HOST)]
        if user == "svc":
            # ASREP would re-produce svc (already visited -> not re-queued); DCSYNC = goal.
            return [Verdict("ASREP", HOST), Verdict("DCSYNC", DC)]
        return []
    runner = ExecRunner(_asrep_hook)
    report = run_exec(tmp_path, discover, runner, params={"ASREP": {"principal": "svc"}})
    assert report["goal_reached"] is True
    assert report["status"] == "goal_reached"
    assert [p["technique"] for p in report["executed_path"]][-1] == "DCSYNC"
    assert report["executed_path"][-1]["reached_goal"] is True
    # visited prevents re-exploiting an identity: each discovered exactly once.
    assert seen.count("operator") == 1 and seen.count("svc") == 1


def test_unresolvable_identity_is_skipped_not_fatal(tmp_path):
    # A re-scoped identity whose discovery blows up is audited + skipped; the run
    # continues (forgiving by default) and never aborts with execution_failed.
    def discover(ctx, hosts):
        if ctx.config.username == "operator":
            return [Verdict("ASREP", HOST)]
        raise RuntimeError("private re-scope detail that must never leak")
    report = run_exec(tmp_path, discover, ExecRunner(_asrep_hook),
                      params={"ASREP": {"principal": "svc"}})
    assert report["status"] == "empty_frontier"
    assert any(e["outcome"] == "identity_skipped" for e in report["events"])
    assert "private re-scope detail" not in json.dumps(report) + audit_text(tmp_path)


# ------------------------------------------------------------ audit secret-safety
def test_execute_audit_holds_no_secret(tmp_path, capsys):
    def discover(ctx, hosts):
        return ([Verdict("ASREP", HOST)] if ctx.config.username == "operator"
                else [Verdict("DCSYNC", DC)] if ctx.config.username == "svc" else [])
    runner = ExecRunner(_asrep_hook)
    report = run_exec(tmp_path, discover, runner, params={"ASREP": {"principal": "svc"}})
    assert report["goal_reached"] is True
    blob = json.dumps(report) + audit_text(tmp_path) + capsys.readouterr().out
    assert EXEC_SECRET not in blob               # the start-identity password
    assert CRACKED not in blob                   # the produced credential value
    # the audit events carry only the public allowlist (no secret-bearing keys).
    rows = [json.loads(line) for line in audit_text(tmp_path).splitlines()]
    allowed = {"outcome", "technique", "target", "principal", "in_scope", "rollback"}
    assert all(set(row) == allowed for row in rows if "header" not in row and "status" not in row)


# ------------------------------------------------------------ dry-run unchanged
def test_dry_run_default_is_unchanged(tmp_path, monkeypatch):
    # The dry-run planner path never enters execute() and stays mode=dry_run.
    monkeypatch.setattr(autopwn, "execute", forbid)
    only(monkeypatch, "ASREP")
    report = run_plan(tmp_path, params={"ASREP": {"principal": "svc"}})
    assert report["header"]["mode"] == "dry_run"
    assert report["goal_reached"] is False
    assert "executed_path" not in report
