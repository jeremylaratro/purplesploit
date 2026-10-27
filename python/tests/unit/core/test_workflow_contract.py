"""Workflow contracts exercised through real templates and execution adapters."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from purplesploit.core.framework import Framework
from purplesploit.core.module import ExternalToolModule, ModuleMetadata
from purplesploit.core.workflow import StepStatus, WorkflowEngine, WorkflowStatus
from purplesploit.modules.ad.kerbrute import KerbruteModule
from purplesploit.modules.impacket.asreproast import ImpacketASREPRoastModule
from purplesploit.modules.impacket.kerberoast import ImpacketKerberoastModule
from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
from purplesploit.modules.network.nxc_ldap import NXCLDAPModule
from purplesploit.modules.network.nxc_smb import NXCSMBModule
from purplesploit.modules.recon.nmap_comprehensive import NmapComprehensiveModule
from purplesploit.modules.recon.nmap_fast import NmapFastModule
from purplesploit.modules.recon.nuclei import NucleiModule
from purplesploit.modules.smb.enumeration import SMBEnumerationModule
from purplesploit.modules.web.httpx import HTTPxModule


class BoundaryModule(ExternalToolModule):
    name = "Boundary"
    description = "Workflow process boundary"
    author = "Tests"
    category = "test"
    tool_name = "workflow-boundary"

    def build_command(self):
        return ["workflow-boundary"]


@pytest.fixture
def engine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    framework = Framework(db_path=":memory:")
    classes = {
        "test/boundary": BoundaryModule,
        "recon/nmap_fast": NmapFastModule,
        "recon/nmap_comprehensive": NmapComprehensiveModule,
        "web/httpx": HTTPxModule,
        "recon/nuclei": NucleiModule,
        "smb/enumeration": SMBEnumerationModule,
        "network/nxc_smb": NXCSMBModule,
        "network/nxc_ldap": NXCLDAPModule,
        "ad/kerbrute": KerbruteModule,
        "impacket/asreproast": ImpacketASREPRoastModule,
        "impacket/kerberoast": ImpacketKerberoastModule,
        "impacket/secretsdump": ImpacketSecretsDumpModule,
    }
    for path, cls in classes.items():
        framework.modules[path] = ModuleMetadata(path, cls.__name__, "test", "Test", "Tests", cls)
    monkeypatch.setattr(ExternalToolModule, "check_tool_installed", lambda self: True)
    yield WorkflowEngine(framework, storage_path=tmp_path / "workflows")
    framework.database.close()


@pytest.mark.parametrize("template", ["quick_recon", "full_network_assessment"])
def test_real_templates_wait_for_scan_and_never_prompt(engine, monkeypatch, template):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert kwargs["timeout"] == 600
        assert kwargs["stdin"] is subprocess.DEVNULL
        stdout = "80/tcp open http\n445/tcp open microsoft-ds\n" if argv[0] == "nmap" else ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("background launch"))
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("interactive prompt"))
    workflow = engine.create_workflow("", from_template=template)
    result = engine.run_workflow(workflow.id, {"target": "192.0.2.10"})
    assert result["success"], result
    assert all(step.status != StepStatus.PENDING for step in workflow.steps)
    if template == "quick_recon":
        assert [argv[0] for argv in calls] == ["nmap", "httpx", "nuclei"]
    else:
        assert [argv[0] for argv in calls] == ["nmap", "nmap", "nxc", "nxc"]
        assert "spider_plus" in calls[-1]
        assert "DOWNLOAD_FLAG=False" in calls[-1]
        assert workflow.steps[-1].status == StepStatus.SKIPPED


@pytest.mark.parametrize("template", ["ad_assessment", "credential_harvest"])
def test_authenticated_templates_bind_scoped_credentials_and_users(
    engine, monkeypatch, template
):
    calls = []
    ldap_fixture = (
        "LDAP 192.0.2.10 389 DC01 [+] CORP\\alice:Fixture1!\n"
        "LDAP 192.0.2.10 389 DC01 Enumerated users\n"
        "LDAP 192.0.2.10 389 DC01 Username: alice\n"
    )

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "nxc" and "ldap" in argv:
            stdout = ldap_fixture
        elif argv[0] == "kerbrute":
            stdout = "[+] VALID USERNAME: alice@CORP.LOCAL\n"
        elif argv[0] == "impacket-GetNPUsers":
            stdout = "$krb5asrep$23$alice@CORP.LOCAL:fixture\n"
        elif argv[0] == "impacket-GetUserSPNs":
            stdout = "$krb5tgs$23$*svc@CORP.LOCAL$fixture\n"
        else:
            stdout = ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("interactive prompt"))
    workflow = engine.create_workflow("", from_template=template)
    result = engine.run_workflow(
        workflow.id,
        {
            "target": "192.0.2.10",
            "services": [
                {"target": "192.0.2.10", "service": "smb", "port": 445}
            ],
            "credentials": [
                {
                    "target": "192.0.2.10",
                    "username": "alice",
                    "password": "Fixture1!",
                    "domain": "CORP.LOCAL",
                    "is_admin": True,
                }
            ],
        },
    )
    assert result["success"], result
    assert all(step.status == StepStatus.SUCCESS for step in workflow.steps)
    assert any(argv[0] == "impacket-GetNPUsers" for argv in calls)
    kerberos = next(argv for argv in calls if argv[0] == "impacket-GetUserSPNs")
    assert any("CORP.LOCAL/alice:Fixture1!" in value for value in kerberos)
    user_files = [
        value
        for argv in calls
        for value in argv
        if isinstance(value, str) and value.endswith("users.txt")
    ]
    if template == "ad_assessment":
        assert user_files and all(
            "alice" in open(path, encoding="utf-8").read()
            for path in user_files
        )


def test_validation_does_not_activate_module_or_change_session(engine):
    selected = engine.framework.use_module("test/boundary")
    workflow = engine.create_workflow("", from_template="quick_recon")
    result = engine.run_workflow(workflow.id, {"target": "192.0.2.10"}, dry_run=True)
    assert result["success"]
    assert engine.framework.session.current_module is selected
    workflow.steps[0].operation = "Fast Scan"
    assert engine._validate_workflow(workflow)["valid"]
    assert engine.framework.session.current_module is selected


def test_services_and_credential_conditions_are_target_scoped(engine):
    workflow = engine.create_workflow("Scoped")
    workflow.variables.update(target="192.0.2.10", services=[{"target": "198.51.100.10", "service": "http"}],
                              credentials=[{"target": "198.51.100.10", "is_admin": True}])
    engine.framework.database.add_service("198.51.100.10", 80, "http")
    step = workflow.add_step("Conditional", "test/boundary", conditions=[{"type": "service_found", "service": "http"}])
    assert not engine._check_conditions(step, workflow)
    step.conditions = [{"type": "has_admin_creds"}]
    assert not engine._check_conditions(step, workflow)
    workflow.variables["target"] = "198.51.100.0/24"
    assert engine._check_conditions(step, workflow)
    assert engine._service_exists("http", workflow)


@pytest.mark.parametrize("succeeds", [True, False])
def test_retries_and_branch_destinations(engine, monkeypatch, succeeds):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        # The first step retries once. Branch handlers then complete normally.
        return SimpleNamespace(returncode=0 if len(calls) > 2 or succeeds and len(calls) == 2 else 1,
                               stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    workflow = engine.create_workflow("Branch")
    first = workflow.add_step("First", "test/boundary", retry_count=1, on_success=["step_2"], on_failure=["step_3"])
    success = workflow.add_step("Success branch", "test/boundary")
    failure = workflow.add_step("Failure branch", "test/boundary")
    result = engine.run_workflow(workflow.id)
    assert first.attempts == 2
    assert len(calls) == 3
    assert success.status == (StepStatus.SUCCESS if succeeds else StepStatus.SKIPPED)
    assert failure.status == (StepStatus.SKIPPED if succeeds else StepStatus.SUCCESS)
    assert result["success"] is succeeds


def test_process_timeout_is_passed_and_retry_is_recorded(engine, monkeypatch):
    timeouts = []

    def run(argv, **kwargs):
        timeouts.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", run)
    workflow = engine.create_workflow("Timeout")
    step = workflow.add_step("Deadline", "test/boundary", timeout=3, retry_count=1)
    result = engine.run_workflow(workflow.id)
    assert not result["success"]
    assert timeouts == [3, 3]
    assert step.attempts == 2
    assert step.result["timed_out"]


def test_save_list_load_and_resume_checkpoint(engine, monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: (calls.append(argv) or SimpleNamespace(returncode=0, stdout="", stderr="")))
    workflow = engine.create_workflow("Durable")
    workflow.add_step("First", "test/boundary")
    workflow.add_step("Second", "test/boundary")
    assert engine.save_workflow(workflow.id)
    engine.on_step_complete = lambda workflow, step, result: engine.pause_workflow(workflow.id)
    assert engine.run_workflow(workflow.id)["status"] == "paused"
    fresh = WorkflowEngine(engine.framework, engine.storage_path)
    assert fresh.list_workflows()[0].id == workflow.id
    loaded = fresh.get_workflow(workflow.id)
    assert loaded.steps[0].status == StepStatus.SUCCESS
    assert fresh.resume_workflow(workflow.id)["success"]
    assert len(calls) == 2


def test_crash_recovery_does_not_replay_unknown_external_work(engine, monkeypatch):
    workflow = engine.create_workflow("Interrupted")
    first = workflow.add_step("Uncertain", "test/boundary")
    first.status = StepStatus.RUNNING
    first.attempts = 1
    workflow.add_step("Pending", "test/boundary")
    workflow.status = WorkflowStatus.RUNNING
    engine.save_workflow(workflow.id)
    fresh = WorkflowEngine(engine.framework, engine.storage_path)
    loaded = fresh.get_workflow(workflow.id)
    assert loaded.status == WorkflowStatus.PAUSED
    assert loaded.steps[0].status == StepStatus.FAILED
    assert "unknown" in loaded.steps[0].error
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    result = fresh.resume_workflow(workflow.id)
    assert not result["success"]
    assert loaded.steps[0].attempts == 1
    assert json.loads((engine.storage_path / f"{workflow.id}.json").read_text())["status"] == "failed"


def test_background_option_rejected(engine, monkeypatch):
    workflow = engine.create_workflow("Background")
    step = workflow.add_step("Background", "recon/nmap_fast", options={"BACKGROUND": True})
    assert not engine._validate_workflow(workflow)["valid"]
    step.options = {"BACKGROUND": False}
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    # The real template's explicit synchronous request is covered above.
    assert engine.run_workflow(workflow.id, {"target": "192.0.2.10"})["success"]


def test_live_checkpoint_is_not_misidentified_as_a_crash(engine, monkeypatch):
    workflow = engine.create_workflow("Live checkpoint")
    workflow.add_step("Running", "test/boundary")

    def run(argv, **kwargs):
        fresh = WorkflowEngine(engine.framework, engine.storage_path)
        loaded = fresh.get_workflow(workflow.id)
        assert loaded.status == WorkflowStatus.RUNNING
        assert loaded.steps[0].status == StepStatus.RUNNING
        assert "already running" in fresh.run_workflow(workflow.id)["error"]
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    assert engine.run_workflow(workflow.id)["success"]


def test_unexpected_background_result_is_never_scan_success(engine, monkeypatch):
    monkeypatch.setattr(BoundaryModule, "run", lambda self: {"success": True, "background": True, "pid": 12345})
    workflow = engine.create_workflow("Unexpected background")
    step = workflow.add_step("Unexpected job", "test/boundary", retry_count=2)
    workflow.add_step("Dependent", "test/boundary")
    result = engine.run_workflow(workflow.id)
    assert result["status"] == "paused"
    assert not result["success"]
    assert result["steps_completed"] == 0
    assert step.status == StepStatus.RUNNING
    assert step.attempts == 1
    assert "unresolved" in engine.resume_workflow(workflow.id)["error"]


def test_template_definitions_are_independent(engine):
    first = engine.create_workflow("", from_template="quick_recon")
    first.steps[0].options["BACKGROUND"] = True
    second = engine.create_workflow("", from_template="quick_recon")
    assert second.steps[0].options["BACKGROUND"] == "false"


def test_configured_spider_quotes_optional_share_and_pattern(engine, monkeypatch):
    commands = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kwargs: (commands.append(argv) or SimpleNamespace(returncode=0, stdout="", stderr="")))
    workflow = engine.create_workflow("Spider")
    workflow.add_step("Spider", "network/nxc_smb", operation="Spider Configured (No Download)",
                      options={"SPIDER_SHARE": "Share with spaces", "SPIDER_PATTERN": "*.xlsx"})
    assert engine.run_workflow(workflow.id, {"target": "192.0.2.10"})["success"]
    assert "SHARE=Share with spaces" in commands[0]
    assert "PATTERN=*.xlsx" in commands[0]
