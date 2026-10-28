"""Capability regressions retaining real AutoEnum, Nmap and Framework execution."""

import shlex
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

from purplesploit.core.auto_enum import AutoEnumPipeline, EnumPhase, EnumScope, ServiceRule
from purplesploit.core.framework import Framework
from purplesploit.core.module import ExternalToolModule


@pytest.fixture
def framework(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    instance = Framework(db_path=str(tmp_path / "auto-enum.db"))
    instance.discover_modules()
    yield instance
    instance.cleanup()


@pytest.fixture
def nmap_process(framework, monkeypatch):
    calls = []
    nmap_class = framework.get_module("recon/nmap").instance
    monkeypatch.setattr(nmap_class, "check_tool_installed", lambda self: True)

    def run(argv, **kwargs):
        calls.append(argv)
        xml = Path(argv[argv.index("-oA") + 1] + ".xml")
        xml.write_text("""<nmaprun>
          <host><status state="up"/><address addr="192.0.2.21" addrtype="ipv4"/>
          <ports><port protocol="udp" portid="53"><state state="open"/>
          <service name="domain" product="BIND"/></port></ports></host>
          <host><status state="up"/><address addr="192.0.2.22" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="8443"><state state="open"/>
          <service name="http" tunnel="ssl" product="nginx"/></port></ports></host>
          </nmaprun>""")
        return subprocess.CompletedProcess(
            argv, 0, stdout="53/udp open domain BIND\n8443/tcp open ssl/http nginx", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", run)
    return calls


@pytest.mark.parametrize("operation,flag", [("Fast Scan", "-sV"), ("UDP Scan", "-sU")])
def test_real_nmap_operation_argv_is_targeted(framework, nmap_process, operation, flag):
    result = AutoEnumPipeline(framework)._run_module("192.0.2.0/24", "recon/nmap", operation)
    assert result.success
    argv = nmap_process[0]
    assert argv[argv.index("--top-ports") + 1] == "100"
    assert "-p" not in argv and flag in argv
    assert argv[-1] == "192.0.2.0/24"
    assert framework.session.current_module is None


@pytest.mark.parametrize("target", ["192.0.2.0/24", "192.0.2.20-25"])
def test_range_discovery_uses_xml_hosts(framework, nmap_process, target):
    pipeline = AutoEnumPipeline(framework, EnumScope.LIGHT)
    pipeline._run_discovery_phase([target])
    assert pipeline.discovered_services == {"192.0.2.21": {"dns"}, "192.0.2.22": {"https"}}
    assert pipeline.discovered_endpoints["192.0.2.21"][0]["protocol"] == "udp"
    assert pipeline.discovered_endpoints["192.0.2.22"][0]["port"] == 8443


def test_range_stdout_without_xml_never_creates_endpoint(framework):
    pipeline = AutoEnumPipeline(framework)
    assert (
        pipeline._extract_discovered_services(
            {"parsed": {"services": {"445/tcp": {"service": "microsoft-ds"}}}}, "192.0.2.0/24"
        )
        == []
    )


def test_missing_range_xml_is_a_reported_failure(framework, monkeypatch):
    nmap_class = framework.get_module("recon/nmap").instance
    monkeypatch.setattr(nmap_class, "check_tool_installed", lambda self: True)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, stdout="445/tcp open microsoft-ds", stderr=""
        ),
    )
    pipeline = AutoEnumPipeline(framework)
    pipeline._run_discovery_phase(["192.0.2.0/24"])
    assert pipeline.discovered_endpoints == {}
    summary = pipeline._build_summary(datetime.now())
    assert summary["success"] is False
    assert "per-host XML" in summary["results"][0]["error"]


def test_external_seeds_skip_discovery_and_preserve_metadata(framework, monkeypatch):
    pipeline = AutoEnumPipeline(framework)
    seed = {
        "target": "192.0.2.22",
        "service": "https",
        "port": 8443,
        "protocol": "tcp",
        "source_tool": "aranum",
        "source_schema": "observation/v1",
        "source_id": "obs-7",
        "run_id": "run-3",
        "raw": {"tunnel": "ssl"},
        "attributes": {"domain": "example.test"},
        "version": "nginx",
    }
    nmap_class = framework.get_module("recon/nmap").instance
    monkeypatch.setattr(nmap_class, "run", lambda self: pytest.fail("Nmap ran"))
    summary = pipeline.run(["192.0.2.0/24"], phases=[EnumPhase.DISCOVERY], seeds=[seed])
    endpoint = summary["service_endpoints"][0]
    for key, value in seed.items():
        assert endpoint[key] == value
    assert summary["modules_executed"] == 0


@pytest.mark.parametrize("source", ["session", "database"])
def test_context_seeds_skip_discovery(framework, monkeypatch, source):
    if source == "session":
        framework.session.services.add_service("192.0.2.22", "https", 8443)
    else:
        framework.database.add_service("192.0.2.22", "https", 8443, "nginx")
    pipeline = AutoEnumPipeline(framework)
    pipeline.service_rules = []
    nmap_class = framework.get_module("recon/nmap").instance
    monkeypatch.setattr(nmap_class, "run", lambda self: pytest.fail("Nmap ran"))
    summary = pipeline.run(["192.0.2.0/24"])
    assert summary["service_endpoints"][0]["source"] == source


def test_domain_and_controller_bindings(framework):
    pipeline = AutoEnumPipeline(framework)
    for path, controller in [("recon/dns", "NAMESERVER"), ("ad/kerbrute", "DC")]:
        module = framework.get_module(path).instance(framework)
        pipeline._set_module_target(module, "192.0.2.21", endpoint={"domain": "example.test"})
        assert module.get_option("DOMAIN") == "example.test"
        assert module.get_option(controller) == "192.0.2.21"


def test_domain_rule_skips_without_domain(framework):
    pipeline = AutoEnumPipeline(framework)
    assert pipeline._run_module("192.0.2.21", "recon/dns", "Zone Transfer (AXFR)") is None
    summary = pipeline._build_summary(datetime.now())
    assert summary["skipped_rules"][0]["module"] == "recon/dns"
    assert "domain" in summary["skipped_rules"][0]["reason"].lower()
    assert summary["status"] == "skipped"
    assert summary["success"] is False


def test_hostname_is_not_guessed_to_be_a_domain(framework):
    pipeline = AutoEnumPipeline(framework)
    assert pipeline._run_module("dc.example.test", "ad/kerbrute", "User Enumeration") is None
    assert "Domain required" in pipeline.skipped_rules[0]["reason"]


@pytest.mark.parametrize(
    "target,port,service,expected",
    [
        ("192.0.2.22", 8443, "https", "https://192.0.2.22:8443"),
        ("192.0.2.22", 8080, "http", "http://192.0.2.22:8080"),
        ("https://example.test:9443/path", 9443, "https", "https://example.test:9443/path"),
    ],
)
def test_target_retains_url_scheme_and_port(framework, target, port, service, expected):
    module = framework.get_module("web/httpx").instance(framework)
    AutoEnumPipeline(framework)._set_module_target(module, target, port, service)
    assert module.get_option("TARGET") == expected
    assert expected in shlex.split(module.build_command())


def test_default_https_rules_reach_web_discovery_tools():
    rules = [rule for rule in AutoEnumPipeline.DEFAULT_SERVICE_RULES if rule.service == "https"]
    assert {module for rule in rules for module in rule.modules} >= {
        "web/httpx",
        "web/feroxbuster",
        "recon/nuclei",
    }


def test_external_tools_receive_timeout_and_isolated_run_directory(
    framework, monkeypatch, tmp_path
):
    captured = {}
    nmap_class = framework.get_module("recon/nmap").instance
    monkeypatch.setattr(nmap_class, "check_tool_installed", lambda self: True)

    def run(argv, **kwargs):
        captured.update(argv=argv, kwargs=kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="80/tcp open http", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    base = tmp_path / "artifacts"
    result = AutoEnumPipeline(framework, run_dir=base, timeout_s=17)._run_module(
        "192.0.2.10", "recon/nmap", "Fast Scan"
    )
    assert result.success
    assert captured["kwargs"]["timeout"] == 17
    run_dir = Path(captured["kwargs"]["cwd"])
    assert run_dir.parent == base and run_dir.is_dir()
    output_base = Path(captured["argv"][captured["argv"].index("-oA") + 1])
    assert output_base.parent == run_dir


def test_auth_rule_injects_session_credentials(framework, monkeypatch):
    # Exercise the legacy fallback explicitly; Aranum owns SMB when registered.
    framework.modules.pop("recon/aranum", None)
    captured = []
    framework.session.credentials.add(
        {"username": "alice", "password": "test-pass", "domain": "example.test"}
    )
    module_class = framework.get_module("network/nxc_smb").instance

    def handler(module):
        captured.append(
            {key: module.get_option(key) for key in ("USERNAME", "PASSWORD", "DOMAIN", "RHOST")}
        )
        return {"success": True}

    monkeypatch.setattr(module_class, "op_test_auth", handler)
    pipeline = AutoEnumPipeline(framework)
    pipeline.service_rules = [
        ServiceRule(
            service="smb",
            modules=["network/nxc_smb"],
            requires_auth=True,
            operations={"network/nxc_smb": "Test Authentication"},
        )
    ]
    pipeline.ingest_seeds([{"target": "192.0.2.30", "service": "smb", "port": 445}])
    pipeline._run_enumeration_phase("192.0.2.30")
    assert captured == [
        {
            "USERNAME": "alice",
            "PASSWORD": "test-pass",
            "DOMAIN": "example.test",
            "RHOST": "192.0.2.30",
        }
    ]


def test_auth_rules_exclude_offline_and_explicitly_unauthenticated_credentials(framework):
    pipeline = AutoEnumPipeline(framework)
    pipeline.discovered_credentials.extend(
        [
            {
                "username": "roasted",
                "hash": "$krb5asrep$23$alice@example.test:deadbeef",
                "credential_type": "offline_hash",
                "authenticated": False,
            },
            {
                "username": "rejected",
                "password": "wrong-password",
                "authenticated": False,
            },
            {
                "username": "validated-password",
                "password": "test-pass",
                "authenticated": True,
            },
            {
                "username": "validated-hash",
                "hash": "0123456789abcdef0123456789abcdef",
                "authenticated": True,
            },
        ]
    )

    assert [credential["username"] for credential in pipeline._available_credentials()] == [
        "validated-password",
        "validated-hash",
    ]


def test_missing_credentials_are_skipped(framework):
    # Exercise the legacy fallback explicitly; Aranum owns SSH when registered.
    framework.modules.pop("recon/aranum", None)
    pipeline = AutoEnumPipeline(framework)
    pipeline.service_rules = [
        ServiceRule(service="ssh", modules=["network/nxc_ssh"], requires_auth=True)
    ]
    pipeline.ingest_seeds([{"target": "192.0.2.30", "service": "ssh", "port": 22}])
    pipeline._run_enumeration_phase("192.0.2.30")
    assert pipeline.results == []
    assert "credentials" in pipeline.skipped_rules[0]["reason"]


def test_explicit_empty_password_is_not_replaced_by_current_credential(framework, monkeypatch):
    framework.session.credentials.add({"username": "interactive", "password": "different-pass"})
    captured = []
    module_class = framework.get_module("network/nxc_smb").instance

    def handler(module):
        captured.append((module.get_option("USERNAME"), module.get_option("PASSWORD")))
        return {"success": True}

    monkeypatch.setattr(module_class, "op_test_auth", handler)
    result = AutoEnumPipeline(framework)._run_module(
        "192.0.2.30",
        "network/nxc_smb",
        "Test Authentication",
        credential={"username": "selected", "password": ""},
    )
    assert result.success
    assert captured == [("selected", "")]


def test_parallel_execution_preserves_current_module(framework, monkeypatch):
    current = framework.use_module("recon/nmap")
    monkeypatch.setattr(ExternalToolModule, "check_tool_installed", lambda self: True)
    monkeypatch.setattr(
        ExternalToolModule,
        "execute_command",
        lambda self, *args, **kwargs: {"success": True, "stdout": ""},
    )
    pipeline = AutoEnumPipeline(framework)
    pipeline.service_rules = [ServiceRule(service="https", modules=["web/httpx"])]
    pipeline.run(
        ["192.0.2.0/24"],
        phases=[EnumPhase.ENUMERATION],
        parallel=True,
        seeds=[
            {"target": host, "service": "https", "port": 8443}
            for host in ("192.0.2.21", "192.0.2.22")
        ],
    )
    assert len(pipeline.results) == 2
    assert framework.session.current_module is current


def test_partial_summary_records_missing_module_failure(framework, monkeypatch):
    monkeypatch.setattr(ExternalToolModule, "check_tool_installed", lambda self: True)
    monkeypatch.setattr(
        ExternalToolModule,
        "execute_command",
        lambda self, *args, **kwargs: {"success": True, "stdout": ""},
    )
    pipeline = AutoEnumPipeline(framework)
    pipeline._run_module("192.0.2.22", "web/httpx", port=8443, service="https")
    pipeline._run_module("192.0.2.22", "missing/module")
    summary = pipeline._build_summary(datetime.now())
    assert summary["success"] is False and summary["status"] == "partial"
    assert summary["failed_executions"] == 1
    assert "Module not found" in summary["results"][1]["error"]


def test_exploitation_uses_concrete_seed_hosts(framework, monkeypatch):
    pipeline = AutoEnumPipeline(framework)
    framework.session.credentials.add({"username": "alice", "password": "test-pass"})
    candidates = []
    monkeypatch.setattr(
        pipeline, "_run_exploitation_phase", lambda targets: candidates.extend(targets)
    )
    pipeline.run(
        ["192.0.2.0/24"],
        phases=[EnumPhase.EXPLOITATION],
        seeds=[{"target": "192.0.2.21", "service": "smb", "port": 445}],
    )
    assert candidates == ["192.0.2.21"]


def test_seeded_runs_do_not_enumerate_hosts_from_previous_runs(framework, monkeypatch):
    pipeline = AutoEnumPipeline(framework)
    pipeline.ingest_seeds([{"target": "198.51.100.1", "service": "smb", "port": 445}])
    candidates = []
    monkeypatch.setattr(
        pipeline, "_run_enumeration_phase", lambda target: candidates.append(target)
    )
    pipeline.run(
        ["192.0.2.0/24"],
        phases=[EnumPhase.ENUMERATION],
        seeds=[{"target": "192.0.2.21", "service": "smb", "port": 445}],
    )
    assert candidates == ["192.0.2.21"]
