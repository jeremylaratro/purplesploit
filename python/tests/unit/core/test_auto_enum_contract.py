"""Contract regressions for auto-enumeration against the real Framework API."""

from unittest.mock import Mock

import pytest

from purplesploit.core.auto_enum import (
    AutoEnumPipeline,
    EnumPhase,
    EnumScope,
    ServiceRule,
)
from purplesploit.core.framework import Framework
from purplesploit.core.module import BaseModule


@pytest.fixture
def real_framework(tmp_path, monkeypatch):
    """Discover real modules while replacing only the process execution boundary."""
    monkeypatch.chdir(tmp_path)
    framework = Framework(db_path=str(tmp_path / "auto-enum-contract.db"))
    framework.discover_modules()
    yield framework
    framework.cleanup()


def test_real_framework_executes_registered_nmap_operation_synchronously(
    real_framework, monkeypatch
):
    captured = {}

    def fake_run_operation(module, operation):
        captured["module"] = module
        captured["operation"] = operation
        captured["background"] = module.get_option("BACKGROUND")
        # The real Nmap module also imports parsed XML into the legacy session
        # index, which has no protocol field. The richer parsed endpoint wins.
        module.framework.session.services.add_service("192.0.2.10", "smb", 445)
        return {
            "success": True,
            "parsed": {
                "services": {
                    "445/tcp": {
                        "service": "microsoft-ds",
                        "version": "Windows SMB",
                    }
                }
            },
        }

    monkeypatch.setattr(real_framework, "run_operation", fake_run_operation)
    pipeline = AutoEnumPipeline(real_framework, scope=EnumScope.LIGHT)

    result = pipeline._run_module(
        target="192.0.2.10",
        module_path="recon/nmap",
        operation=pipeline._get_nmap_operation(),
    )
    assert isinstance(captured["module"], BaseModule)
    assert captured["operation"]["name"] == "Fast Scan"
    assert captured["background"] == "false"
    assert result is not None and result.success is True
    assert result.discovered_services == [
        {
            "target": "192.0.2.10",
            "service": "smb",
            "port": 445,
            "protocol": "tcp",
            "version": "Windows SMB",
            "raw_service": "microsoft-ds",
        }
    ]


def test_nmap_host_results_preserve_concrete_host_port_and_protocol(
    real_framework, monkeypatch
):
    def fake_run_operation(module, operation):
        return {
            "success": True,
            "parsed": {
                "hosts": [
                    {
                        "ip": "192.0.2.21",
                        "services": {
                            "53/udp": {
                                "service": "domain",
                                "port": 53,
                                "protocol": "udp",
                                "version": "BIND",
                            }
                        },
                    },
                    {
                        "ip": "192.0.2.22",
                        "services": {
                            "8443/tcp": {
                                "service": "ssl/http",
                                "port": 8443,
                                "protocol": "tcp",
                                "version": "nginx",
                            }
                        },
                    },
                ]
            },
        }

    monkeypatch.setattr(real_framework, "run_operation", fake_run_operation)
    pipeline = AutoEnumPipeline(real_framework)

    pipeline._run_discovery_phase(["192.0.2.0/24"])

    assert pipeline.discovered_services == {
        "192.0.2.21": {"dns"},
        "192.0.2.22": {"https"},
    }
    assert pipeline.discovered_endpoints["192.0.2.21"][0]["protocol"] == "udp"
    assert pipeline.discovered_endpoints["192.0.2.22"][0]["port"] == 8443
    assert "192.0.2.0/24" not in pipeline.discovered_services


def test_passive_scope_does_not_load_or_execute_nmap():
    framework = Mock()
    pipeline = AutoEnumPipeline(framework, scope=EnumScope.PASSIVE)

    pipeline._run_discovery_phase(["192.0.2.10"])

    framework.use_module.assert_not_called()
    framework.run_module.assert_not_called()
    framework.run_operation.assert_not_called()


def test_default_rule_operation_names_exist_on_registered_modules(real_framework):
    checked = set()
    for rule in AutoEnumPipeline.DEFAULT_SERVICE_RULES:
        for module_path, operation_name in rule.operations.items():
            pair = (module_path, operation_name)
            if pair in checked:
                continue
            checked.add(pair)
            module = real_framework.use_module(module_path)
            assert module is not None, module_path
            available = {operation["name"] for operation in module.get_operations()}
            assert operation_name in available, pair


def test_service_rule_runs_exact_operation_on_matching_endpoint(
    real_framework, monkeypatch
):
    # This contract targets the local fallback path, not Aranum's SMB ownership.
    real_framework.modules.pop("recon/aranum", None)
    captured = {}

    def fake_run_operation(module, operation):
        captured["target"] = module.get_option("RHOST")
        captured["operation"] = operation["name"]
        return {"success": True}

    monkeypatch.setattr(real_framework, "run_operation", fake_run_operation)
    pipeline = AutoEnumPipeline(real_framework)
    pipeline.service_rules = [
        ServiceRule(
            service="smb",
            ports=[445],
            modules=["network/nxc_smb"],
            operations={"network/nxc_smb": "List Shares"},
            phase=EnumPhase.ENUMERATION,
        )
    ]
    pipeline._remember_endpoint(
        {
            "target": "192.0.2.30",
            "service": "smb",
            "port": 445,
            "protocol": "tcp",
            "version": "",
        },
        "192.0.2.30",
    )

    pipeline._run_enumeration_phase("192.0.2.30")

    assert captured == {
        "target": "192.0.2.30",
        "operation": "List Shares",
    }
    assert (
        "network/nxc_smb:List Shares:192.0.2.30:445:tcp"
        in pipeline.executed_modules
    )
