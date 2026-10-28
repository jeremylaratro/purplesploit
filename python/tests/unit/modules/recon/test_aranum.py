"""Hermetic coverage for the Aranum module and auto-enum handoff."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from purplesploit.core.auto_enum import (
    AutoEnumPipeline,
    EnumPhase,
    EnumResult,
    ServiceRule,
)
from purplesploit.core.framework import Framework
from purplesploit.modules.recon.aranum import (
    ARANUM_OWNED_BASELINES,
    DEFAULT_ARGV,
    AranumModule,
)


FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "interop" / "aranum"
FORBIDDEN = {"--aggressive", "--desktop", "--write", "--exploit"}


def test_registration_and_published_dispatcher_operations(tmp_path):
    framework = Framework(
        db_path=str(tmp_path / "framework.db"),
        plugins_dir=tmp_path / "plugins",
        plugin_config_dir=tmp_path / "config",
    )
    try:
        framework.discover_modules()
        assert framework.get_module("recon/aranum") is not None
        module = framework.instantiate_module("recon/aranum")
        # Discovery loads modules from their paths, so the discovered class is a
        # separate import identity from this test module's direct import.
        assert module.__class__.__name__ == "AranumModule"
        assert module.category == "recon"

        labels = {
            str(operation.get("name") or operation.get("id"))
            for operation in module.get_operations()
        }
        assert "Run Selected Services" in labels
        dispatchers = __import__("json").loads(
            (FIXTURES / "dispatchers.json").read_text(encoding="utf-8")
        )["dispatchers"]
        for dispatcher in dispatchers:
            name = dispatcher["name"]
            assert any(name in label for label in labels), f"dispatcher {name} does not resolve"
    finally:
        framework.cleanup()


def test_selected_services_builds_safe_operator_root_argv(tmp_path, mock_framework_minimal):
    module = AranumModule(mock_framework_minimal)
    output_root = tmp_path / "operator-output"
    module.tool_path = "/opt/aranum/bin/aranum"
    module.set_option("TARGET", "192.0.2.10 192.0.2.11")
    module.set_option("SERVICES", "smb, ldap")
    module.set_option("OUTPUT_ROOT", str(output_root))

    argv = module.build_argv()

    assert argv == [
        "/opt/aranum/bin/aranum",
        *DEFAULT_ARGV,
        "--only",
        "smb,ldap",
        "--service-parallel",
        "-o",
        str(output_root),
        "192.0.2.10",
        "192.0.2.11",
    ]
    assert not FORBIDDEN.intersection(argv)
    assert not FORBIDDEN.intersection(DEFAULT_ARGV)


def test_partial_returncode_imports_bundle(mock_framework_minimal):
    module = AranumModule(mock_framework_minimal)
    module.tool_path = "/opt/aranum/bin/aranum"
    module.set_option("TARGET", "192.0.2.10")
    module.set_option("SERVICES", "smb")
    module.set_option("OUTPUT_ROOT", str(FIXTURES / "fx-3"))
    imported = SimpleNamespace(
        status="partial",
        observations=[SimpleNamespace(to_dict=lambda: {"kind": "service"})],
        findings=[SimpleNamespace(to_dict=lambda: {"id": "finding-1"})],
    )

    with patch.object(
        module,
        "execute_command",
        return_value={"success": False, "returncode": 4, "stdout": "", "stderr": ""},
    ) as execute, patch(
        "purplesploit.modules.recon.aranum.import_aranum_bundle", return_value=imported
    ) as importer:
        result = module.op_run_selected_services()

    assert result["success"] is True
    assert result["aranum_returncode"] == 4
    assert result["returncode"] == 0
    assert result["bundle_status"] == "partial"
    assert result["observations"] == [{"kind": "service"}]
    assert result["findings"] == [{"id": "finding-1"}]
    assert "--only" in execute.call_args.args[0]
    importer.assert_called_once_with(FIXTURES / "fx-3")


def test_auto_enum_coalesces_owned_services_without_double_dispatch():
    framework = SimpleNamespace(modules={"recon/aranum": object()})
    pipeline = AutoEnumPipeline(framework)
    pipeline.discovered_services["192.0.2.10"] = {"smb", "ldap", "ftp"}
    pipeline.service_rules = [
        ServiceRule(
            service="smb",
            modules=["network/legacy-smb"],
            phase=EnumPhase.ENUMERATION,
            priority=9,
        ),
        ServiceRule(
            service="ldap",
            modules=["network/legacy-ldap"],
            phase=EnumPhase.ENUMERATION,
            priority=8,
        ),
        ServiceRule(
            service="ftp",
            modules=["network/ftp"],
            phase=EnumPhase.ENUMERATION,
            priority=7,
        ),
    ]
    calls = []

    def run_module(**kwargs):
        calls.append(kwargs)
        return EnumResult(
            module=kwargs["module_path"],
            operation=kwargs.get("operation"),
            target=kwargs["target"],
            success=True,
        )

    pipeline._run_module = Mock(side_effect=run_module)
    pipeline._process_enum_results = Mock()

    pipeline._run_enumeration_phase("192.0.2.10")

    aranum_calls = [call for call in calls if call["module_path"] == "recon/aranum"]
    assert len(aranum_calls) == 1
    assert aranum_calls[0]["operation"] == "Run Selected Services"
    assert aranum_calls[0]["options"]["SERVICES"] == "smb,ldap"
    assert [call["module_path"] for call in calls if call["module_path"] != "recon/aranum"] == [
        "network/ftp"
    ]
    assert not {"network/legacy-smb", "network/legacy-ldap"}.intersection(
        call["module_path"] for call in calls
    )
    assert {"smb", "ldap", "winrm", "rdp", "ssh", "mssql", "dns", "http"} <= set(
        ARANUM_OWNED_BASELINES
    )
