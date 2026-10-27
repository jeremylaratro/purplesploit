"""Offline exact-argv and XML golden coverage for the canonical Nmap backend."""

import importlib
import json
from pathlib import Path
import shlex
import subprocess
from unittest.mock import patch

import pytest

from purplesploit.core.execution import ExecutionRequest, Observation
from purplesploit.modules.recon.nmap import NMAP_PROFILES, NmapModule
from purplesploit.modules.recon.nmap_importer import parse_nmap_xml
from purplesploit.modules.recon.nmap_parser import NmapParser


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "nmap"
TARGET = "192.0.2.7"
PROFILE_ARGV = {
    "default": ["-sCV", "-p", "-", "-T4", "--min-rate", "3900", "--max-rtt-timeout", "4.5"],
    "fast": ["-sV", "--top-ports", "100", "-T4", "--version-intensity", "2", "--min-rate", "5000",
             "--max-rtt-timeout", "2", "--max-retries", "1"],
    "comprehensive": ["-sCV", "-p", "-", "-T4", "--version-intensity", "9", "--min-rate", "3900",
                      "--max-rtt-timeout", "4.5"],
    "aggressive": ["-sCV", "-p", "-", "-T4", "-O", "--traceroute", "--version-intensity", "9",
                   "--min-rate", "3900", "--max-rtt-timeout", "4.5"],
    "stealth": ["-sS", "-p", "-", "-T2", "--min-rate", "100", "--max-rtt-timeout", "10"],
    "udp": ["-sU", "--top-ports", "100", "-T4", "--min-rate", "1000", "--max-rtt-timeout", "4.5"],
    "udp_full": ["-sU", "-p", "-", "-T4", "--min-rate", "1000", "--max-rtt-timeout", "4.5"],
    "no_ping": ["-sCV", "-p", "-", "-T4", "-Pn", "--min-rate", "3900", "--max-rtt-timeout", "4.5"],
}
ALIASES = [("fast", "NmapFastModule"), ("udp", "NmapUdpModule"), ("no_ping", "NmapNoPingModule"),
           ("stealth", "NmapStealthModule"), ("aggressive", "NmapAggressiveModule"),
           ("comprehensive", "NmapComprehensiveModule")]


def configure(module):
    module.set_option("RHOST", TARGET)
    module.set_option("OUTPUT_FORMAT", "normal")
    return module


@pytest.mark.parametrize("profile", NMAP_PROFILES)
def test_profiles_exact_argv(mock_framework, profile):
    module = configure(NmapModule(mock_framework))
    module.apply_profile(profile)
    expected = ["nmap", *PROFILE_ARGV[profile], TARGET]
    assert module.build_argv() == expected
    assert shlex.split(module.build_command()) == expected


@pytest.mark.parametrize("profile,class_name", ALIASES)
def test_legacy_alias_uses_canonical_profile(mock_framework, profile, class_name):
    alias = getattr(importlib.import_module(f"purplesploit.modules.recon.nmap_{profile}"), class_name)
    module = configure(alias(mock_framework))
    assert module.build_argv() == ["nmap", *PROFILE_ARGV[profile], TARGET]
    assert "build_command" not in alias.__dict__ and "_init_options" not in alias.__dict__
    # Operations on a legacy path route the same canonical implementations.
    with patch.object(module, "run", return_value={"success": True}):
        module.op_default_scan()
    assert module.build_argv() == ["nmap", *PROFILE_ARGV["default"], TARGET]


def test_operations_reset_previous_profile_without_losing_timeout(mock_framework):
    module = configure(NmapModule(mock_framework))
    module.set_option("HOST_TIMEOUT", "30m")
    with patch.object(module, "run", return_value={"success": True}):
        module.op_aggressive_scan()
        module.op_fast_scan()
        module.op_udp_scan()
    assert module.build_argv() == ["nmap", *PROFILE_ARGV["udp"], "--host-timeout", "30m", TARGET]


@pytest.mark.parametrize("profile,canonical", [("tcp-full", "default"), ("tcp-top", "fast"),
                                               ("udp-top", "udp"), ("udp-full", "udp_full")])
def test_profile_option_aliases(mock_framework, profile, canonical):
    module = configure(NmapModule(mock_framework))
    module.set_option("PROFILE", profile)
    assert module.build_argv() == ["nmap", *PROFILE_ARGV[canonical], TARGET]


def test_legacy_operation_ids_and_operations_are_orchestratable(mock_framework):
    module = NmapModule(mock_framework)
    assert {item["id"] for item in module.get_operations()} == {
        "default-scan", "fast-scan", "comprehensive-scan", "aggressive-scan",
        "stealth-scan", "udp-scan", "udp-full-scan", "no-ping-scan",
    }
    assert all(not item["background"] for item in module.get_operations())
    module.execution_request = ExecutionRequest("recon/nmap", background=False)
    assert all(not item["background"] for item in module.get_operations())


def test_ipv6_exact_argv_and_run_path(mock_framework, tmp_path):
    module = NmapModule(mock_framework)
    module.set_option("RHOST", "2001:db8::7")
    module.set_option("RUN_DIR", str(tmp_path / "run"))
    module.set_option("OUTPUT_FORMAT", "xml")
    module.set_option("OUTPUT_FILE", "scan output.xml")
    module.set_option("HOST_TIMEOUT", "90s")
    assert module.build_argv() == ["nmap", "-6", *PROFILE_ARGV["default"], "--host-timeout", "90s",
                                   "-oX", str(tmp_path / "run" / "scan output.xml"), "2001:db8::7"]
    assert not (tmp_path / "run").exists()  # Building a command has no filesystem side effects.


def test_target_file_and_list_exact_argv(mock_framework, tmp_path):
    module = NmapModule(mock_framework)
    targets = tmp_path / "segment one.txt"
    targets.write_text("192.0.2.0/28\n# next segment\n192.0.2.90\n")
    module.set_option("TARGET_FILE", str(targets))
    module.set_option("TARGETS", ["192.0.2.7", "192.0.2.8"])
    module.set_option("OUTPUT_FORMAT", "normal")
    assert module.validate_options()[0]
    assert module.build_argv() == ["nmap", *PROFILE_ARGV["default"], "-iL", str(targets),
                                   "192.0.2.7", "192.0.2.8"]


def test_request_cwd_resolves_output_before_execution(mock_framework, tmp_path):
    module = configure(NmapModule(mock_framework))
    module.set_option("OUTPUT_FORMAT", "xml")
    module.set_option("OUTPUT_FILE", "result.xml")
    module.execution_request = ExecutionRequest("recon/nmap", cwd=str(tmp_path / "cwd"),
                                                run_dir=str(tmp_path / "artifacts"))
    assert module.build_argv()[-3:] == ["-oX", str(tmp_path / "cwd" / "result.xml"), TARGET]


def test_ipv6_target_file_autodetection(mock_framework, tmp_path):
    module = NmapModule(mock_framework)
    targets = tmp_path / "v6.txt"
    targets.write_text("2001:db8::7\n2001:db8::8\n")
    module.set_option("TARGET_FILE", str(targets))
    module.set_option("OUTPUT_FORMAT", "normal")
    assert module.build_argv() == ["nmap", "-6", *PROFILE_ARGV["default"], "-iL", str(targets)]


def test_mixed_families_require_separate_segments(mock_framework):
    module = NmapModule(mock_framework)
    module.set_option("TARGETS", ["192.0.2.7", "2001:db8::7"])
    valid, error = module.validate_options()
    assert not valid and "segmented" in error


def test_whitespace_targets_are_separate_argv(mock_framework):
    module = configure(NmapModule(mock_framework))
    module.set_option("RHOST", "192.0.2.0/28\n192.0.2.90")
    assert module.build_argv()[-2:] == ["192.0.2.0/28", "192.0.2.90"]


def test_legacy_extra_options_are_built_once_and_quoted(mock_framework):
    module = configure(NmapModule(mock_framework))
    module.set_option("SCAN_TYPE", "sS -sU")
    module.set_option("PORTS", "T:53,U:53")
    module.set_option("NO_PING", "true")
    module.set_option("SKIP_DISCOVERY", "true")
    module.set_option("TRACEROUTE", "true")
    module.set_option("DECOY", "example.test; literal")
    module.set_option("FRAGMENT", "true")
    module.set_option("SCRIPT", "default and safe")
    argv = module.build_argv()
    assert argv == ["nmap", "-sS", "-sU", "-p", "T:53,U:53", "-T4", "--traceroute", "-f", "-Pn",
                    "--min-rate", "3900", "--max-rtt-timeout", "4.5", "-D", "example.test; literal",
                    "--script=default and safe", TARGET]
    assert shlex.split(module.build_command()) == argv


def test_xml_observation_golden():
    parsed = parse_nmap_xml(FIXTURES / "cwp2.xml")
    keys = ("kind", "target", "port", "protocol", "service", "version")
    attribute_keys = ("hostname", "product", "service_version", "scripts")
    actual = [{**{key: observation[key] for key in keys},
               **{key: observation["attributes"].get(key) for key in attribute_keys}}
              for observation in parsed["observations"]]
    assert actual == json.loads((FIXTURES / "cwp2.json").read_text())
    assert parsed["total_hosts"] == 3 and parsed["hosts_with_ports"] == 2
    endpoints = [Observation.from_dict(item) for item in parsed["observations"] if item["kind"] == "service"]
    assert {(item.target, item.port, item.protocol) for item in endpoints} == {
        ("192.0.2.53", 53, "tcp"), ("192.0.2.53", 53, "udp"), ("2001:db8::443", 8443, "tcp")}
    assert len({item.observation_id for item in endpoints}) == 3
    assert all(item.attributes["source_tool_version"] == "7.95" for item in endpoints)


def test_parser_and_scanner_share_importer(mock_framework):
    scanner = NmapModule(mock_framework)
    parser = NmapParser(mock_framework)
    parser.set_option("XML_FILE", str(FIXTURES / "cwp2.xml"))
    parser.set_option("RUN_SEARCHSPLOIT", "false")
    with patch("purplesploit.modules.recon.nmap_parser.db_manager"):
        imported = parser.run()
    scanned = scanner.parse_xml_output(str(FIXTURES / "cwp2.xml"))
    assert imported["success"] and imported["hosts"] == scanned["hosts"]
    assert imported["data"]["hosts_processed"] == 3 and imported["data"]["services_found"] == 3
    def identity(items):
        return [(item["kind"], item["target"], item["port"], item["protocol"], item["service"], item["attributes"])
                for item in items]
    assert identity(imported["observations"]) == identity(scanned["observations"])


def test_sync_request_overrides_legacy_background_default(mock_framework, tmp_path, monkeypatch):
    module = NmapModule(mock_framework)
    module.set_option("RHOST", "192.0.2.0/24")
    module.execution_request = ExecutionRequest("recon/nmap", background=False, run_dir=str(tmp_path))
    monkeypatch.setattr(module, "check_tool_installed", lambda: True)
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        Path(argv[argv.index("-oA") + 1] + ".xml").write_bytes((FIXTURES / "cwp2.xml").read_bytes())
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
    monkeypatch.setattr(subprocess, "run", run)
    with patch("purplesploit.modules.recon.nmap.db_manager"):
        result = module.op_fast_scan()
    assert result["success"] and result["xml_parsed"]
    assert result["observations"] and all(item["source_execution_id"] == module.execution_request.request_id
                                          for item in result["observations"])
    assert calls[0][0] == ["nmap", *PROFILE_ARGV["fast"], "-oA", str(tmp_path / "nmap_192.0.2.0_24"),
                           "192.0.2.0/24"]
    assert all("/24" not in item["target"] for item in result["observations"])


def test_background_is_pending_and_does_not_import_existing_xml(mock_framework, tmp_path):
    module = configure(NmapModule(mock_framework))
    module.set_option("OUTPUT_FORMAT", "xml")
    module.set_option("OUTPUT_FILE", str(FIXTURES / "cwp2.xml"))
    module.execution_request = ExecutionRequest("recon/nmap", background=True)
    with patch.object(module, "check_tool_installed", return_value=True), \
            patch.object(module, "execute_command", return_value={"success": True, "pid": 99}), \
            patch.object(module, "process_discovered_hosts") as imported:
        result = module.run()
    assert not result["success"] and result["background"] and result["pid"] == 99
    assert result["observations"] == []
    imported.assert_not_called()


@pytest.mark.parametrize("target", ["192.0.2.0/24", "192.0.2.1 192.0.2.2", "192.0.2.1-4"])
def test_missing_xml_never_synthesizes_range_or_list_endpoints(mock_framework, tmp_path, target):
    module = configure(NmapModule(mock_framework))
    module.set_option("RHOST", target)
    module.set_option("BACKGROUND", "false")
    with patch("purplesploit.modules.recon.nmap.ExternalToolModule.run", return_value={
        "success": True, "parsed": {"services": {"445/tcp": {"service": "microsoft-ds"}}},
    }):
        result = module.run()
    assert not result["success"] and result["observations"] == []


def test_invalid_xml_fails_both_entrypoints(mock_framework, tmp_path):
    path = tmp_path / "bad.xml"
    path.write_text("<nmaprun><host>")
    module = NmapModule(mock_framework)
    parser = NmapParser(mock_framework)
    parser.set_option("XML_FILE", str(path))
    assert module.parse_xml_output(str(path))["error"]
    assert not parser.run()["success"]
