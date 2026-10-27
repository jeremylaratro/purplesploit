"""Portable Aranum contracts; producer installation and live targets are absent."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from purplesploit.core.auto_enum import AutoEnumPipeline, ServiceRule
from purplesploit.core.execution import Observation
from purplesploit.core.findings import FindingStatus
from purplesploit.core.framework import Framework
from purplesploit.interop.aranum import INVENTORY_SCHEMA, import_aranum_bundle, seed_auto_enum


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "aranum"


def test_network_inventory_keeps_host_endpoint_and_producer_identity():
    bundle = import_aranum_bundle(FIXTURES / "network")
    hosts = [item for item in bundle.observations if item.kind == "host"]
    assert len(hosts) == 3
    assert any(item.target == "192.0.2.10" and item.port is None for item in hosts)
    endpoints = [item for item in bundle.observations if item.kind == "service"]
    assert {(item.target, item.port, item.protocol) for item in endpoints} >= {
        ("2001:db8::10", 53, "tcp"), ("2001:db8::10", 53, "udp"), ("2001:db8::10", 9443, "tcp")}
    web = next(item for item in endpoints if item.port == 9443)
    assert web.service == "https" and web.attributes["raw_service"] == "http"
    assert web.attributes["subject"]["hostname"] == "dual.example.test"
    assert web.attributes["product"] == "nginx" and web.version == "fixture"
    assert web.attributes["extrainfo"] == "TLS endpoint" and web.attributes["tunnel"] == "ssl"
    assert web.attributes["categories"] == ["http", "https"]
    assert web.source_schema == INVENTORY_SCHEMA
    assert web.source_id is None and web.source_tool_version is None
    assert web.attributes["run_id"] == "network-fixture-run"
    assert Observation.from_dict(json.loads(json.dumps(web.to_dict()))) == web


def test_exact_reimport_deduplicates_and_preserves_operator_changes(tmp_path):
    observations, findings = [], []
    first = import_aranum_bundle(FIXTURES / "posture")
    assert first.merge_into(observations, findings) == {"observations": len(first.observations), "findings": 2}
    findings[0].notes.append("Operator note")
    assert import_aranum_bundle(FIXTURES / "posture").merge_into(observations, findings) == {"observations": 0, "findings": 0}
    assert findings[0].notes == ["Operator note"]
    shutil.copytree(FIXTURES / "posture", tmp_path / "fresh")
    for filename in ("findings.json", "posture.json"):
        path = tmp_path / "fresh" / filename
        document = json.loads(path.read_text())
        document["run_id"] = "another-producer-run"
        path.write_text(json.dumps(document))
    fresh = import_aranum_bundle(tmp_path / "fresh")
    assert fresh.merge_into(observations, findings) == {"observations": len(fresh.observations), "findings": 2}
    assert len(findings) == 4


def test_unknown_run_is_distinct_from_bundle_fingerprint(tmp_path):
    shutil.copytree(FIXTURES / "network", tmp_path / "unknown")
    (tmp_path / "unknown" / "run-state.json").unlink()
    first = import_aranum_bundle(tmp_path / "unknown")
    second = import_aranum_bundle(tmp_path / "unknown")
    assert first.run_id is None
    assert first.bundle_fingerprint == second.bundle_fingerprint
    assert all(item.attributes["run_id"] is None for item in first.observations)
    assert {item.observation_id for item in first.observations} == {item.observation_id for item in second.observations}
    assert all(item.observed_at is None for item in first.observations)


def test_posture_retains_every_status_without_manufacturing_findings():
    bundle = import_aranum_bundle(FIXTURES / "posture")
    checks = [item for item in bundle.observations if item.attributes["record_type"] == "posture_check"]
    assert len(checks) == 7
    assert {item.attributes["status"] for item in checks} == {"PASS", "FAIL", "WARN", "INFO", "NA", "ERR"}
    assert len(bundle.findings) == 2
    assert {item.source_id for item in bundle.observations if item.kind == "finding"} == {"AR-fixture-host", "AR-fixture-domain"}
    domain = next(item for item in checks if item.target == "example.test")
    assert domain.attributes["scope"] == "domain"
    assert domain.attributes["observed_from"][0]["host"] == "192.0.2.31"
    assert domain.port is None
    assert bundle.findings[0].status is FindingStatus.DRAFT
    assert "unmapped" in bundle.findings[1].notes[0]
    metadata = next(item for item in bundle.observations if item.attributes["source_file"] == "findings.json" and item.attributes["record_type"] == "snapshot_metadata")
    assert metadata.raw["kb"]["checks"]["LIN-FAIL"]["remediation"]["steps"]
    host_finding = next(item for item in bundle.observations if item.source_id == "AR-fixture-host")
    assert len(host_finding.attributes["artifacts"]) == 1
    assert host_finding.attributes["artifacts"][0]["exists"] is True
    assert Path(bundle.findings[0].evidence[0].file_path).is_file()
    assert bundle.findings[1].evidence[0].file_path is None
    assert "missing/domain.txt" in bundle.findings[1].evidence[0].description


def test_partial_error_skipped_unassessed_and_redacted_paths_stay_visible():
    bundle = import_aranum_bundle(FIXTURES / "partial")
    assert not bundle.findings
    raw = [item.raw for item in bundle.observations]
    assert {item.get("status") for item in raw} >= {"ERR", "failed", "skipped", "unassessed"}
    metadata = next(item for item in raw if item.get("partial"))
    assert metadata["errors"][0]["error"] == "missing optional dependency"
    assert metadata["summary"]["coverage"][0]["status"] == "unassessed"
    artifacts = [artifact for item in bundle.observations for artifact in item.attributes["artifacts"]]
    assert artifacts and all(not item["exists"] and item["resolved_path"] is None for item in artifacts)
    assert any("<redacted>" in item["reference"] for item in artifacts)


def test_seeded_real_framework_followup_resolves_registered_operation_and_skips_nmap(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    framework = Framework(db_path=str(tmp_path / "interop.db"))
    framework.discover_modules()
    calls = []

    def fake_process(argv, **kwargs):
        calls.append((argv, kwargs))
        assert argv[0] == "nxc", "Discovery or an unselected follow-up ran"
        return subprocess.CompletedProcess(argv, 0, "fixture NLA result", "")

    monkeypatch.setattr(subprocess, "run", fake_process)
    try:
        pipeline = AutoEnumPipeline(framework)
        pipeline.service_rules = [ServiceRule(service="rdp", ports=[3389], modules=["network/nxc_rdp"],
                                             operations={"network/nxc_rdp": "Check NLA Status"})]
        bundle = import_aranum_bundle(FIXTURES / "network")
        assert seed_auto_enum(bundle, pipeline) == 4
        summary = pipeline.run(["192.0.2.10", "2001:db8::10", "192.0.2.20"], skip_discovery=True)
        assert summary["modules_executed"] == 1 and len(calls) == 1
        assert pipeline.results[0].success is True
        assert pipeline.results[0].operation == "Check NLA Status"
        assert calls[0][0] == ["nxc", "rdp", "192.0.2.20"]
        assert pipeline.discovered_endpoints["2001:db8::10"][2]["port"] == 9443
        assert framework.session.current_module is None
    finally:
        framework.cleanup()


@pytest.mark.parametrize("filename,version", [("findings.json", 3), ("posture.json", "2"), ("run-state.json", 2)])
def test_future_companion_schema_is_not_silently_misread(tmp_path, filename, version):
    shutil.copytree(FIXTURES / "posture", tmp_path / "invalid")
    (tmp_path / "invalid" / filename).write_text(json.dumps({"schema_version": version}))
    with pytest.raises(ValueError, match="Unsupported"):
        import_aranum_bundle(tmp_path / "invalid")


def test_inventory_is_required(tmp_path):
    with pytest.raises(FileNotFoundError):
        import_aranum_bundle(tmp_path)
