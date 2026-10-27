"""CWP6 golden contracts for canonical finding/report compatibility."""

from copy import deepcopy
from dataclasses import fields
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from purplesploit.core.findings import Evidence, Finding, FindingsManager, FindingStatus, Severity
from purplesploit.reporting import models
from purplesploit.reporting.generator import ReportGenerator
from purplesploit.reporting.html import HTMLReportGenerator
from purplesploit.reporting.models import ReportConfig, ReportData, finding_record_json


@pytest.fixture
def golden():
    return json.loads((Path(__file__).parent / "fixtures" / "finding_v1.json").read_text())


class FindingRecords(HTMLParser):
    def __init__(self):
        super().__init__()
        self.records = []
        self.active = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "pre" and ("class", "finding-record") in attrs:
            self.active = True
            self.parts = []

    def handle_data(self, data):
        if self.active:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag == "pre" and self.active:
            self.records.append(json.loads("".join(self.parts)))
            self.active = False


def test_reporting_imports_are_canonical():
    for name, canonical in (("Finding", Finding), ("Evidence", Evidence),
                            ("Severity", Severity), ("FindingStatus", FindingStatus)):
        assert getattr(models, name) is canonical


@pytest.mark.parametrize("keyword", [False, True])
def test_reporting_attachment_compatibility(keyword):
    finding = Finding(id="finding")
    evidence = models.Evidence(id="evidence", finding_id="", file_type="log")
    attached = finding.add_evidence(evidence=evidence) if keyword else finding.add_evidence(evidence)
    assert attached is evidence
    assert evidence.finding_id == finding.id
    assert evidence.evidence_type == "log"
    assert finding.evidence == [evidence]


def test_golden_round_trip_is_lossless_non_mutating_and_detached(golden):
    original = deepcopy(golden)
    assert set(golden) == {f.name for f in fields(Finding)}
    finding = Finding.from_dict(golden)
    assert golden == original
    assert finding.to_dict() == original
    assert Finding.from_dict(finding.to_dict()).to_dict() == original
    assert Finding.from_dict(finding.to_report_dict()).to_dict() == original
    golden["metadata"]["custom"]["count"] = 99
    exported = finding.to_dict()
    exported["tags"].append("changed")
    exported["evidence"][0]["tags"].append("changed")
    assert finding.to_dict() == original


def test_json_report_projection_and_import_are_lossless(golden, tmp_path):
    generator = ReportGenerator()
    finding = generator.create_finding(**golden)
    assert finding.to_dict() == golden
    path = tmp_path / "report.json"
    generator.generate("json", str(path))
    report = json.loads(path.read_text())
    assert report["schema_version"] == 1
    assert report["findings"] == [{"schema_version": 1, **golden}]
    imported = ReportGenerator()
    imported.load_findings_from_json(str(path))
    assert imported.findings[0].to_dict() == golden


@pytest.mark.parametrize("format", ["html", "markdown", "html-simple"])
def test_human_reports_preserve_full_versioned_record(golden, tmp_path, format):
    generator = ReportGenerator()
    generator.config.include_raw_output = True
    generator.add_finding(golden)
    path = tmp_path / f"report.{format}"
    if format == "html-simple":
        HTMLReportGenerator()._generate_simple(generator._build_report_data(), path)
    else:
        generator.generate(format, str(path))
    rendered = path.read_text()
    if format == "markdown":
        records = [json.loads(r) for r in re.findall(r"```json\n(.*?)\n```", rendered, re.DOTALL)]
    else:
        parser = FindingRecords()
        parser.feed(rendered)
        records = parser.records
    assert records == [{"schema_version": 1, **golden}]
    assert "accepted_risk" in rendered


def test_report_options_apply_to_canonical_records(golden):
    config = ReportConfig(include_evidence=False, include_raw_output=False)
    projection = json.loads(finding_record_json(Finding.from_dict(golden), config))
    assert "evidence" not in projection
    assert "raw_output" not in projection
    assert projection["retest"] == golden["retest"]


def test_manager_report_preserves_identity_and_all_fields(golden, tmp_path):
    manager = FindingsManager(storage_path=str(tmp_path))
    finding = Finding.from_dict(golden)
    manager.findings[finding.id] = finding
    generator = manager.to_report_generator()
    assert generator.findings[0] is finding
    assert generator._build_report_data().findings[0].to_dict() == golden


def test_builder_discovers_manager_without_database(golden, tmp_path):
    manager = FindingsManager(storage_path=str(tmp_path))
    manager.findings[golden["id"]] = Finding.from_dict(golden)
    report = ReportGenerator(SimpleNamespace(findings_manager=manager))._build_report_data()
    assert report.total_findings == 1
    assert report.findings[0].to_dict() == golden


def test_builder_reads_legacy_database_rows_without_dropping_data(memory_database):
    identifier = memory_database.add_finding(
        target="192.0.2.1", title="Legacy finding", severity="high",
        description="Legacy description", evidence="Legacy evidence",
        remediation="Legacy fix", module_name="legacy/module",
    )
    report = ReportGenerator(SimpleNamespace(database=memory_database))._build_report_data()
    assert report.total_findings == 1
    finding = report.findings[0]
    assert finding.id == identifier
    assert finding.evidence[0].content == "Legacy evidence"
    assert finding.discovered_at.isoformat(sep=" ") == finding.metadata["legacy_fields"]["created_at"]
    assert finding.remediation == "Legacy fix"
    assert finding.module_name == "legacy/module"


@pytest.mark.parametrize("as_dict", [False, True])
@pytest.mark.parametrize("shape", ["list", "single", "mapping"])
def test_builder_accepts_objects_and_dicts(golden, as_dict, shape):
    finding = golden if as_dict else Finding.from_dict(golden)
    selection = {"list": [finding], "single": finding, "mapping": {"id": finding}}[shape]
    report = ReportGenerator()._build_report_data(selection)
    assert report.findings[0].to_dict() == golden


def test_module_result_import_preserves_rich_fields(golden):
    result = {**golden, "success": True, "stdout": golden["raw_output"]}
    finding = ReportGenerator().import_from_module_result(
        golden["module_name"], result, golden["target"],
    )
    projected = finding.to_dict()
    assert projected["metadata"].pop("legacy_fields") == {
        "success": True, "stdout": golden["raw_output"],
    }
    assert projected == golden


def test_invalid_findings_fail_explicitly():
    with pytest.raises(TypeError, match="canonical Finding"):
        ReportGenerator()._build_report_data([object()])
    with pytest.raises(ValueError, match="schema version"):
        Finding.from_dict({"schema_version": 2})
    with pytest.raises(ValueError, match="conflicting evidence"):
        Evidence.from_dict({"file_type": "log", "evidence_type": "pcap"})


def test_unknown_legacy_fields_and_string_notes_are_preserved():
    data = {"host": "192.0.2.2", "notes": "Multiline\nnote", "reviewer": "peer",
            "evidence": [{"file_type": "log", "source": "legacy"}]}
    original = deepcopy(data)
    finding = Finding.from_dict(data)
    assert data == original
    assert finding.target == "192.0.2.2"
    assert finding.notes == ["Multiline\nnote"]
    assert finding.metadata["legacy_fields"] == {"reviewer": "peer"}
    assert finding.evidence[0].evidence_type == "log"
    assert finding.evidence[0].metadata["legacy_fields"] == {"source": "legacy"}
    assert Finding.from_dict(finding.to_dict()).to_dict() == finding.to_dict()


def test_accept_risk_remains_distinct_and_included_by_default(tmp_path):
    manager = FindingsManager(storage_path=str(tmp_path))
    finding = manager.create("Exception", "high", "Description", "192.0.2.2")
    finding.accept_risk("Upgrade scheduled", "risk-owner")
    assert finding.status is FindingStatus.ACCEPTED_RISK
    assert finding.risk_accepted_at is not None
    assert finding.risk_accepted_by == "risk-owner"
    assert finding.risk_acceptance_reason == "Upgrade scheduled"
    assert finding.remediated_at is None
    report = ReportData(ReportConfig(), [finding])
    assert report.filter_findings(report.config) == [finding]
    report.config.statuses_to_include = [FindingStatus.CONFIRMED]
    assert report.filter_findings(report.config) == []
    manager.transition_status(finding.id, "accepted_risk", "reviewed")
    loaded = FindingsManager(storage_path=str(tmp_path)).get(finding.id)
    assert loaded.status is FindingStatus.ACCEPTED_RISK
    assert loaded.risk_acceptance_reason == "reviewed"
    assert loaded.risk_accepted_by == "risk-owner"
