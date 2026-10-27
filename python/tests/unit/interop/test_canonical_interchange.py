"""Canonical schema, deterministic interchange and consumer-shaped imports."""

from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path

import pytest

from purplesploit.core.assessment import Engagement, EvidenceReference, Hypothesis, PeerReview, Remediation, Retest
from purplesploit.core.attack_graph import AttackGraph, NodeType, EdgeType
from purplesploit.core.execution import ExecutionOutcome, ExecutionResult, Observation
from purplesploit.core.findings import Evidence, Finding
from purplesploit.interop.canonical import (
    CanonicalDocument, SCHEMA_VERSION, SCHEMA_PATH, export_csv, import_csv,
    export_sarif, import_sarif, export_defectdojo, import_defectdojo, validate_document,
)
from purplesploit.interop.importers import AdapterImporter, ImporterRegistry, detect, parse


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
HERE = FIXTURES / "canonical"


def document():
    evidence = Evidence(id="ev1", finding_id="f1", file_path="evidence/output.txt", captured_at=datetime(2026, 10, 26), metadata={"custom": [1]})
    finding = Finding(id="f1", title="Full lifecycle", severity="high", status="accepted_risk", target="192.0.2.1", port=443,
                      protocol="tcp", service="https", description="Multiple\nlines, commas", remediation="Upgrade", evidence=[evidence],
                      discovered_at=datetime(2026, 10, 26), cvss_score=8.1, cwe_ids=["CWE-79"], cve_ids=["CVE-2026-0001"],
                      review={"state": "approved"}, retest={"outcome": "persists"}, risk_accepted_by="owner", metadata={"unknown": True})
    observation = Observation(kind="service", target="192.0.2.1", port=443, protocol="tcp", observed_at="2026-10-26T12:00:00Z", source_execution_id="run1")
    execution = ExecutionResult(request_id="run1", outcome=ExecutionOutcome.SUCCESS, success=True, started_at="2026-10-26T12:00:00Z", observations=[observation], raw_result={"vendor": "keep"})
    engagement = Engagement(name="Fixture", id="e1", created_at="2026-10-26T12:00:00Z", evidence=[EvidenceReference(ref="evidence/output.txt", id="ev1")],
                            hypotheses=[Hypothesis(id="h1", text="hypothesis")], reviews=[PeerReview(subject_type="finding", subject_id="f1", reviewer="peer", id="r1", recorded_at="2026-10-26T12:00:00Z")],
                            remediations=[Remediation(finding_id="f1", owner="owner", id="m1")], retests=[Retest(outcome="persists", original_finding_id="f1", id="rt1", recorded_at="2026-10-26T12:00:00Z")])
    graph = AttackGraph()
    a = graph.add_node(NodeType.HOST, "Host", identifier="192.0.2.1")
    b = graph.add_node(NodeType.SERVICE, "HTTPS", identifier="192.0.2.1:443/tcp")
    graph.add_edge(a.id, b.id, EdgeType.HAS_SERVICE)
    return CanonicalDocument.from_components(engagement={"id": "e1", "name": "Fixture"}, assessment=engagement, graph=graph,
                                             assets=[{"id": "a1", "target": "192.0.2.1", "future": {"keep": True}}], services=[{"id": "s1", "port": 443}],
                                             identities=[{"id": "i1", "name": "alice"}], resources=[{"id": "r1", "name": "bucket"}],
                                             executions=[execution], observations=[observation], findings=[finding], evidence=[evidence], extensions={"custom": {"preserve": True}})


def test_schema_and_golden_ordering_unknown_fields():
    value = {"engagement": {"id": "e1", "name": "Fixture"}, "assets": [{"id": "a2", "target": "192.0.2.2"}, {"id": "a1", "target": "192.0.2.1"}],
             "findings": [{"id": "f1", "title": "Fixture finding", "severity": "high", "target": "192.0.2.1", "future": {"keep": True}}], "future_document": {"keep": True}}
    result = CanonicalDocument.from_mapping(value)
    assert result.to_dict() == json.loads((HERE / "golden.json").read_text())
    assert result.to_json() == CanonicalDocument.from_json(result.to_json()).to_json()
    for fallback in (True, False):
        result.validate(use_jsonschema=fallback)
    assert value["findings"][0]["future"] == {"keep": True}


def test_deterministic_ids_order_and_copy():
    a = {"assets": [{"target": "b"}, {"target": "a"}]}
    first = CanonicalDocument.from_mapping(a)
    second = CanonicalDocument.from_mapping({"assets": list(reversed(a["assets"]))})
    assert first.to_json() == second.to_json()
    first.to_dict()["assets"].clear()
    assert len(first.to_dict()["assets"]) == 2


@pytest.mark.parametrize("exporter,importer", [(export_csv, import_csv), (export_sarif, import_sarif), (export_defectdojo, import_defectdojo)])
def test_full_document_roundtrip(exporter, importer):
    original = document()
    exported = exporter(original)
    assert exported.diagnostics
    imported = importer(exported.data)
    assert imported.document.to_dict() == original.to_dict()
    assert imported.diagnostics
    assert exporter(imported.document).data == exported.data


@pytest.mark.parametrize("use_jsonschema", [True, False])
@pytest.mark.parametrize("mutate", [
    lambda value: value.update(schema_version="future"),
    lambda value: value.update(assets={}),
    lambda value: value["assets"].append({"id": "a1"}),
    lambda value: value["findings"][0].update(severity="urgent"),
    lambda value: value["findings"][0].update(port=True),
    lambda value: value["findings"][0].update(port=65536),
    lambda value: value["findings"][0].update(references="not-an-array"),
    lambda value: value["findings"][0].update(description=42),
    lambda value: value["findings"][0].update(cvss_score=float("nan")),
    lambda value: value["observations"][0].update(attributes=[]),
    lambda value: value["executions"][0].update(outcome="unknown"),
    lambda value: value["graph"]["edges"][0].update(target="absent"),
    lambda value: value["extensions"].update(bad=object()),
    lambda value: value.update(unknown_top_field=True),
    lambda value: value["assessment"]["reviews"][0].update(state="unknown"),
    lambda value: value["assessment"]["retests"][0].update(outcome="unknown"),
    lambda value: value["assessment"]["remediations"][0].update(status="unknown"),
    lambda value: value["assessment"].update(checks=[{"id": "check", "case_id": "case", "state": "unknown"}]),
])
def test_malformed_document_rejected(mutate, use_jsonschema):
    value = document().to_dict()
    mutate(value)
    with pytest.raises(ValueError):
        validate_document(value, use_jsonschema=use_jsonschema)


def test_schema_file_declares_version():
    schema = json.loads(SCHEMA_PATH.read_text())
    assert schema["properties"]["schema_version"]["const"] == SCHEMA_VERSION


def test_consumer_sarif_rule_index_location_fingerprint_source_retention():
    source = json.loads((HERE / "tier1.sarif.json").read_text())
    result = import_sarif(source)
    finding = result.document.data["findings"][0]
    assert finding["severity"] == "high"
    assert finding["rule_id"] == "CWE-89"
    assert finding["target"] == "src/api.py"
    assert finding["extensions"]["sarif"]["result"]["locations"][0]["physicalLocation"]["region"]["startLine"] == 17
    assert result.document.data["extensions"]["sarif"] == source
    assert result.document.to_json() == import_sarif(source).document.to_json()
    assert import_sarif(export_sarif(result.document).data).document.to_dict() == result.document.to_dict()


def test_consumer_dojo_duplicate_ids_and_extra_fields():
    source = json.loads((HERE / "defectdojo-generic.json").read_text())
    result = import_defectdojo(source)
    assert len(result.document.data["findings"]) == 2
    assert len({item["id"] for item in result.document.data["findings"]}) == 2
    assert any("Conflicting duplicate" in item for item in result.diagnostics)
    assert result.document.data["extensions"]["defectdojo"] == source
    assert import_defectdojo(export_defectdojo(result.document).data).document.to_dict() == result.document.to_dict()


def test_identical_duplicate_dojo_collapses_with_diagnostic():
    item = {"title": "Same", "severity": "Info", "unique_id_from_tool": "a"}
    result = import_defectdojo({"findings": [item, deepcopy(item)]})
    assert len(result.document.data["findings"]) == 1
    assert "Identical duplicate" in result.diagnostics[0]
    assert len(result.document.data["extensions"]["defectdojo"]["findings"]) == 2


def test_repeated_conflicting_duplicate_occurrence_is_idempotent():
    first = {"title": "One", "severity": "High", "unique_id_from_tool": "same"}
    second = {"title": "Two", "severity": "Low", "unique_id_from_tool": "same"}
    result = import_defectdojo({"findings": [first, second, deepcopy(second)]})
    assert len(result.document.data["findings"]) == 2


def test_sarif_source_fingerprint_identity_survives_message_changes():
    source = json.loads((HERE / "tier1.sarif.json").read_text())
    before = import_sarif(source).document.data["findings"][0]
    source["runs"][0]["results"][0]["message"]["text"] = "Revised explanation"
    after = import_sarif(source).document.data["findings"][0]
    assert before["id"] == after["id"]
    exported = export_sarif(import_sarif(source).document).data
    assert exported["runs"][0]["results"][0]["locations"] == after["locations"]


def test_duplicate_source_keys_rejected_without_overwriting():
    with pytest.raises(ValueError, match="Duplicate JSON"):
        CanonicalDocument.from_json('{"assets": [], "assets": [1]}')
    with pytest.raises(ValueError, match="duplicate columns"):
        import_csv("record_type,id,id\nasset,a,b")
    with pytest.raises(ValueError, match="Duplicate JSON"):
        parse('{"template-id":"one","template-id":"two"}', format="nuclei-jsonl")
    with pytest.raises(ValueError, match="conflicting preserved"):
        CanonicalDocument.from_mapping({"future": 1, "extensions": {"source_fields": {"future": 2}}})


def test_csv_subset_unknown_column_and_malformed():
    source = 'record_type,id,title,severity,target,port,vendor\nfinding,f1,"Quoted, title",high,192.0.2.1,443,keep\nasset,a1,,,192.0.2.1,,custom\n'
    result = import_csv(source)
    assert result.document.data["findings"][0]["extensions"]["csv"]["vendor"] == "keep"
    assert result.document.data["findings"][0]["port"] == 443
    assert result.document.data["assets"][0]["target"] == "192.0.2.1"
    with pytest.raises(ValueError):
        import_csv("record_type,id\nfinding,1,extra\n")
    with pytest.raises(ValueError):
        import_csv("record_type,id\nunsupported,1\n")


@pytest.mark.parametrize("importer,value", [(import_sarif, {}), (import_sarif, {"version": "2.0.0", "runs": []}), (import_defectdojo, []), (import_defectdojo, {"findings": [{}]}), (import_csv, "a,b\n1,2")])
def test_malformed_tier1(importer, value):
    with pytest.raises(ValueError):
        importer(value)


@pytest.mark.parametrize("exporter,importer,mutate", [
    (export_csv, import_csv, lambda value: value.replace("Full lifecycle", "Changed", 1)),
    (export_sarif, import_sarif, lambda value: {**value, "new_source_field": True}),
    (export_defectdojo, import_defectdojo, lambda value: {**value, "new_source_field": True}),
])
def test_conflicting_snapshot_never_silently_drops_native_edits(exporter, importer, mutate):
    with pytest.raises(ValueError):
        importer(mutate(exporter(document()).data))


@pytest.mark.parametrize("path,format,options", [
    ("canonical/nmap.xml", "nmap-xml", {}),
    ("canonical/nuclei.jsonl", "nuclei-jsonl", {}),
    ("nxc/smb_modern.txt", "netexec-log", {"arguments": ["--shares"]}),
    ("cloud/aws.json", "aws-json", {}),
    ("cloud/azure.json", "azure-json", {}),
    ("cloud/gcp.json", "gcp-json", {}),
    ("cloud/entra.json", "entra-json", {}),
    ("containers/kubernetes.json", "kubernetes-json", {}),
    ("containers/docker.json", "docker-json", {}),
    ("containers/crictl.json", "crictl-json", {}),
    ("containers/trivy.json", "trivy-json", {}),
    ("containers/grype.json", "grype-json", {}),
    ("aranum/network", "aranum-bundle", {}),
    ("aranum/posture", "aranum-bundle", {}),
])
def test_registry_existing_offline_fixtures(path, format, options):
    source = FIXTURES / path
    assert detect(source).name == format
    imported = parse(source, **options)
    assert imported.format == format
    assert imported.observations
    assert imported.extensions["source"]
    first = imported.to_document()
    first.validate(use_jsonschema=False)
    assert first.to_json() == parse(source, **options).to_document().to_json()


def test_nmap_data_transport_and_udp_identity():
    result = parse((HERE / "nmap.xml").read_text())
    endpoints = [item for item in result.observations if item.kind == "service"]
    assert {(item.port, item.protocol) for item in endpoints} == {(53, "tcp"), (53, "udp")}
    assert "future=\"preserve\"" in result.extensions["source"]


def test_bloodhound_mapping_wrapper_and_graph():
    source = Path(__file__).resolve().parents[1] / "core" / "fixtures" / "bloodhound_subset.json"
    result = parse(source)
    assert result.format == "bloodhound-json"
    assert result.graph["nodes"] and result.graph["edges"]
    assert result.to_document().to_json() == parse(source).to_document().to_json()


def test_nuclei_partial_parse_diagnostics_and_normalized_findings():
    result = parse((HERE / "nuclei.jsonl").read_text() + "\nnot json\n", format="nuclei-jsonl")
    assert len(result.findings) == 2
    assert result.diagnostics
    assert all(isinstance(item, Finding) for item in result.findings)
    assert any(item.metadata["source_record"].get("future") for item in result.findings)


def test_vulnerability_adapters_project_findings():
    assert parse(FIXTURES / "containers" / "trivy.json").findings
    assert parse(FIXTURES / "containers" / "grype.json").findings


def test_registry_invalid_unsupported_and_ambiguous():
    with pytest.raises(ValueError, match="Unsupported"):
        detect({"unrecognized": True})
    with pytest.raises(ValueError, match="Unsupported"):
        parse({}, format="not-supported")
    with pytest.raises(ValueError):
        parse("not-json", format="nuclei-jsonl")
    with pytest.raises(ValueError):
        parse({}, format="trivy-json")
    with pytest.raises(ValueError):
        parse("<nmaprun>", format="nmap-xml")
    registry = ImporterRegistry()
    registry.register(AdapterImporter("one", lambda source: True, lambda source: None))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(AdapterImporter("one", lambda source: True, lambda source: None))
    registry.register(AdapterImporter("two", lambda source: True, lambda source: None))
    with pytest.raises(ValueError, match="Ambiguous"):
        registry.detect({})
