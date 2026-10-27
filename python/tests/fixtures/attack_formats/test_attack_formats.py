"""Golden supported-subset contracts; this suite intentionally needs no network."""

from copy import deepcopy
import json
from pathlib import Path
from uuid import UUID

import pytest

from purplesploit.core.attack_graph import AttackGraph, EdgeType
from purplesploit.core.execution import Observation
from purplesploit.core.findings import Finding
from purplesploit.interop.attack_formats import (
    export_graph_csv, export_graph_json, export_navigator_layer, export_stix_bundle,
    import_graph_csv, import_graph_json, import_navigator_layer, import_stix_bundle,
    validate_stix_bundle,
)


ROOT = Path(__file__).parent


def fixture(name):
    return json.loads((ROOT / name).read_text())


def source():
    return fixture("source.json")


def layer(data):
    return export_navigator_layer(data["findings"], executions=data["executions"],
                                  operations=data["operations"], coverage=data["coverage"])


def bundle(data):
    return export_stix_bundle(data["observations"], findings=data["findings"])


def test_navigator_golden_scores_scope_status_evidence_and_determinism():
    data = source()
    original = deepcopy(data)
    actual = layer(data)
    assert actual == fixture("navigator.golden.json")
    rows = {row["techniqueID"]: row for row in actual["techniques"]}
    assert {key: value["score"] for key, value in rows.items()} == {"T1046": 0, "T1059": 0, "T1110.001": 3}
    assert "capability:op-a" in rows["T1059"]["comment"]
    assert "not_tested" in rows["T1059"]["comment"]
    assert "evidence-a" in rows["T1110.001"]["metadata"][1]["value"]
    data["findings"].reverse()
    data["executions"].reverse()
    assert layer(data) == actual
    assert original == source()


def test_duplicate_records_and_generators_do_not_inflate_scores():
    finding = source()["findings"][0]
    actual = export_navigator_layer([finding, finding], executions=iter(source()["executions"]))
    assert actual["techniques"][-1]["score"] == 2


def test_navigator_import_retains_extensions_and_never_claims_tested():
    data = fixture("navigator.golden.json")
    data["custom_future_field"] = {"preserved": True}
    data["techniques"][0]["future"] = "row extension"
    result = import_navigator_layer(json.dumps(data), source="layer.json")
    assert result.status == "ok"
    assert result.raw == data
    assert result.extensions["custom_future_field"] == {"preserved": True}
    assert all(row["state"] == "imported" and row["tested"] is False for row in result.coverage)
    assert all(obs.confidence == "inferred" and obs.observed_at is None for obs in result.observations)
    assert result.coverage[0]["raw"]["future"] == "row extension"
    assert result.to_dict() == import_navigator_layer(data, source="layer.json").to_dict()
    observations = []
    assert result.merge_into(observations) == 3
    assert result.merge_into(observations) == 0


@pytest.mark.parametrize("document", ["{", [], {}, {"domain": "wrong", "techniques": []},
                                           {"domain": "enterprise-attack", "techniques": {}}])
def test_malformed_navigator(document):
    assert import_navigator_layer(document).status == "invalid"


def test_navigator_duplicate_invalid_and_different_tactics():
    row = {"techniqueID": "T1059", "score": 1, "tactic": "execution"}
    data = {"domain": "enterprise-attack", "techniques": [row, row, {**row, "tactic": "other"},
            {"techniqueID": "garbage"}, {"techniqueID": "T1001", "score": True},
            {"techniqueID": "T1002", "enabled": "yes"}]}
    result = import_navigator_layer(data)
    assert result.status == "partial" and len(result.coverage) == 2
    assert len(result.diagnostics) == 4 and result.raw == data


def test_stix_golden_ids_timestamps_refs_and_deterministic_order():
    data = source()
    actual = bundle(data)
    assert actual == fixture("stix.golden.json")
    assert validate_stix_bundle(actual) == []
    assert actual["type"] == "bundle"
    ids = {obj["id"] for obj in actual["objects"]}
    assert len(ids) == len(actual["objects"])
    for obj in actual["objects"]:
        assert obj["spec_version"] == "2.1"
        UUID(obj["id"].split("--")[1])
        assert all(ref in ids for ref in obj.get("object_refs", []))
        if "created" in obj:
            assert obj["created"].endswith("Z") and obj["modified"].endswith("Z")
    data["observations"].reverse()
    assert bundle(data) == actual


def test_stix_supported_roundtrip_canonical_finding_entities_and_graph_evidence():
    data = source()
    result = import_stix_bundle(bundle(data), source="bundle.json")
    assert result.status == "ok", result.diagnostics
    assert result.findings[0].to_dict() == Finding.from_dict(data["findings"][0]).to_dict()
    host = next(obs for obs in result.observations if obs.kind == "host")
    assert host.confidence == "observed" and host.target == "192.0.2.10"
    resource = next(obs for obs in result.observations if obs.kind == "resource" and obs.target == "bucket-a")
    assert resource.attributes["unknown_provider_field"] == {"retained": True}
    # A grouping SDO is an annotation of the resource, not an observed SCO.
    assert resource.confidence == "inferred"
    ownership = next(edge for edge in result.graph.edges.values() if edge.edge_type == EdgeType.OWNS)
    assert ownership.properties["raw"]["x_purplesploit"]["source_record"]["evidence_ids"] == ["evidence-a"]
    assert any(edge.edge_type == EdgeType.REFERENCES for edge in result.graph.edges.values())
    assert all(row["tested"] is False for row in result.coverage)
    assert result.to_dict() == import_stix_bundle(bundle(data), source="bundle.json").to_dict()


def test_stix_source_id_collision_produces_unique_objects_and_repeatable_import_ids():
    first = Observation("host", "192.0.2.1", observation_id="duplicate", observed_at=None)
    second = Observation("host", "192.0.2.2", observation_id="duplicate", observed_at=None)
    actual = export_stix_bundle([first, second, first])
    addresses = [obj for obj in actual["objects"] if obj["type"] == "ipv4-addr"]
    assert len(addresses) == 2
    result = import_stix_bundle(actual)
    assert len({obs.observation_id for obs in result.observations}) == len(result.observations)
    assert not any(obj["type"] == "observed-data" for obj in actual["objects"])


def test_stix_import_duplicate_unsupported_and_dangling_relationship():
    data = bundle(source())
    data["objects"].append(deepcopy(data["objects"][0]))
    data["objects"].append({"type": "x-future", "id": "x-future--00000000-0000-4000-8000-000000000001",
                            "spec_version": "2.1", "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
                            "future": "retained"})
    relation = deepcopy(next(obj for obj in data["objects"] if obj["type"] == "relationship"))
    relation["id"] = "relationship--00000000-0000-4000-8000-000000000002"
    relation["target_ref"] = "identity--00000000-0000-4000-8000-000000000003"
    data["objects"].append(relation)
    result = import_stix_bundle(data)
    assert result.status == "partial"
    assert any("duplicate" in item["message"] for item in result.diagnostics)
    assert any("unsupported" in item["message"] for item in result.diagnostics)
    assert any("endpoint" in item["message"] for item in result.diagnostics)
    assert result.raw == data


@pytest.mark.parametrize("document", ["{", [], {}, {"type": "bundle", "id": "wrong", "objects": []},
    {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": {}}])
def test_malformed_stix(document):
    assert import_stix_bundle(document).status == "invalid"


@pytest.mark.parametrize("change", [{"value": "bad"}, {"id": "ipv4-addr--bad"}, {"spec_version": "2.0"}])
def test_invalid_stix_sco_skipped_with_diagnostics(change):
    doc = export_stix_bundle([Observation("host", "192.0.2.1", observed_at=None)])
    obj = next(obj for obj in doc["objects"] if obj["type"] == "ipv4-addr")
    obj.update(change)
    result = import_stix_bundle(doc)
    assert result.status == "partial" and result.diagnostics
    assert not any(obs.kind == "host" for obs in result.observations)


def test_graph_json_and_csv_roundtrip_edge_provenance_and_metadata():
    graph = AttackGraph.from_dict(fixture("graph.json"))
    expected = export_graph_json(graph)
    assert export_graph_json(import_graph_json(expected).graph) == expected
    csv_data = export_graph_csv(graph)
    assert "source_records" in csv_data["edges"]
    result = import_graph_csv(csv_data)
    assert result.status == "ok", result.diagnostics
    assert export_graph_json(result.graph) == expected
    assert import_graph_csv(graph.to_csv()).graph.edges["edge:a"].properties == graph.edges["edge:a"].properties
    stix = export_stix_bundle(graph=graph)
    imported = import_stix_bundle(stix)
    edge = next(edge for edge in imported.graph.edges.values() if edge.edge_type == EdgeType.OWNS)
    assert edge.properties["raw"]["x_purplesploit"]["source_record"]["properties"]["source_records"] == [{"id":"edge-source","evidence_id":"evidence-a"}]


def test_graph_unknown_duplicate_and_malformed_records_are_retained():
    data = fixture("graph.json")
    data["future"] = {"retained": True}
    data["nodes"][0]["vendor"] = "extra"
    data["nodes"].extend([data["nodes"][0], {"id":"wrong","type":"future","label":"x"}])
    data["edges"].append({"id":"dangling","source":"bad","target":"bad","type":"owns"})
    result = import_graph_json(data)
    assert result.status == "partial" and len(result.diagnostics) == 3
    assert result.raw == data and result.extensions["future"] == {"retained": True}
    assert result.graph.nodes["host:a"].metadata["interop_extensions"]["vendor"] == "extra"


@pytest.mark.parametrize("data", [{"nodes": {}}, {"nodes":[None],"edges":[None]},
    {"nodes":[{"id":"a","type":"host","label":"x","metadata":[]}],"edges":[]},
    {"nodes":[],"edges":[],"attack_paths":[{"id":"a","nodes":[{}]}]}])
def test_graph_bad_shapes_do_not_crash(data):
    assert import_graph_json(data).diagnostics


def test_graph_malformed_csv_reports_invalid_cells():
    assert import_graph_csv(None).status == "invalid"
    result = import_graph_csv({"nodes":"id,type,label,properties\na,host,x,not-json\n", "edges":"", "metadata":"[]"})
    assert result.status == "partial" and len(result.diagnostics) == 2


@pytest.mark.parametrize("kind", [None, [], {}, 5, "bad type"])
def test_stix_type_shape_is_checked_before_dispatch(kind):
    data = bundle(source())
    data["objects"].append({"type": kind, "id": "identity--00000000-0000-4000-8000-000000000001"})
    result = import_stix_bundle(data)
    assert result.status == "partial" and result.diagnostics


def test_external_stix_vulnerability_and_generic_relationship_supported():
    data = export_stix_bundle([Observation("host", "192.0.2.10", observed_at=None)])
    host = next(obj for obj in data["objects"] if obj["type"] == "ipv4-addr")
    vulnerability_id = "vulnerability--00000000-0000-4000-8000-000000000001"
    data["future_bundle_extension"] = {"keep": True}
    data["objects"].extend([
        {"type":"vulnerability", "id":vulnerability_id,"spec_version":"2.1",
         "created":"2026-01-01T00:00:00Z", "modified":"2026-01-01T00:00:00Z", "name":"Fixture vulnerability",
         "external_references":[{"source_name":"cve","external_id":"CVE-2026-12345"}],"x_vendor":"retained"},
        {"type":"relationship", "id":"relationship--00000000-0000-4000-8000-000000000002", "spec_version":"2.1",
         "created":"2026-01-01T00:00:00Z", "modified":"2026-01-01T00:00:00Z", "relationship_type":"has",
         "source_ref":host["id"], "target_ref":vulnerability_id}
    ])
    result = import_stix_bundle(data)
    assert result.status == "ok", result.diagnostics
    assert result.findings[0].cve_ids == ["CVE-2026-12345"]
    assert result.findings[0].metadata["raw"]["x_vendor"] == "retained"
    assert result.relationships[0]["type"] == "references"
    assert result.relationships[0]["stix_relationship_type"] == "has"
    assert result.extensions["future_bundle_extension"] == {"keep": True}


def test_observed_data_requires_valid_times_count_and_refs():
    data = bundle(source())
    observed = next(obj for obj in data["objects"] if obj["type"] == "observed-data")
    observed.update(first_observed="wrong", number_observed=0, object_refs={})
    result = import_stix_bundle(data)
    assert result.status == "partial" and len(result.diagnostics) >= 3


def test_stix_observation_technique_reference_is_not_tested_coverage():
    observation = Observation("host", "192.0.2.10", observed_at=None,
                              attributes={"mitre_techniques":["T1046"]})
    result = import_stix_bundle(export_stix_bundle([observation]))
    assert result.status == "ok", result.diagnostics
    assert result.coverage[0]["technique_id"] == "T1046"
    assert result.coverage[0]["tested"] is False
    assert next(iter(result.graph.edges.values())).edge_type == EdgeType.REFERENCES
