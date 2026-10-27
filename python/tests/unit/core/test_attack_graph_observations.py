"""Offline graph projection and evidence persistence contracts."""

import csv
import io
import json
from unittest.mock import Mock

import pytest

from purplesploit.core.attack_graph import AttackGraph, EdgeType, NodeStatus, NodeType
from purplesploit.core.execution import Observation


def test_typed_and_dictionary_observations_merge_all_provenance():
    graph = AttackGraph()
    first = Observation("service", "192.0.2.10", port=445, service="smb", protocol="tcp",
                        source_execution_id="run-a", observation_id="obs-a")
    second = Observation("service", "192.0.2.10", port=445, service="smb", protocol="tcp",
                         version="3", source_execution_id="run-b", observation_id="obs-b")
    graph.ingest_observations([first, first.to_dict(), second.to_dict()])
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    service = graph.get_node_by_identifier(NodeType.SERVICE, "192.0.2.10:445")
    assert service.properties["version"] == "3"
    assert service.metadata["source_observation_ids"] == ["obs-a", "obs-b"]
    edge = next(iter(graph.edges.values()))
    assert edge.properties["source_observation_ids"] == ["obs-a", "obs-b"]
    assert edge.source_id == graph.get_node_by_identifier(NodeType.HOST, "192.0.2.10").id
    udp = graph.ingest_observation(Observation("service", "192.0.2.10", port=445, protocol="udp"))
    assert udp.id != service.id


def test_supported_identity_objects_and_relationships():
    graph = AttackGraph()
    values = [
        ("computer", {"hostname": "dc.lab", "ip": "192.0.2.1"}),
        ("domain", {"name": "LAB"}),
        ("user", {"name": "alice", "domain": "LAB", "groups": ["admins"]}),
        ("group", {"name": "admins", "domain": "LAB", "members": ["alice"]}),
        ("share", {"name": "ADMIN$"}),
        ("session", {"username": "alice", "domain": "LAB"}),
        ("credential", {"username": "alice", "domain": "LAB", "host": "192.0.2.1",
                        "authenticated": True, "admin": True}),
        ("identity", {"username": "alice", "domain": "LAB"}),
    ]
    nodes = graph.ingest_observations([Observation(kind, "192.0.2.1", attributes=attrs)
                                       for kind, attrs in values])
    assert {node.node_type.value for node in nodes} == {kind for kind, _ in values}
    assert {edge.edge_type for edge in graph.edges.values()} >= {
        EdgeType.CONTAINS, EdgeType.MEMBER_OF, EdgeType.HAS_SESSION, EdgeType.SESSION_ON,
        EdgeType.SESSION_USER, EdgeType.IDENTIFIES, EdgeType.AUTHENTICATES_TO, EdgeType.ADMIN_TO,
    }
    alice = graph.get_node_by_identifier(NodeType.USER, "LAB\\alice")
    admins = graph.get_node_by_identifier(NodeType.GROUP, "LAB\\admins")
    memberships = [edge for edge in graph.edges.values() if edge.edge_type == EdgeType.MEMBER_OF]
    assert len(memberships) == 1
    assert (memberships[0].source_id, memberships[0].target_id) == (alice.id, admins.id)
    assert len(memberships[0].properties["source_observation_ids"]) == 2
    assert graph.ingest_observation({"kind": "unknown", "target": "ignored"}) is None


def test_observation_dict_without_id_is_stable_and_does_not_claim_authentication():
    graph = AttackGraph()
    value = {"kind": "credential", "target": "192.0.2.1",
             "attributes": {"username": "alice", "host": "192.0.2.1", "authenticated": False}}
    first = graph.ingest_observation(value)
    assert graph.ingest_observation(value).id == first.id
    assert len(first.metadata["source_observation_ids"]) == 1
    assert all(edge.edge_type != EdgeType.AUTHENTICATES_TO for edge in graph.edges.values())


def test_unknown_source_status_does_not_abort_observation_ingestion():
    graph = AttackGraph()
    node = graph.ingest_observation(
        Observation("host", "192.0.2.2", attributes={"status": "producer-specific"})
    )
    assert node.status == NodeStatus.DISCOVERED


@pytest.mark.parametrize("statuses", [
    [NodeStatus.SCANNED, NodeStatus.COMPROMISED, NodeStatus.DISCOVERED],
    [NodeStatus.TARGET, NodeStatus.DOMAIN_ADMIN, NodeStatus.PIVOT],
])
def test_status_upgrades_use_evidence_order(statuses):
    graph = AttackGraph()
    for status in statuses:
        node = graph.add_host("192.0.2.1", status=status)
    assert node.status == statuses[1]
    graph.mark_compromised(node.id)
    assert node.status == statuses[1]


def test_severity_retains_highest_observed_value():
    graph = AttackGraph()
    service = graph.add_service("192.0.2.1", 80, "http")
    for severity in ["medium", "high", "critical", "low", "unknown"]:
        node = graph.add_vulnerability(service.id, "Example", severity)
    assert node.properties["severity"] == "critical"


def test_paths_are_persisted_idempotently_and_distinguish_parallel_edges():
    graph = AttackGraph()
    start = graph.add_credential("alice")
    graph.mark_compromised(start.id)
    target = graph.add_host("192.0.2.1", status=NodeStatus.TARGET)
    graph.add_edge(start.id, target.id, EdgeType.AUTHENTICATES_TO)
    graph.add_edge(start.id, target.id, EdgeType.ADMIN_TO)
    callback = Mock()
    graph.on_path_found = callback
    paths = graph.derive_attack_paths()
    assert len(paths) == 2
    assert len({path.id for path in paths}) == 2
    graph.find_attack_paths(start.id, target.id)
    assert callback.call_count == 2
    assert graph.get_statistics()["attack_paths"] == 2
    restored = AttackGraph.from_json(graph.to_json())
    assert [path.to_dict() for path in restored.attack_paths] == [path.to_dict() for path in paths]
    assert restored.find_attack_paths("missing", "also missing") == []


def test_generic_exports_preserve_json_and_csv_evidence():
    graph = AttackGraph()
    graph.ingest_observation(Observation("service", "192.0.2.1", port=80, service="http",
                                        attributes={"banner": 'a,"b"\nsecond line'}, observation_id="obs"))
    restored = AttackGraph.from_json(graph.to_json())
    assert restored.to_dict() == graph.to_dict()
    exports = graph.to_csv()
    nodes = list(csv.DictReader(io.StringIO(exports["nodes"])))
    edges = list(csv.DictReader(io.StringIO(exports["edges"])))
    service = next(node for node in nodes if node["type"] == "service")
    assert json.loads(service["properties"])["banner"] == 'a,"b"\nsecond line'
    assert json.loads(service["metadata"])["source_observation_ids"] == ["obs"]
    assert json.loads(edges[0]["properties"])["source_observation_ids"] == ["obs"]
