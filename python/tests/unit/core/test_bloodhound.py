"""Synthetic BloodHound legacy/CE collector fixtures; no live AD dependency."""

import json
from pathlib import Path

import pytest

from purplesploit.core.attack_graph import AttackGraph, NodeType
from purplesploit.interop.bloodhound import export_bloodhound, import_bloodhound


FIXTURE = Path(__file__).parent / "fixtures" / "bloodhound_subset.json"


def relationships(graph):
    return sorted((graph.nodes[edge.source_id].metadata["raw_source_id"], edge.edge_type.value,
                   graph.nodes[edge.target_id].metadata["raw_source_id"])
                  for edge in graph.edges.values())


def test_golden_subset_relationship_directions_and_raw_identity():
    graph = import_bloodhound(FIXTURE)
    assert len(graph.nodes) == 7
    assert relationships(graph) == [
        ("S-LAB-1001", "admin_to", "S-LAB-2002"),
        ("S-LAB-1001", "member_of", "S-LAB-513"),
        ("S-LAB-2001", "has_session", "S-LAB-1001"),
        ("S-LAB-512", "admin_to", "S-LAB-2001"),
        ("S-LAB-513", "member_of", "S-LAB-512"),
        ("S-OTHER", "trusted_by", "S-LAB"),
    ]
    alice = next(node for node in graph.nodes.values() if node.metadata["raw_source_id"] == "S-LAB-1001")
    assert alice.metadata["raw_source_type"] == "User"
    assert alice.label == "ALICE@LAB.EXAMPLE"
    assert all(node.metadata["source_observation_ids"] for node in graph.nodes.values())
    assert all(edge.properties["source_observation_ids"] for edge in graph.edges.values())


def test_duplicate_import_and_unknown_records_survive_generic_roundtrip():
    graph = import_bloodhound(FIXTURE)
    before = graph.to_dict()
    assert import_bloodhound(FIXTURE, graph=graph) is graph
    assert graph.to_dict() == before
    unknown = graph.metadata["bloodhound"]["unsupported_records"]
    assert unknown[0]["record"]["ObjectIdentifier"] == "unknown"
    assert AttackGraph.from_json(graph.to_json()).metadata == graph.metadata


@pytest.mark.parametrize("version", [5, 6])
def test_supported_bloodhound_export_roundtrip(version):
    graph = import_bloodhound(FIXTURE)
    graph.add_host("192.0.2.1")
    exports = graph.to_bloodhound(version=version)
    assert exports["users"]["meta"] == {"type": "users", "count": 1, "version": version}
    assert "192.0.2.1" not in json.dumps(exports)
    restored = import_bloodhound(json.dumps(exports))
    original = import_bloodhound(FIXTURE)
    assert relationships(restored) == relationships(original)
    assert sorted((node.metadata["raw_source_id"], node.node_type.value, node.label)
                  for node in restored.nodes.values()) == sorted(
                      (node.metadata["raw_source_id"], node.node_type.value, node.label)
                      for node in original.nodes.values())


def test_later_record_resolves_placeholder_and_preserves_membership_evidence():
    graph = import_bloodhound({"meta": {"type": "groups"}, "groups": [
        {"ObjectIdentifier": "group", "Properties": {"name": "Admins"},
         "Members": [{"ObjectIdentifier": "user", "ObjectType": "User"},
                     {"ObjectIdentifier": "alien", "ObjectType": "Unknown"}]},
    ]})
    user = next(node for node in graph.nodes.values() if node.node_type == NodeType.USER)
    assert user.metadata["placeholder"] is True
    provenance = list(user.metadata["source_observation_ids"])
    import_bloodhound({"meta": {"type": "users"}, "data": [
        {"ObjectIdentifier": "user", "Properties": {"name": "Alice"}},
    ]}, graph)
    assert user.metadata["placeholder"] is False
    assert user.label == "Alice"
    assert len(user.metadata["source_observation_ids"]) == 2
    assert all(item in user.metadata["source_observation_ids"] for item in provenance)
    assert len(graph.nodes) == 2
    assert graph.metadata["bloodhound"]["unsupported_records"][0]["type"] == "reference"


@pytest.mark.parametrize("direction,expected", [
    ("Inbound", [("a", "trusted_by", "b")]),
    (2, [("b", "trusted_by", "a")]),
    ("Bidirectional", [("a", "trusted_by", "b"), ("b", "trusted_by", "a")]),
    ("Unknown", []),
])
def test_trust_direction_variants(direction, expected):
    graph = import_bloodhound({"domains": [
        {"ObjectIdentifier": "a", "Trusts": [{"TargetDomainSid": "b", "TrustDirection": direction}]},
    ]})
    assert relationships(graph) == expected


def test_uncollected_data_is_not_claimed_collected_and_versions_are_explicit():
    graph = import_bloodhound({"computers": [{"ObjectIdentifier": "computer"}]})
    computer = export_bloodhound(graph)["computers"]["data"][0]
    assert computer["Sessions"]["Collected"] is False
    assert computer["LocalAdmins"]["Collected"] is False
    with pytest.raises(ValueError):
        export_bloodhound(graph, version=99)


def test_directory_fixture_boundary(tmp_path):
    source = json.loads(FIXTURE.read_text())
    # Only the offline filesystem boundary is substituted; graph logic is real.
    (tmp_path / "users.json").write_text(json.dumps(source["users"]))
    graph = import_bloodhound(tmp_path)
    assert len(graph.get_nodes_by_type(NodeType.USER)) == 1
