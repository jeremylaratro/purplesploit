import json
from pathlib import Path

import pytest

from purplesploit.core.attack_graph import AttackGraph, EdgeType, NodeType
from purplesploit.interop.cloud import (
    CLOUD_SCHEMA_VERSION,
    import_aws_inventory,
    import_azure_inventory,
    import_entra_inventory,
    import_gcp_inventory,
)


FIXTURES = Path(__file__).parents[2] / "fixtures" / "cloud"


@pytest.mark.parametrize(
    ("provider", "importer"),
    [
        ("aws", import_aws_inventory),
        ("azure", import_azure_inventory),
        ("gcp", import_gcp_inventory),
        ("entra", import_entra_inventory),
    ],
)
def test_cloud_fixture_import_is_deterministic_and_provenanced(provider, importer):
    first = importer(FIXTURES / f"{provider}.json", run_id="run-7")
    second = importer(json.loads((FIXTURES / f"{provider}.json").read_text()), run_id="run-7")

    assert first.provider == provider
    assert first.schema_version == CLOUD_SCHEMA_VERSION
    assert first.import_id == second.import_id
    assert [item.observation_id for item in first.observations] == [
        item.observation_id for item in second.observations
    ]
    assert first.observations
    for observation in first.observations:
        assert observation.source_execution_id == f"cloud:{provider}:run-7"
        assert observation.attributes["provider"] == provider
        assert observation.source_schema == CLOUD_SCHEMA_VERSION
        assert observation.raw


def test_aws_inventory_preserves_permission_exposure_and_ownership_relations():
    result = import_aws_inventory(FIXTURES / "aws.json")
    user = next(item for item in result.observations if item.attributes["record_type"] == "iam_user")
    bucket = next(item for item in result.observations if item.attributes["record_type"] == "resource")

    assert {item["type"] for item in user.attributes["relationships"]} >= {
        "member_of",
        "has_permission",
        "owns",
    }
    assert bucket.attributes["public"] is True
    assert {item["type"] for item in bucket.attributes["relationships"]} >= {
        "owns",
        "exposed_to",
        "applies_to",
    }


def test_azure_assignment_projects_principal_role_and_scope():
    result = import_azure_inventory(FIXTURES / "azure.json")
    assignment = next(
        item for item in result.observations if item.attributes["record_type"] == "role_assignment"
    )
    assert assignment.target == "sp-1"
    assert assignment.attributes["assignment"] is True
    assert {(item["type"], item["target_kind"]) for item in assignment.attributes["relationships"]} == {
        ("assumes", "role"),
        ("has_permission", "resource"),
    }


def test_gcp_bindings_create_explicit_member_to_role_relationships():
    result = import_gcp_inventory(FIXTURES / "gcp.json")
    member = next(item for item in result.observations if item.attributes["record_type"] == "iam_member")
    assert member.target.startswith("serviceAccount:")
    assert member.attributes["relationships"][0]["target"] == "roles/viewer"


def test_entra_inventory_preserves_membership_roles_and_consents():
    result = import_entra_inventory(FIXTURES / "entra.json")
    user = next(item for item in result.observations if item.attributes["record_type"] == "user")
    grant = next(
        item for item in result.observations
        if item.attributes["record_type"] == "oauth2_permission_grant"
    )
    assert any(item["type"] == "member_of" for item in user.attributes["relationships"])
    assert grant.attributes["scopes"] == ["User.Read", "Directory.Read.All"]


def test_cloud_observations_populate_extended_attack_graph():
    result = import_aws_inventory(FIXTURES / "aws.json")
    graph = AttackGraph()
    assert result.populate_graph(graph) == len(result.observations)
    assert graph.get_nodes_by_type(NodeType.TENANT)
    assert graph.get_nodes_by_type(NodeType.IDENTITY)
    assert graph.get_nodes_by_type(NodeType.ROLE)
    assert graph.get_nodes_by_type(NodeType.POLICY)
    assert graph.get_nodes_by_type(NodeType.RESOURCE)
    assert graph.get_edges_by_type(EdgeType.HAS_PERMISSION)
    assert graph.get_edges_by_type(EdgeType.EXPOSED_TO)
    assert graph.get_edges_by_type(EdgeType.OWNS)


def test_merge_is_idempotent_and_partial_inventory_is_diagnostic():
    result = import_gcp_inventory({})
    assert result.observations == []
    assert result.diagnostics == ["No recognized GCP inventory records"]
    observations = []
    populated = import_entra_inventory(FIXTURES / "entra.json")
    assert populated.merge_into(observations) == len(populated.observations)
    assert populated.merge_into(observations) == 0


def test_non_object_inventory_file_is_rejected(tmp_path):
    path = tmp_path / "inventory.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain an object"):
        import_aws_inventory(path)
