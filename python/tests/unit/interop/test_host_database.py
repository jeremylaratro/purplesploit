import json
from pathlib import Path

import pytest

from purplesploit.core.attack_graph import AttackGraph, EdgeType, NodeType
from purplesploit.interop.host_database import (
    DATABASE_ENGINES,
    import_database_inventory,
    import_linpeas_output,
    import_linux_snapshot,
)


FIXTURES = Path(__file__).parents[2] / "fixtures" / "platform"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_linux_snapshot_emits_host_and_inventory_resources():
    result = import_linux_snapshot(load("linux.json"), run_id="linux-run")
    assert result.source_execution_id == "host-database:linux:linux-run"
    assert [item.kind for item in result.observations].count("host") == 1
    types = {item.attributes["record_type"] for item in result.observations}
    assert types >= {
        "package",
        "system_service",
        "cron",
        "systemd_timer",
        "permission",
        "credential_artifact",
    }
    credential = next(
        item for item in result.observations
        if item.attributes["record_type"] == "credential_artifact"
    )
    assert "private_key_reference" in json.dumps(credential.attributes["raw"])
    assert "PRIVATE KEY" not in json.dumps(result.to_dict())


def test_linux_snapshot_determinism_merge_and_partial_diagnostic():
    document = {"host": "linux01", "os": "Linux"}
    first = import_linux_snapshot(document)
    second = import_linux_snapshot(document)
    assert first.import_id == second.import_id
    assert first.observations[0].observation_id == second.observations[0].observation_id
    assert first.diagnostics == ["Linux snapshot contains host metadata only"]
    destination = []
    assert first.merge_into(destination) == 1
    assert first.merge_into(destination) == 0


def test_linpeas_import_strips_ansi_and_does_not_claim_exploitability():
    output = "\x1b[31mPERMISSIONS\x1b[0m\n/usr/local/bin/backup is writable\nPassword file: /opt/app/.env\n"
    result = import_linpeas_output(output, host="linux01")
    notes = [item for item in result.observations if item.kind == "note"]
    assert len(notes) == 2
    assert {item.attributes["record_type"] for item in notes} == {
        "permission",
        "credential_artifact",
    }
    assert all("severity" not in item.attributes for item in notes)
    assert "\x1b" not in json.dumps(result.to_dict())


@pytest.mark.parametrize(
    ("engine", "fixture", "port"),
    [("postgresql", "postgresql.json", 5432), ("redis", "redis.json", 6379)],
)
def test_database_inventory_normalizes_service_identity_role_and_data(engine, fixture, port):
    result = import_database_inventory(engine, load(fixture), run_id="db-run")
    service = next(item for item in result.observations if item.kind == "service")
    assert service.port == port
    assert service.protocol == "tcp"
    assert service.service == engine
    assert any(item.kind == "identity" for item in result.observations)
    assert any(item.kind == "role" for item in result.observations)
    assert any(item.attributes["record_type"] == "database" for item in result.observations)
    assert any(item.attributes["record_type"].startswith("database_") for item in result.observations)


def test_database_identity_relationships_populate_graph():
    result = import_database_inventory("postgresql", load("postgresql.json"))
    graph = AttackGraph()
    result.populate_graph(graph)
    assert graph.get_nodes_by_type(NodeType.SERVICE)
    assert graph.get_nodes_by_type(NodeType.IDENTITY)
    assert graph.get_nodes_by_type(NodeType.ROLE)
    assert graph.get_nodes_by_type(NodeType.RESOURCE)
    assert graph.get_edges_by_type(EdgeType.ASSUMES)
    assert graph.get_edges_by_type(EdgeType.CONTAINS)


def test_all_declared_database_engines_have_default_ports():
    for engine in DATABASE_ENGINES:
        result = import_database_inventory(engine, {"host": "db.example.test"})
        service = result.observations[0]
        assert 1 <= service.port <= 65535


@pytest.mark.parametrize("engine", ["oracle", "elasticsearch", ""])
def test_unsupported_database_engine_is_explicit(engine):
    with pytest.raises(ValueError, match="Unsupported database engine"):
        import_database_inventory(engine, {"host": "db.example.test"})


def test_invalid_host_document_and_port_are_rejected():
    with pytest.raises(ValueError, match="requires host"):
        import_linux_snapshot({})
    with pytest.raises(ValueError, match="between 1 and 65535"):
        import_database_inventory("postgresql", {"host": "db"}, port=70000)
