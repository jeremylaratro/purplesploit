"""Recorded schema import contracts; no clients or live endpoints are used."""

import builtins
from copy import deepcopy
import json
from pathlib import Path

import pytest

from purplesploit.core.attack_graph import AttackGraph, NodeType
from purplesploit.core.execution import Observation
from purplesploit.interop.api_surface import (
    import_asyncapi, import_graphql, import_grpc_descriptor_set, import_openapi,
)


FIXTURES = Path(__file__).parents[2] / "fixtures" / "api_surface"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def test_openapi_v2_overrides_auth_body_and_duplicate_servers():
    result = import_openapi(fixture("openapi_v2.json"), source="fixture-v2.json")
    assert result.status == "ok"
    assert len(result.inventory["endpoints"]) == 2
    get, put = result.replay_plan
    assert get["method"] == "GET"
    assert get["url"] == "https://api.example.test:8443/v1/pets/{id}"
    assert get["security"] == []
    verbose = [p for p in get["parameters"] if p["name"] == "verbose"]
    assert verbose == [{"name": "verbose", "in": "query", "type": "integer"}]
    assert put["security"] == [{"key": []}]
    assert put["request_body"]["parameters"][0]["schema"] == {"$ref": "#/definitions/Pet"}
    assert {o.attributes["record_type"] for o in result.observations} >= {
        "endpoint", "parameter", "request_body", "auth_requirements", "auth_scheme",
    }
    assert all(isinstance(o, Observation) and o.confidence == "inferred" for o in result.observations)
    assert all(o.attributes["source_file"] == "fixture-v2.json" for o in result.observations)
    assert all(o.observed_at is None for o in result.observations)
    assert all(item["status"] == "not_executed" for item in result.replay_plan)


@pytest.mark.parametrize("encoding", ["mapping", "text", "bytes"])
def test_openapi_v3_preserves_body_schema_security_and_raw(encoding):
    doc = fixture("openapi_v3.json")
    original = deepcopy(doc)
    source = doc if encoding == "mapping" else json.dumps(doc)
    if encoding == "bytes":
        source = source.encode()
    result = import_openapi(source)
    assert result.status == "ok"
    endpoint = result.inventory["endpoints"][0]
    assert endpoint["url"] == "https://fixture.example.test/api/pets"
    assert endpoint["security"] == [{"oauth": ["read"], "key": []}, {"key": []}]
    assert endpoint["request_body"]["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/Pet"}
    assert result.raw == original == doc
    result.inventory["schemas"]["Pet"]["type"] = "changed"
    assert result.raw == original
    assert result.source_schema == "openapi/3.1.0"
    json.dumps(result.to_dict())


def test_deterministic_ids_merge_import_identity_and_graph_projection():
    doc = fixture("openapi_v2.json")
    first = import_openapi(doc, source="fixture")
    second = import_openapi(dict(reversed(list(doc.items()))), source="fixture")
    assert first.to_dict() == second.to_dict()
    observations = []
    assert first.merge_into(observations) == len(first.observations)
    assert second.merge_into(observations) == 0
    assert import_openapi(doc, source="other").import_id != first.import_id
    assert import_openapi(doc, import_id="run-2").import_id == "run-2"
    graph = AttackGraph()
    graph.ingest_observations(observations)
    graph.ingest_observations([item.to_dict() for item in observations])
    assert len(graph.nodes) == 2
    service = graph.get_node_by_identifier(NodeType.SERVICE, "api.example.test:8443")
    assert service.properties["schema_declared"] is True
    assert service.metadata["source_execution_ids"] == [f"import:{first.import_id}"]


def test_openapi_servers_inheritance_local_refs_and_partial_errors():
    doc = fixture("openapi_v3.json")
    doc["paths"]["/pets"]["servers"] = [{"url": "/override"}]
    operation = doc["paths"]["/pets"]["post"]
    operation["parameters"] = [{"$ref": "https://never.example/params"}, {"name": "broken"}]
    operation["requestBody"] = {"$ref": "#/missing"}
    result = import_openapi(doc, base_url="https://fixture.example.test")
    assert result.status == "partial"
    assert result.inventory["endpoints"][0]["url"] == "https://fixture.example.test/override/pets"
    assert result.inventory["endpoints"][0]["request_body"] == {"$ref": "#/missing"}
    assert any("without fetching" in item["message"] for item in result.diagnostics)
    doc["paths"]["/pets"]["post"]["servers"] = [{"url": "https://op.example.test"}]
    assert import_openapi(doc).inventory["endpoints"][0]["url"] == "https://op.example.test/pets"


@pytest.mark.parametrize("document", ["not-json", b"\xff", [], None, {"openapi": "3.0.3", "paths": []}, {"openapi": "3.0.3", "components": []}])
def test_malformed_openapi_returns_diagnostics(document):
    result = import_openapi(document)
    assert result.status in {"invalid", "partial"}
    assert result.diagnostics
    assert result.import_id
    json.dumps(result.to_dict())


def test_unknown_openapi_version_and_cyclic_parameter_ref():
    assert import_openapi({"openapi": "4.0.0"}).status == "unsupported"
    result = import_openapi({"openapi": "3.0.3", "paths": {"/pets": {"get": {
        "responses": {}, "parameters": [{"$ref": "#/parameters/loop"}],
    }}}, "parameters": {"loop": {"$ref": "#/parameters/loop"}}})
    assert result.status == "partial"
    assert any("cyclic" in d["message"] for d in result.diagnostics)


def test_graphql_types_arguments_defaults_and_duplicate_inventory():
    doc = fixture("graphql.json")
    doc["data"]["__schema"]["types"].append(deepcopy(doc["data"]["__schema"]["types"][0]))
    first = import_graphql(doc, endpoint="https://api.example.test/graphql")
    second = import_graphql(json.dumps(doc), endpoint="https://api.example.test/graphql")
    assert first.status == "ok"
    assert first.to_dict() == second.to_dict()
    assert len(first.inventory["types"]) == 5
    assert [(op["operation"], op["name"]) for op in first.inventory["operations"]] == [("query", "pet"), ("mutation", "rename")]
    argument = next(o for o in first.observations if o.attributes["record_type"] == "graphql_argument")
    assert argument.attributes["schema"]["kind"] == "NON_NULL"
    assert first.replay_plan[1]["arguments"][0]["defaultValue"] == '"unnamed"'
    assert import_graphql({"data": None, "errors": [{"message": "no schema"}]}).status == "invalid"
    partial = import_graphql({"__schema": {"types": [], "queryType": {"name": "Absent"}}})
    assert partial.status == "partial"


def test_grpc_descriptor_json_binary_nested_messages_and_streams():
    pytest.importorskip("google.protobuf")
    from google.protobuf import descriptor_pb2, json_format
    doc = fixture("grpc_descriptor_set.json")
    doc["file"].append(deepcopy(doc["file"][0]))
    result = import_grpc_descriptor_set(doc, endpoint="grpcs://rpc.example.test:443")
    descriptor = json_format.ParseDict(doc, descriptor_pb2.FileDescriptorSet())
    binary = import_grpc_descriptor_set(descriptor.SerializeToString(), endpoint="grpcs://rpc.example.test:443")
    assert result.status == "ok"
    # Wire encoding drops explicitly empty repeated fields. Keep that source
    # distinction in provenance while producing the same normalized inventory.
    assert result.inventory == binary.inventory
    assert result.to_dict() == import_grpc_descriptor_set(doc, endpoint="grpcs://rpc.example.test:443").to_dict()
    assert binary.to_dict() == import_grpc_descriptor_set(descriptor, endpoint="grpcs://rpc.example.test:443").to_dict()
    assert [m["name"] for m in result.inventory["messages"]] == ["fixture.Reply", "fixture.Request", "fixture.Request.Metadata"]
    assert len(result.inventory["services"]) == 1
    assert result.replay_plan[1]["server_streaming"] is True
    assert result.replay_plan[0]["path"] == "/fixture.Pets/Get"
    assert result.inventory["enums"][0]["name"] == "fixture.State"
    assert import_grpc_descriptor_set(b"\xff").status == "invalid"
    assert import_grpc_descriptor_set({"unknown": []}).status == "invalid"
    assert import_grpc_descriptor_set({}).status == "partial"


def test_grpc_missing_optional_protobuf_is_structured(monkeypatch):
    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name.startswith("google.protobuf"):
            raise ImportError("fixture: optional dependency missing")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    result = import_grpc_descriptor_set(b"fixture")
    assert result.status == "unsupported"
    assert result.observations == []
    assert "not installed" in result.diagnostics[0]["message"]
    assert result.raw == {"encoding": "hex", "data": b"fixture".hex()}
    assert result.import_id


@pytest.mark.parametrize("version", ["v2", "v3"])
def test_asyncapi_websocket_inventory_message_schema_and_no_duplicate_messages(version):
    doc = fixture(f"asyncapi_{version}.json")
    result = import_asyncapi(doc, source="socket-fixture")
    assert result.status == "ok"
    assert len(result.inventory["messages"]) == 1
    assert len(result.replay_plan) == 1
    assert result.replay_plan[0]["url"] == "wss://socket.example.test/ws/pets/{id}"
    assert result.inventory["messages"][0]["payload"]["type"] == "object"
    assert result.to_dict() == import_asyncapi(json.dumps(doc).encode(), source="socket-fixture").to_dict()
    assert any(o.attributes["record_type"] == "websocket_message" for o in result.observations)


def test_asyncapi_partial_and_non_websocket_protocols():
    assert import_asyncapi({"asyncapi": "1.0"}).status == "unsupported"
    doc = fixture("asyncapi_v2.json")
    doc["servers"]["fixture"]["protocol"] = "mqtt"
    result = import_asyncapi(doc)
    assert not result.replay_plan
    assert result.inventory["messages"]
    doc["channels"]["pets/{id}"]["servers"] = ["missing"]
    assert import_asyncapi(doc).status == "partial"
    assert import_asyncapi({"asyncapi": "3.0.0", "channels": None}).status == "partial"
