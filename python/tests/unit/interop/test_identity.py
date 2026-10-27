"""Offline identity capability contracts; sample values are synthetic."""

import base64
import builtins
from copy import deepcopy
import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from purplesploit.core.attack_graph import AttackGraph, NodeType
from purplesploit.core.execution import Observation
from purplesploit.interop.identity import (
    ADAPTER_SCHEMA_VERSION,
    MD,
    SAML,
    analyze_jwt,
    import_jwks,
    import_oauth_client,
    import_oauth_metadata,
    import_oidc_discovery,
    import_saml_assertion,
    import_saml_metadata,
)


FIXTURES = Path(__file__).parents[2] / "fixtures" / "identity"


def fixture(name):
    return (FIXTURES / name).read_text()


def b64(value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(claims=None, header=None, signature=b"sample-signature"):
    return ".".join([b64(header or {"alg": "RS256", "kid": "rsa-example"}),
                     b64(claims or {"iss": "https://id.example.test", "sub": "subject-123",
                                    "aud": ["client-a", "client-b"], "exp": 200, "nbf": 50, "iat": 75}),
                     b64(signature)])


def test_oidc_full_capabilities_and_no_fetch(monkeypatch):
    import socket

    def network_forbidden(*args, **kwargs):
        pytest.fail("offline import attempted network access")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    result = import_oidc_discovery(fixture("oidc.json"), source="oidc.json")
    assert result.status == "ok"
    assert result.inventory["issuer"] == "https://id.example.test/tenant"
    assert result.inventory["endpoints"]["jwks_uri"].endswith("/keys")
    assert result.inventory["capabilities"]["scopes_supported"] == ["openid", "profile", "email"]
    assert result.inventory["flags"]["request_parameter_supported"] is True
    assert result.observations[0].kind == "identity"
    assert result.observations[0].observed_at is None


def test_partial_oidc_retains_available_inventory():
    result = import_oidc_discovery({"issuer": "https://example.test", "scopes_supported": ["openid", 3],
                                    "token_endpoint": ["bad"]})
    assert result.status == "partial"
    assert result.inventory["capabilities"]["scopes_supported"] == ["openid"]
    assert len(result.observations) == 1
    assert {d["path"] for d in result.diagnostics} >= {"$/token_endpoint", "$/scopes_supported/1", "$/jwks_uri"}


def test_oauth_server_and_client_inventory():
    server = import_oauth_metadata({"issuer": "https://issuer.test", "registration_endpoint": "https://issuer.test/register",
                                    "grant_types_supported": ["client_credentials"],
                                    "require_pushed_authorization_requests": True})
    assert server.status == "ok"
    assert server.inventory["flags"]["require_pushed_authorization_requests"] is True
    client = import_oauth_client(fixture("oauth_client.json"), issuer="https://issuer.test")
    assert client.status == "ok"
    assert len(client.inventory["redirect_uris"]) == 2
    assert client.inventory["scopes"] == ["openid", "profile", "email"]
    assert client.inventory["token_endpoint_auth_method"] == "private_key_jwt"
    assert client.observations[0].target == "https://issuer.test"


def test_oauth_client_secret_omitted_and_jwks_diagnostics():
    result = import_oauth_client({"client_id": "one", "client_secret": "must-not-be-retained",
                                  "scope": ["openid"], "redirect_uris": "invalid",
                                  "jwks": {"keys": ["invalid", {"kty": "RSA"}]}})
    assert result.status == "partial"
    assert "must-not-be-retained" not in json.dumps(result.to_dict())
    assert result.inventory["client_secret_present"] is True
    assert any(d["path"].startswith("$/jwks/keys") for d in result.diagnostics)


@pytest.mark.parametrize("adapter", [import_oidc_discovery, import_oauth_metadata, import_oauth_client, import_jwks])
@pytest.mark.parametrize("document", ["{broken", "[]", [], None, {"a": float("nan")}, b"\xff", {1: "invalid"}])
def test_json_malformed_diagnostics(adapter, document):
    result = adapter(document)
    assert result.status == "invalid"
    assert result.diagnostics
    assert result.observations == []


def test_missing_issuer_is_a_partial_document_identity():
    result = import_oauth_metadata({"token_endpoint": "https://example.test/token"})
    assert result.status == "partial"
    assert result.observations[0].attributes["identifier"].startswith("oauth:document:")


def test_jwks_inventory_public_types_and_input_immutable():
    value = json.loads(fixture("jwks.json"))
    original = deepcopy(value)
    result = import_jwks(value, issuer="https://issuer.test")
    assert result.status == "ok"
    assert value == original
    assert [key["kty"] for key in result.inventory["keys"]] == ["RSA", "EC", "OKP"]
    assert all(key["public_fingerprint"] for key in result.inventory["keys"])
    assert all(not key["signature_verified"] for key in result.inventory["keys"])
    assert len(result.observations) == 3


def test_jwks_private_and_symmetric_material_not_retained():
    result = import_jwks({"keys": [{"kty": "oct", "k": "secret-value", "kid": "shared"},
                                     {"kty": "RSA", "n": "AQID", "e": "AQAB", "d": "private-value"}]})
    rendered = json.dumps(result.to_dict())
    assert "secret-value" not in rendered
    assert "private-value" not in rendered
    assert all(key["private_material_present"] for key in result.inventory["keys"])
    assert result.inventory["keys"][0]["public_fingerprint"] is None


def test_jwks_duplicates_partial_keys_and_malformed_array():
    result = import_jwks({"keys": [4, {"kty": "RSA", "kid": "same"},
                                     {"kty": "EC", "kid": "same", "key_ops": "verify"},
                                     {"kty": ["invalid"]}, {"kty": "new-type"}]})
    assert result.status == "partial"
    assert len(result.inventory["keys"]) == 4
    assert any("duplicate key ID" in d["message"] for d in result.diagnostics)
    assert import_jwks({"keys": {}}).status == "invalid"
    assert import_jwks({}).status == "invalid"
    assert import_jwks({"keys": []}).status == "ok"


def test_jwt_claim_analysis_never_authenticates_and_uses_explicit_time():
    token = jwt()
    result = analyze_jwt(token, reference_time=200)
    assert result.status == "ok"
    assert result.inventory["signature_status"] == "unverified"
    assert result.inventory["authenticated"] is False
    assert result.inventory["claims_verified"] is False
    assert result.inventory["claims"]["sub"] == "subject-123"
    assert result.inventory["numeric_dates"]["exp"]["state"] == "expired"
    assert result.inventory["numeric_dates"]["nbf"]["state"] == "reached"
    assert token not in json.dumps(result.to_dict())
    assert all(item["state"] == "not_evaluated" for item in analyze_jwt(token).inventory["numeric_dates"].values())


def test_jwt_unsigned_empty_signature_and_invalid_numeric_dates():
    result = analyze_jwt(jwt({"exp": True, "nbf": "later", "iat": 100}, {"alg": "none"}, b""),
                         reference_time=50)
    assert result.status == "partial"
    assert result.inventory["signature_status"] == "unsigned"
    assert result.inventory["numeric_dates"]["iat"]["state"] == "in_future"
    assert set(result.inventory["numeric_dates"]) == {"iat"}
    assert analyze_jwt(jwt(signature=b"")).status == "partial"
    assert analyze_jwt(jwt(header={"alg": "none"})).status == "partial"


@pytest.mark.parametrize("token", [None, b"\xff", "one.two", "a.b.c.d", "*.e30.c2ln", "e30.*.c2ln",
                                     b64([]) + ".e30.", "e30." + b64([]) + ".", "e30.e30.***",
                                     b64({"alg": "RS256"}) + "." + b64(b"{broken") + ".c2ln"])
def test_jwt_malformed_diagnostics(token):
    result = analyze_jwt(token)
    assert result.status == "invalid"
    assert result.diagnostics
    assert not result.observations


def test_jwt_bad_claim_types_and_header_extensions():
    result = analyze_jwt(jwt({"iss": ["bad"], "sub": 3, "aud": ["one", 2]}, {"alg": "RS256", "crit": ["custom"]}),
                         reference_time="today")
    assert result.status == "partial"
    paths = {item["path"] for item in result.diagnostics}
    assert paths >= {"$/claims/iss", "$/claims/sub", "$/claims/aud/1", "$/reference_time", "$/header/crit"}
    assert analyze_jwt(jwt(header={"alg": "RS256", "b64": False})).status == "invalid"


def test_jwe_structure_inventory_without_decryption():
    token = ".".join([b64({"alg": "dir", "enc": "A256GCM"}), "", b64(b"iv"), b64(b"ciphertext"), b64(b"tag")])
    result = analyze_jwt(token)
    assert result.status == "ok"
    assert result.inventory["format"] == "JWE"
    assert result.inventory["signature_status"] == "not_inspected_encrypted"
    assert result.inventory["encrypted"] is True
    assert "claims" not in result.inventory
    assert token not in json.dumps(result.to_dict())


def test_saml_metadata_idp_sp_roles_and_signature_scope():
    result = import_saml_metadata(fixture("metadata.xml"))
    assert result.status == "ok"
    assert result.inventory["signature_present"] is True
    idp, sp = result.inventory["entities"]
    assert idp["signature_present"] is False
    assert idp["signature_verified"] is False
    assert idp["roles"][0]["type"] == "IDPSSODescriptor"
    assert idp["roles"][0]["keys"][0]["certificate_count"] == 1
    assert idp["roles"][0]["keys"][0]["certificate_fingerprints"]
    assert sp["roles"][0]["endpoints"][0]["Location"] == "https://app.example.test/acs"
    assert sp["roles"][0]["requested_attributes"][0]["Name"] == "department"
    assert len(result.observations) == 2


def test_saml_metadata_single_entity_nested_entities_and_partial():
    root = ElementTree.fromstring(fixture("metadata.xml"))
    entity = root.find(MD + "EntityDescriptor")
    assert import_saml_metadata(ElementTree.tostring(entity)).status == "ok"
    nested = f'<EntitiesDescriptor xmlns="{MD[1:-1]}"><EntitiesDescriptor><EntityDescriptor/></EntitiesDescriptor></EntitiesDescriptor>'
    result = import_saml_metadata(nested)
    assert result.status == "partial"
    assert len(result.inventory["entities"]) == 1
    assert result.observations[0].attributes["identifier"].startswith("saml:entity:")
    assert import_saml_metadata(f'<EntitiesDescriptor xmlns="{MD[1:-1]}"/>').status == "partial"


def test_saml_assertion_claims_conditions_attributes_and_response_signature():
    result = import_saml_assertion(fixture("assertion.xml"))
    assert result.status == "ok"
    assert result.inventory["response"]["signature_present"] is True
    item = result.inventory["assertions"][0]
    assert item["signature_present"] is False
    assert item["signature_verified"] is False
    assert item["authenticated"] is False
    assert item["subject"]["name_id"] == "subject-123"
    assert item["subject"]["confirmations"][0]["data"][0]["InResponseTo"] == "request-1"
    assert item["conditions"]["audience_restrictions"] == [
        ["https://app.example.test/saml", "urn:example:api"], ["urn:example:second-restriction"]]
    assert item["conditions"]["evaluated"] is False
    assert item["conditions"]["one_time_use"] is True
    assert item["conditions"]["proxy_restrictions"][0]["attributes"]["Count"] == "1"
    attrs = item["attribute_statements"][0]
    assert len(attrs) == 3
    assert attrs[1]["values"] == ["readers", "analysts"]
    assert attrs[0]["attributes"]["Name"] == attrs[2]["attributes"]["Name"]
    assert item["authn_statements"][0]["attributes"]["SessionIndex"] == "session-123"


def test_standalone_multiple_and_encrypted_assertions():
    root = ElementTree.fromstring(fixture("assertion.xml"))
    assertion = root.find(SAML + "Assertion")
    single = import_saml_assertion(ElementTree.tostring(assertion))
    assert single.status == "ok"
    assert single.inventory["response"] is None
    root.append(deepcopy(assertion))
    multiple = import_saml_assertion(ElementTree.tostring(root))
    assert len(multiple.inventory["assertions"]) == 2
    assert len({item.observation_id for item in multiple.observations}) == 2
    encrypted = import_saml_assertion(fixture("encrypted_assertion.xml"))
    assert encrypted.status == "ok"
    assert encrypted.inventory["encryption_present"] is True
    assert encrypted.inventory["encrypted_assertion_count"] == 1
    assert encrypted.inventory["assertions"] == []
    assert encrypted.observations[0].attributes["inventory"]["decrypted"] is False


@pytest.mark.parametrize("adapter", [import_saml_metadata, import_saml_assertion])
@pytest.mark.parametrize("document", ["<broken", "<Assertion/>", "<root/>", None, b"\xff",
                                        '<!DOCTYPE x [<!ENTITY v "expanded">]><x>&v;</x>',
                                        '<!DOCTYPE x SYSTEM "file:///etc/passwd"><x/>',
                                        '<!DOCTYPE x [<!ENTITY v SYSTEM "https://example.test/xxe">]><x>&v;</x>'])
def test_xml_malformed_wrong_namespace_and_entities(adapter, document):
    result = adapter(document)
    assert result.status == "invalid"
    assert result.diagnostics
    assert result.observations == []


def test_xml_stdlib_fallback_is_also_hardened(monkeypatch):
    original = builtins.__import__

    def no_defused(name, *args, **kwargs):
        if name.startswith("defusedxml"):
            raise ImportError("dependency unavailable")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_defused)
    assert import_saml_metadata(fixture("metadata.xml")).status == "ok"
    assert import_saml_assertion(fixture("assertion.xml")).status == "ok"
    assert import_saml_metadata('<!DOCTYPE x [<!ENTITY v "expanded">]><x>&v;</x>').status == "invalid"


@pytest.mark.parametrize("adapter,document", [
    (import_oidc_discovery, fixture("oidc.json")), (import_oauth_metadata, fixture("oidc.json")),
    (import_oauth_client, fixture("oauth_client.json")), (import_jwks, fixture("jwks.json")),
    (analyze_jwt, jwt()), (import_saml_metadata, fixture("metadata.xml")),
    (import_saml_assertion, fixture("assertion.xml")),
])
def test_all_adapters_provenance_stable_ids_merge_roundtrip_and_graph(adapter, document):
    context = {"source": "offline-export", "run_id": "producer-run", "observed_at": "2026-10-26T00:00:00Z"}
    first = adapter(document, **context)
    second = adapter(document, **context)
    assert first.to_dict() == second.to_dict()
    observations = []
    assert first.merge_into(observations) == len(first.observations)
    observations[0].attributes["operator_note"] = "preserve this"
    assert second.merge_into(observations) == 0
    assert observations[0].attributes["operator_note"] == "preserve this"
    for item in first.observations:
        assert Observation.from_dict(item.to_dict()).to_dict() == item.to_dict()
        attrs = item.attributes
        assert attrs["schema_version"] == ADAPTER_SCHEMA_VERSION
        assert attrs["source_schema"] == first.source_schema
        assert attrs["source_file"] == "offline-export"
        assert attrs["run_id"] == "producer-run"
        assert attrs["import_id"] == first.import_id
        assert attrs["document_fingerprint"] == first.document_fingerprint
        assert item.source_execution_id == f"import:{first.import_id}"
        assert item.observed_at == "2026-10-26T00:00:00Z"
    distinct_run = adapter(document, **{**context, "run_id": "another-run"})
    distinct_source = adapter(document, **{**context, "source": "another-export"})
    first_ids = {o.observation_id for o in first.observations}
    assert first_ids.isdisjoint(o.observation_id for o in distinct_run.observations)
    assert first_ids.isdisjoint(o.observation_id for o in distinct_source.observations)
    graph = AttackGraph()
    assert len(first.ingest_graph(graph)) == len(first.observations)
    count = len(graph.nodes)
    second.ingest_graph(graph)
    assert len(graph.nodes) == count
    assert all(node.node_type == NodeType.IDENTITY for node in graph.nodes.values())
    assert not graph.edges
    assert all(node.metadata["source_observation_ids"] for node in graph.nodes.values())


def test_explicit_import_id_does_not_collapse_changed_evidence():
    first = import_oauth_client({"client_id": "one", "scope": "read"}, import_id="batch-1")
    second = import_oauth_client({"client_id": "one", "scope": "write"}, import_id="batch-1")
    assert first.import_id == second.import_id == "batch-1"
    assert first.observations[0].observation_id != second.observations[0].observation_id
    another_source = import_oauth_client({"client_id": "one", "scope": "read"},
                                         import_id="batch-1", source="another-file")
    assert first.observations[0].observation_id != another_source.observations[0].observation_id


def test_semantically_equal_json_key_order_is_deterministic():
    first = import_oauth_metadata('{"issuer":"https://example.test","scopes_supported":["read"]}')
    second = import_oauth_metadata('{"scopes_supported":["read"],"issuer":"https://example.test"}')
    assert first.to_dict() == second.to_dict()


def test_metadata_malformed_boolean_and_array_types():
    result = import_oauth_metadata({"issuer": "https://example.test", "scopes_supported": True,
                                    "request_parameter_supported": ["bad"],
                                    "require_pushed_authorization_requests": "true"})
    assert result.status == "partial"
    assert result.inventory["capabilities"]["scopes_supported"] == []
    assert len(result.diagnostics) == 3


def test_jwt_large_numeric_dates_and_nonascii_diagnostics():
    value = 10 ** 400
    result = analyze_jwt(jwt({"exp": value}), reference_time=value)
    assert result.status == "ok"
    assert result.inventory["numeric_dates"]["exp"]["state"] == "expired"
    assert analyze_jwt("\ud800.e30.").status == "invalid"


def test_xml_utf16_declaration_cannot_bypass_stdlib_dtd_check(monkeypatch):
    original = builtins.__import__

    def no_defused(name, *args, **kwargs):
        if name.startswith("defusedxml"):
            raise ImportError("dependency unavailable")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_defused)
    xml = '<!DOCTYPE x [<!ENTITY v "expanded">]><x>&v;</x>'
    assert import_saml_metadata(xml.encode("utf-16-le")).status == "invalid"
    assert import_saml_metadata(xml.encode("utf-16")).status == "invalid"


def test_metadata_invalid_certificate_and_foreign_endpoint_namespace():
    xml = fixture("metadata.xml").replace("AQID BA==", "***")
    xml = xml.replace('<md:SingleSignOnService Binding=', '<SingleSignOnService Binding=').replace(
        '<md:SingleLogoutService Binding=', '<SingleLogoutService Binding=')
    result = import_saml_metadata(xml)
    assert result.status == "partial"
    role = result.inventory["entities"][0]["roles"][0]
    assert role["keys"][0]["certificate_fingerprints"] == []
    assert role["endpoints"] == []
