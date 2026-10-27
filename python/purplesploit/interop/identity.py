"""Deterministic, offline OIDC/OAuth/JWT/JWKS and SAML inventories.

These adapters inspect supplied documents, never retrieve URLs or authenticate.
An observation records what a document says; token and assertion claims are not
authenticated identities. JWT signatures and XML signatures are not verified.
Input tokens, private JWK material, and client secrets are not retained.
"""

import base64
import binascii
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
import math
import re
from typing import Any, Mapping
from uuid import NAMESPACE_URL, uuid5
from xml.etree import ElementTree

from purplesploit.core.execution import Observation


ADAPTER_SCHEMA_VERSION = "purplesploit/identity/1"
MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
SAML = "{urn:oasis:names:tc:SAML:2.0:assertion}"
SAMLP = "{urn:oasis:names:tc:SAML:2.0:protocol}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"
XENC = "{http://www.w3.org/2001/04/xmlenc#}"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def _digest(value):
    return sha256(_canonical(value).encode()).hexdigest()


@dataclass
class IdentityImportResult:
    """Serializable inventory with explicit diagnostics and stable observations.

    Absent producer time remains None. IDs include source, document fingerprint,
    optional import ID and producer run ID, so reimporting one snapshot is stable
    while distinct sources/runs retain distinct evidence occurrences.
    """

    protocol: str
    source: str
    source_schema: str
    import_id: str = ""
    run_id: str | None = None
    observed_at: str | None = None
    document_fingerprint: str = ""
    schema_version: str = ADAPTER_SCHEMA_VERSION
    status: str = "ok"
    inventory: dict[str, Any] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    diagnostics: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    def diagnose(self, path, message, *, invalid=False):
        self.diagnostics.append({"path": path, "message": message})
        if invalid:
            self.status = "invalid"
        elif self.status == "ok":
            self.status = "partial"

    def merge_into(self, observations):
        """Append unseen occurrences, preserving existing objects and their edits."""
        known = {item.observation_id for item in observations}
        added = 0
        for item in self.observations:
            if item.observation_id not in known:
                observations.append(item)
                known.add(item.observation_id)
                added += 1
        return added

    def ingest_graph(self, graph):
        """Project supported kinds using the graph's existing evidence semantics.

        No membership, federation, permission or authenticated-access relation is
        inferred from unsigned/unverified claims or advertised metadata.
        """
        return graph.ingest_observations(self.observations)


def _result(protocol, schema, *, source="memory", import_id=None, run_id=None, observed_at=None):
    return IdentityImportResult(protocol, str(source), schema, import_id or "", run_id,
                                observed_at)


def _fingerprint(result, document):
    result.document_fingerprint = _digest(document)
    result.import_id = result.import_id or str(uuid5(NAMESPACE_URL, _canonical([
        result.protocol, result.source, result.run_id, result.document_fingerprint,
    ])))


def _json(document, result):
    try:
        value = json.loads(document) if isinstance(document, (str, bytes, bytearray)) else deepcopy(document)
        if not isinstance(value, Mapping):
            raise ValueError("document must be a JSON object")
        value = dict(value)
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        _fingerprint(result, value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        result.diagnose("$", "invalid JSON object", invalid=True)
        return None


def _emit(result, record_type, identifier, inventory, *, kind="identity", target=None):
    attrs = {
        "source_tool": "identity-import", "source_file": result.source,
        "source_schema": result.source_schema, "schema_version": result.schema_version,
        "import_id": result.import_id, "run_id": result.run_id,
        "document_fingerprint": result.document_fingerprint,
        "record_type": record_type, "identifier": identifier,
        "name": inventory.get("name") or identifier, "inventory": deepcopy(inventory),
        "evidence_type": "document_claim", "authenticated": False,
    }
    observation_id = str(uuid5(NAMESPACE_URL, _canonical([
        result.schema_version, result.source_schema, result.source, result.import_id, result.run_id,
        result.document_fingerprint, record_type, identifier, inventory,
    ])))
    if all(item.observation_id != observation_id for item in result.observations):
        result.observations.append(Observation(
            kind=kind, target=str(target or identifier), attributes=attrs,
            source_execution_id=f"import:{result.import_id}", module_path="interop/identity",
            operation_name=f"Import {result.protocol}", observed_at=result.observed_at,
            observation_id=observation_id,
        ))


def _strings(value, result, path):
    if not isinstance(value, list):
        result.diagnose(path, "expected an array of strings")
        return []
    items = []
    for index, item in enumerate(value):
        if isinstance(item, str):
            items.append(item)
        else:
            result.diagnose(f"{path}/{index}", "expected a string")
    return items


def _text(value, result, path, *, required=False):
    if isinstance(value, str) and value:
        return value
    if required or value is not None:
        result.diagnose(path, "expected a nonempty string")
    return None


def _authorization_metadata(document, protocol, schema, context):
    result = _result(protocol, schema, **context)
    value = _json(document, result)
    if value is None:
        return result
    issuer = _text(value.get("issuer"), result, "$/issuer", required=True)
    inventory = {"issuer": issuer, "endpoints": {}, "capabilities": {}, "flags": {}}
    for key, item in sorted(value.items()):
        if key.endswith("_endpoint") or key == "jwks_uri":
            text = _text(item, result, f"$/{key}")
            if text:
                inventory["endpoints"][key] = text
        elif key in {"require_pushed_authorization_requests", "require_request_uri_registration",
                     "claims_parameter_supported", "request_parameter_supported",
                     "request_uri_parameter_supported", "authorization_response_iss_parameter_supported",
                     "tls_client_certificate_bound_access_tokens"}:
            if isinstance(item, bool):
                inventory["flags"][key] = item
            else:
                result.diagnose(f"$/{key}", "expected a boolean")
        elif key.endswith("_supported"):
            inventory["capabilities"][key] = _strings(item, result, f"$/{key}")
    result.inventory = inventory
    identifier = f"{protocol}:issuer:{issuer}" if issuer else f"{protocol}:document:{result.document_fingerprint}"
    _emit(result, "authorization_server", identifier, inventory, target=issuer)
    if protocol == "oidc":
        for required in ("jwks_uri", "response_types_supported", "subject_types_supported",
                         "id_token_signing_alg_values_supported"):
            if required not in value:
                result.diagnose(f"$/{required}", "OIDC discovery field is absent")
    return result


def import_oidc_discovery(document, *, source="memory", import_id=None, run_id=None, observed_at=None):
    """Inventory supplied OpenID Provider metadata without following its URLs."""
    return _authorization_metadata(document, "oidc", "openid-connect-discovery/1.0", {
        "source": source, "import_id": import_id, "run_id": run_id, "observed_at": observed_at,
    })


def import_oauth_metadata(document, *, source="memory", import_id=None, run_id=None, observed_at=None):
    """Inventory RFC 8414 authorization-server capabilities and endpoints."""
    return _authorization_metadata(document, "oauth", "oauth-authorization-server/RFC8414", {
        "source": source, "import_id": import_id, "run_id": run_id, "observed_at": observed_at,
    })


def import_oauth_client(document, *, issuer=None, source="memory", import_id=None,
                        run_id=None, observed_at=None):
    """Inventory registration metadata, redirects, grants and requested scopes."""
    result = _result("oauth-client", "oauth-client-registration/RFC7591", source=source,
                     import_id=import_id, run_id=run_id, observed_at=observed_at)
    value = _json(document, result)
    if value is None:
        return result
    client_id = _text(value.get("client_id"), result, "$/client_id", required=True)
    inventory = {"client_id": client_id, "issuer": issuer,
                 "client_secret_present": bool(value.get("client_secret"))}
    for key in ("client_name", "application_type", "token_endpoint_auth_method", "jwks_uri"):
        if key in value:
            inventory[key] = _text(value[key], result, f"$/{key}")
    for key in ("redirect_uris", "post_logout_redirect_uris", "grant_types", "response_types",
                "contacts"):
        if key in value:
            inventory[key] = _strings(value[key], result, f"$/{key}")
    scope = value.get("scope", "")
    if isinstance(scope, str):
        inventory["scopes"] = scope.split()
    else:
        result.diagnose("$/scope", "expected a space-delimited string")
        inventory["scopes"] = []
    if "jwks" in value:
        keys = import_jwks(value["jwks"], source=source, import_id=import_id, run_id=run_id)
        inventory["jwks"] = keys.inventory
        for diagnostic in keys.diagnostics:
            result.diagnose("$/jwks" + diagnostic["path"][1:], diagnostic["message"])
    result.inventory = inventory
    identifier = "oauth:client:" + _digest([issuer, client_id or result.document_fingerprint])
    _emit(result, "oauth_client", identifier, inventory, target=issuer or client_id)
    return result


def import_jwks(document, *, issuer=None, source="memory", import_id=None, run_id=None,
                observed_at=None):
    """Inventory public JWK parameters and key uses; omit private/symmetric material."""
    result = _result("jwks", "json-web-key-set/RFC7517", source=source,
                     import_id=import_id, run_id=run_id, observed_at=observed_at)
    value = _json(document, result)
    if value is None:
        return result
    result.inventory = {"issuer": issuer, "keys": []}
    keys = value.get("keys")
    if not isinstance(keys, list):
        result.diagnose("$/keys", "expected a keys array", invalid=True)
        return result
    seen_kids = set()
    public = {"kty", "kid", "use", "alg", "n", "e", "crv", "x", "y", "x5u", "x5t", "x5t#S256"}
    for index, key in enumerate(keys):
        path = f"$/keys/{index}"
        if not isinstance(key, dict):
            result.diagnose(path, "expected a JWK object")
            continue
        kty = _text(key.get("kty"), result, path + "/kty", required=True)
        item = {}
        for name in sorted(public & key.keys()):
            text = _text(key[name], result, path + "/" + name)
            if text is not None:
                item[name] = text
        for name in ("key_ops", "x5c"):
            if name in key:
                item[name] = _strings(key[name], result, path + "/" + name)
        item["private_material_present"] = bool({"d", "p", "q", "dp", "dq", "qi", "oth", "k"} & key.keys())
        item["signature_verified"] = False
        for name in {"RSA": ("n", "e"), "EC": ("crv", "x", "y"), "OKP": ("crv", "x"),
                     "oct": ("k",)}.get(kty, ()):
            if not isinstance(key.get(name), str) or not key[name]:
                result.diagnose(path + "/" + name, "key parameter is absent or malformed")
        if kty and kty not in {"RSA", "EC", "OKP", "oct"}:
            result.diagnose(path + "/kty", "unrecognized key type retained")
        kid = item.get("kid")
        if kid is not None and kid in seen_kids:
            result.diagnose(path + "/kid", "duplicate key ID; selection is ambiguous")
        seen_kids.add(kid)
        # Fingerprint excludes private key material and is not a claim of trust.
        material = {name: item[name] for name in ("kty", "n", "e", "crv", "x", "y") if name in item}
        item["public_fingerprint"] = _digest(material) if len(material) > 1 else None
        result.inventory["keys"].append(item)
        identifier = f"jwks:key:{_digest([issuer, index, item])}"
        _emit(result, "jwk", identifier, item, target=issuer)
    return result


def _b64(segment):
    if not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", segment):
        raise ValueError("not base64url")
    return base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)


def _jwt_object(segment):
    value = json.loads(_b64(segment).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JWT component must be an object")
    _canonical(value)
    return value


def _numeric_date(value):
    return ((isinstance(value, int) and not isinstance(value, bool))
            or (isinstance(value, float) and math.isfinite(value)))


def analyze_jwt(token, *, source="memory", import_id=None, run_id=None, observed_at=None,
                reference_time=None):
    """Decode compact JWS claims or inventory compact JWE structure offline.

    Signatures are always unverified. NumericDates are compared only with an
    explicit numeric reference_time; no wall clock or authentication is implied.
    Five-part encrypted tokens expose their protected header and lengths only.
    """
    result = _result("jwt", "json-web-token/RFC7519", source=source,
                     import_id=import_id, run_id=run_id, observed_at=observed_at)
    if isinstance(token, bytes):
        try:
            token = token.decode("ascii")
        except UnicodeError:
            token = None
    if not isinstance(token, str):
        result.diagnose("$", "expected an ASCII compact token", invalid=True)
        return result
    try:
        token.encode("ascii")
    except UnicodeError:
        result.diagnose("$", "expected an ASCII compact token", invalid=True)
        return result
    _fingerprint(result, token)
    segments = token.split(".")
    if len(segments) not in {3, 5}:
        result.diagnose("$", "compact token requires three JWS or five JWE segments", invalid=True)
        return result
    try:
        header = _jwt_object(segments[0])
        decoded = [_b64(segment) for segment in segments[1:]]
    except (ValueError, TypeError, binascii.Error, UnicodeError, RecursionError):
        result.diagnose("$", "malformed base64url or protected-header JSON", invalid=True)
        return result
    inventory = {"format": "JWS" if len(segments) == 3 else "JWE", "header": header,
                 "segment_lengths": [len(segment) for segment in segments],
                 "signature_status": "unverified", "authenticated": False,
                 "claims_verified": False}
    result.inventory = inventory
    if not _text(header.get("alg"), result, "$/header/alg", required=True):
        inventory["signature_status"] = "unknown_algorithm"
    if len(segments) == 5:
        inventory["encrypted"] = True
        inventory["signature_status"] = "not_inspected_encrypted"
        _text(header.get("enc"), result, "$/header/enc", required=True)
        for index in (2, 3, 4):
            if not decoded[index - 1]:
                result.diagnose(f"$/segments/{index}", "required JWE segment is empty")
    else:
        try:
            claims = _jwt_object(segments[1])
        except (ValueError, TypeError, binascii.Error, UnicodeError, RecursionError):
            result.diagnose("$/claims", "malformed claims JSON object", invalid=True)
            return result
        inventory.update({"claims": claims, "signature_present": bool(segments[2]),
                          "numeric_dates": {}, "encrypted": False})
        if header.get("alg") == "none":
            inventory["signature_status"] = "unsigned"
            if segments[2]:
                result.diagnose("$/signature", "alg none token contains a signature segment")
        elif not segments[2]:
            result.diagnose("$/signature", "signed algorithm has an empty signature")
        if header.get("b64") is False:
            result.diagnose("$/header/b64", "unencoded JWS payloads are unsupported", invalid=True)
            return result
        if "crit" in header:
            result.diagnose("$/header/crit", "critical extensions are inventoried, not processed")
        for name in ("iss", "sub", "jti"):
            if name in claims:
                _text(claims[name], result, f"$/claims/{name}")
        if "aud" in claims:
            audience = claims["aud"]
            if not isinstance(audience, str):
                _strings(audience, result, "$/claims/aud")
        valid_reference = _numeric_date(reference_time)
        if reference_time is not None and not valid_reference:
            result.diagnose("$/reference_time", "expected a finite NumericDate")
        for name in ("exp", "nbf", "iat"):
            if name not in claims:
                continue
            number = claims[name]
            if not _numeric_date(number):
                result.diagnose(f"$/claims/{name}", "expected a finite NumericDate")
                continue
            state = "not_evaluated"
            if valid_reference:
                state = ("expired" if reference_time >= number else "not_expired") if name == "exp" else (
                    "in_future" if reference_time < number else "reached")
            inventory["numeric_dates"][name] = {"value": number, "state": state}
    identifier = f"jwt:document:{result.document_fingerprint}"
    _emit(result, "token_structure", identifier, inventory)
    return result


def _xml(document, result):
    try:
        text = document.decode("utf-8-sig") if isinstance(document, bytes) else document
        if not isinstance(text, str):
            raise ValueError("expected XML text or UTF-8 bytes")
        # Reject declarations before either parser; also covers stdlib fallback.
        if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
            raise ValueError("DTD/entity declarations are unsupported")
        try:
            from defusedxml.ElementTree import fromstring
        except ImportError:
            root = ElementTree.fromstring(text)
        else:
            root = fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        _fingerprint(result, text)
        return root
    except (ValueError, TypeError, UnicodeError, ElementTree.ParseError):
        result.diagnose("$", "invalid XML or unsupported DTD/entity declaration", invalid=True)
        return None


def _element_text(element):
    return "".join(element.itertext()).strip() if element is not None else None


def _signed(element):
    return element.find(DS + "Signature") is not None


def import_saml_metadata(document, *, source="memory", import_id=None, run_id=None,
                         observed_at=None):
    """Inventory SAML 2.0 IdP/SP entities, endpoints, keys and requested attributes."""
    result = _result("saml-metadata", "saml-metadata/2.0", source=source,
                     import_id=import_id, run_id=run_id, observed_at=observed_at)
    root = _xml(document, result)
    if root is None:
        return result
    if root.tag not in {MD + "EntityDescriptor", MD + "EntitiesDescriptor"}:
        result.diagnose("$", "expected a SAML 2.0 metadata root", invalid=True)
        return result
    result.inventory = {"entities": [], "signature_present": _signed(root),
                        "signature_verified": False}
    entities = [root] if root.tag == MD + "EntityDescriptor" else list(root.iter(MD + "EntityDescriptor"))
    if not entities:
        result.diagnose("$", "metadata contains no EntityDescriptor")
    for index, entity in enumerate(entities):
        path = f"$/entities/{index}"
        entity_id = _text(entity.get("entityID"), result, path + "/entityID", required=True)
        item = {"entity_id": entity_id, "valid_until": entity.get("validUntil"),
                "cache_duration": entity.get("cacheDuration"), "roles": [],
                "signature_present": _signed(entity), "signature_verified": False}
        for role_name in ("IDPSSODescriptor", "SPSSODescriptor"):
            for role in entity.findall(MD + role_name):
                role_item = {"type": role_name, "attributes": dict(role.attrib),
                             "endpoints": [], "name_id_formats": [], "keys": [],
                             "requested_attributes": []}
                for child in role:
                    name = child.tag.removeprefix(MD)
                    if child.tag in {MD + endpoint_name for endpoint_name in (
                            "SingleSignOnService", "SingleLogoutService", "AssertionConsumerService",
                            "ArtifactResolutionService", "ManageNameIDService", "NameIDMappingService")}:
                        endpoint = {"type": name, **child.attrib}
                        if not child.get("Location"):
                            result.diagnose(path + "/" + name, "endpoint Location is absent")
                        role_item["endpoints"].append(endpoint)
                    elif child.tag == MD + "NameIDFormat":
                        role_item["name_id_formats"].append(_element_text(child))
                    elif child.tag == MD + "KeyDescriptor":
                        certificates = [_element_text(cert) for cert in child.iter(DS + "X509Certificate")]
                        fingerprints = []
                        for certificate in certificates:
                            try:
                                der = base64.b64decode(re.sub(r"\s", "", certificate), validate=True)
                                if not der:
                                    raise ValueError("empty certificate")
                                fingerprints.append(sha256(der).hexdigest())
                            except (ValueError, binascii.Error):
                                result.diagnose(path + "/KeyDescriptor", "malformed base64 X509Certificate")
                        role_item["keys"].append({"use": child.get("use"),
                                                 "certificate_count": len(certificates),
                                                 "certificate_fingerprints": fingerprints,
                                                 "key_info_present": child.find(DS + "KeyInfo") is not None})
                    elif child.tag == MD + "AttributeConsumingService":
                        role_item["requested_attributes"].extend(
                            {**attr.attrib, "values": [_element_text(v) for v in attr.findall(SAML + "AttributeValue")]}
                            for attr in child.findall(MD + "RequestedAttribute"))
                item["roles"].append(role_item)
        if not item["roles"]:
            result.diagnose(path, "entity has no supported IdP/SP role")
        result.inventory["entities"].append(item)
        identifier = f"saml:entity:{entity_id}" if entity_id else f"saml:entity:{result.document_fingerprint}:{index}"
        _emit(result, "saml_entity", identifier, item, target=entity_id)
    return result


def import_saml_assertion(document, *, source="memory", import_id=None, run_id=None,
                          observed_at=None):
    """Inspect assertions/responses without signature validation or decryption.

    Response and assertion signatures are recorded separately. Audiences retain
    restriction grouping, and duplicate attributes are preserved as occurrences.
    Conditions are structural inventory only, never an acceptance decision.
    """
    result = _result("saml-assertion", "saml-assertion/2.0", source=source,
                     import_id=import_id, run_id=run_id, observed_at=observed_at)
    root = _xml(document, result)
    if root is None:
        return result
    if root.tag not in {SAML + "Assertion", SAMLP + "Response", SAML + "EncryptedAssertion"}:
        result.diagnose("$", "expected a SAML 2.0 Assertion, Response or EncryptedAssertion", invalid=True)
        return result
    response = root if root.tag == SAMLP + "Response" else None
    assertions = [root] if root.tag == SAML + "Assertion" else root.findall(SAML + "Assertion")
    encrypted = ([root] if root.tag == SAML + "EncryptedAssertion"
                 else root.findall(SAML + "EncryptedAssertion"))
    result.inventory = {
        "response": ({"attributes": dict(response.attrib),
                      "issuer": _element_text(response.find(SAML + "Issuer")),
                      "signature_present": _signed(response), "signature_verified": False,
                      "status_codes": [node.get("Value") for node in response.iter(SAMLP + "StatusCode")]}
                     if response is not None else None),
        "assertions": [], "encrypted_assertion_count": len(encrypted),
        "encryption_present": bool(encrypted) or root.find(".//" + XENC + "EncryptedData") is not None,
        "authenticated": False,
    }
    if not assertions and not encrypted:
        result.diagnose("$", "response contains no direct Assertion or EncryptedAssertion")
    for index, assertion in enumerate(assertions):
        issuer = _element_text(assertion.find(SAML + "Issuer"))
        if not issuer:
            result.diagnose(f"$/assertions/{index}/issuer", "assertion issuer is absent")
        subject = assertion.find(SAML + "Subject")
        name_id = subject.find(SAML + "NameID") if subject is not None else None
        confirmations = subject.findall(SAML + "SubjectConfirmation") if subject is not None else []
        conditions = assertion.find(SAML + "Conditions")
        item = {
            "attributes": dict(assertion.attrib), "issuer": issuer,
            "subject": ({"name_id": _element_text(name_id),
                         "name_id_attributes": dict(name_id.attrib) if name_id is not None else {},
                         "encrypted_id_present": subject.find(SAML + "EncryptedID") is not None,
                         "confirmations": [{"attributes": dict(node.attrib),
                                            "data": [dict(v.attrib) for v in node.findall(SAML + "SubjectConfirmationData")]}
                                           for node in confirmations]} if subject is not None else None),
            "conditions": ({"attributes": dict(conditions.attrib),
                            "audience_restrictions": [[_element_text(v) for v in restriction.findall(SAML + "Audience")]
                                                      for restriction in conditions.findall(SAML + "AudienceRestriction")],
                            "one_time_use": conditions.find(SAML + "OneTimeUse") is not None,
                            "proxy_restrictions": [{"attributes": dict(node.attrib),
                                                    "audiences": [_element_text(v) for v in node.findall(SAML + "Audience")]}
                                                   for node in conditions.findall(SAML + "ProxyRestriction")],
                            "evaluated": False} if conditions is not None else None),
            "attribute_statements": [],
            "authn_statements": [{"attributes": dict(node.attrib),
                                  "context_class_refs": [_element_text(v) for v in node.findall(
                                      SAML + "AuthnContext/" + SAML + "AuthnContextClassRef")]}
                                 for node in assertion.findall(SAML + "AuthnStatement")],
            "signature_present": _signed(assertion), "signature_verified": False,
            "encrypted_attributes_present": assertion.find(".//" + SAML + "EncryptedAttribute") is not None,
            "authenticated": False,
        }
        for statement in assertion.findall(SAML + "AttributeStatement"):
            item["attribute_statements"].append([
                {"attributes": dict(attr.attrib),
                 "values": [_element_text(v) for v in attr.findall(SAML + "AttributeValue")]}
                for attr in statement.findall(SAML + "Attribute")])
        result.inventory["assertions"].append(item)
        _emit(result, "saml_assertion", f"saml:assertion:{result.document_fingerprint}:{index}", item,
              target=issuer)
    if encrypted:
        _emit(result, "saml_encrypted_assertion", f"saml:encrypted:{result.document_fingerprint}",
              {"count": len(encrypted), "decrypted": False, "authenticated": False})
    return result
