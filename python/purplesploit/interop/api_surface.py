"""Offline API schema inventory using the common Observation envelope.

Import functions never fetch references or execute the returned replay plans.
Only local JSON pointers are expanded; original documents and records remain
available as provenance. Schema-declared endpoints are inferred, not verified.
"""

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from purplesploit.core.execution import Observation


ADAPTER_SCHEMA_VERSION = "purplesploit/api-surface/1"
HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value):
    return sha256(_canonical(value).encode()).hexdigest()


def _initial_result(document, protocol, source, import_id):
    raw = {"encoding": "hex", "data": bytes(document).hex()} if isinstance(document, (bytes, bytearray)) else deepcopy(document)
    try:
        _canonical(raw)
    except (ValueError, TypeError):
        raw = {"input_type": type(document).__name__}
    return APIImportResult(protocol, source, raw=raw, import_id=import_id or str(
        uuid5(NAMESPACE_URL, _canonical([protocol, source, raw]))))


@dataclass
class APIImportResult:
    """A serializable import, with explicit partial/invalid/unsupported status."""

    protocol: str
    source: str
    source_schema: str = "unknown"
    import_id: str = ""
    schema_version: str = ADAPTER_SCHEMA_VERSION
    status: str = "ok"
    raw: Any = None
    observations: list[Observation] = field(default_factory=list)
    inventory: dict = field(default_factory=dict)
    replay_plan: list[dict] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    def merge_into(self, observations: list[Observation]) -> int:
        """Append unseen IDs once, leaving pre-existing observations untouched."""
        known = {item.observation_id for item in observations}
        added = 0
        for item in self.observations:
            if item.observation_id not in known:
                observations.append(item)
                known.add(item.observation_id)
                added += 1
        return added

    def diagnose(self, path, message, *, status="partial"):
        self.diagnostics.append({"path": path, "message": message})
        if self.status == "ok" or status in {"invalid", "unsupported"}:
            self.status = status


def _load(document, protocol, source, import_id):
    result = _initial_result(document, protocol, source, import_id)
    try:
        value = json.loads(document) if isinstance(document, (str, bytes, bytearray)) else deepcopy(document)
        if not isinstance(value, Mapping):
            raise ValueError("document must be a JSON object")
        value = dict(value)
        # Reject non-JSON mappings early rather than failing during ID generation.
        _canonical(value)
    except (ValueError, TypeError, UnicodeError) as exc:
        result.diagnose("$", str(exc), status="invalid")
        return result, None
    result.raw = value
    result.import_id = import_id or str(uuid5(NAMESPACE_URL, _canonical([protocol, source, value])))
    return result, value


def _mapping(value, result, path):
    if isinstance(value, Mapping):
        return value
    result.diagnose(path, "expected an object")
    return {}


def _sequence(value, result, path):
    if isinstance(value, list):
        return value
    result.diagnose(path, "expected an array")
    return []


def _resolve(value, document, result, path):
    """Resolve reference chains, not recursively expand recursive schemas."""
    seen = set()
    while isinstance(value, Mapping) and "$ref" in value:
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            result.diagnose(path, "external or invalid reference retained without fetching")
            return dict(value)
        if ref in seen:
            result.diagnose(path, "cyclic reference retained")
            return dict(value)
        seen.add(ref)
        resolved = document
        try:
            for token in ref[2:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                resolved = resolved[int(token)] if isinstance(resolved, list) else resolved[token]
        except (KeyError, IndexError, TypeError, ValueError):
            result.diagnose(path, f"unresolved reference: {ref}")
            return dict(value)
        value = resolved
    return _mapping(value, result, path)


def _emit(result, kind, target, record_type, raw, **attributes):
    target = str(target or "")
    try:
        parts = urlsplit(target)
        port = parts.port or {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(parts.scheme)
        host = parts.hostname
    except ValueError:
        host, port = None, None
    attributes = {
        "source_file": result.source,
        "schema_version": result.schema_version, "import_id": result.import_id,
        "document_fingerprint": _digest(result.raw), "record_type": record_type,
        **attributes,
    }
    if host:
        attributes.setdefault("host", host)
    identifier = str(uuid5(NAMESPACE_URL, _canonical([result.import_id, kind, target, attributes])))
    if not any(item.observation_id == identifier for item in result.observations):
        result.observations.append(Observation(
            kind, target, port=port, protocol="tcp" if host else None,
            service=parts.scheme if host else None, attributes=attributes,
            source_schema=result.source_schema, raw=deepcopy(raw),
            source_execution_id=f"import:{result.import_id}", module_path="interop/api_surface",
            operation_name=f"Import {result.protocol}", observed_at=None,
            confidence="inferred", observation_id=identifier,
        ))


def _endpoint(result, url, raw, **attrs):
    _emit(result, "http_endpoint", url, "endpoint", raw, url=url, **attrs)
    try:
        parts = urlsplit(url)
        port = parts.port or {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(parts.scheme)
        if parts.hostname and port and "{" not in parts.netloc:
            _emit(result, "service", url, "declared_service", {}, host=parts.hostname,
                  schema_declared=True)
    except ValueError:
        result.diagnose(url, "invalid endpoint URL retained")


def _plan(result, value):
    value = deepcopy(value)
    value["id"] = str(uuid5(NAMESPACE_URL, _canonical([result.import_id, value])))
    value["status"] = "not_executed"
    if value not in result.replay_plan:
        result.replay_plan.append(value)


def _servers(value, document, result, path, base_url):
    urls = []
    for index, server in enumerate(_sequence(value, result, path)):
        server = _resolve(server, document, result, f"{path}/{index}")
        url = server.get("url")
        if not isinstance(url, str):
            result.diagnose(f"{path}/{index}", "server requires a URL")
            continue
        for name, variable in _mapping(server.get("variables", {}), result, path).items():
            if isinstance(variable, Mapping) and "default" in variable:
                url = url.replace("{" + name + "}", str(variable["default"]))
        if base_url and url.startswith("/"):
            url = base_url.rstrip("/") + url
        urls.append(url)
    return sorted(set(urls))


def import_openapi(document, *, source="memory", base_url=None, import_id=None):
    """Import Swagger 2 / OpenAPI 3 JSON and generate unexecuted replay plans.

    Parameters override inherited parameters by (in, name). Security arrays are
    preserved exactly: alternatives are OR, entries inside one object are AND.
    Schema references remain references; parameter/body local refs are resolved.
    """
    result, doc = _load(document, "openapi", source, import_id)
    if doc is None:
        return result
    version = str(doc.get("openapi") or doc.get("swagger") or "")
    result.source_schema = f"openapi/{version}"
    is_v2 = version == "2.0"
    if not is_v2 and not version.startswith("3."):
        result.diagnose("$", "supported versions: Swagger 2.0 and OpenAPI 3.x", status="unsupported")
        return result
    components = {} if is_v2 else _mapping(doc.get("components", {}), result, "components")
    definitions = doc.get("securityDefinitions", {}) if is_v2 else components.get("securitySchemes", {})
    definitions = _mapping(definitions, result, "securitySchemes")
    result.inventory = {"endpoints": [], "auth_schemes": {}, "schemas": deepcopy(
        doc.get("definitions", {}) if is_v2 else components.get("schemas", {}))}
    for name, definition in sorted(definitions.items()):
        definition = _resolve(definition, doc, result, f"securitySchemes/{name}")
        result.inventory["auth_schemes"][name] = deepcopy(definition)
        _emit(result, "note", base_url or "", "auth_scheme", definition, name=name)
    if is_v2:
        schemes = _sequence(doc.get("schemes", ["https"]), result, "schemes")
        host = doc.get("host")
        default_servers = sorted({f"{scheme}://{host}{doc.get('basePath', '')}" for scheme in schemes if isinstance(scheme, str)}) if host else [base_url or str(doc.get("basePath", ""))]
        if host and "schemes" not in doc:
            result.diagnose("schemes", "scheme absent; supply base_url to avoid an assumed HTTPS URL")
            default_servers = [base_url or str(doc.get("basePath", ""))]
    else:
        default_servers = _servers(doc.get("servers", [{"url": base_url or "/"}]), doc, result, "servers", base_url)
    paths = _mapping(doc.get("paths", {}), result, "paths")
    for path, raw_path in sorted(paths.items()):
        item = _resolve(raw_path, doc, result, f"paths/{path}")
        for method in sorted(HTTP_METHODS.intersection(item)):
            operation = _mapping(item[method], result, f"paths/{path}/{method}")
            if not operation:
                continue
            servers = default_servers
            if not is_v2:
                servers = _servers(operation.get("servers", item.get("servers", [{"url": url} for url in servers])), doc, result, "servers", base_url)
            elif operation.get("schemes") and doc.get("host"):
                servers = [f"{scheme}://{doc['host']}{doc.get('basePath', '')}" for scheme in _sequence(operation["schemes"], result, "schemes") if isinstance(scheme, str)]
            parameters = {}
            for parent in (item, operation):
                for parameter in _sequence(parent.get("parameters", []), result, f"{path}/parameters"):
                    parameter = _resolve(parameter, doc, result, f"{path}/parameters")
                    if not parameter.get("name") or not parameter.get("in"):
                        result.diagnose(f"{path}/parameters", "parameter requires name and in")
                        continue
                    parameters[(str(parameter["in"]), str(parameter["name"]))] = deepcopy(parameter)
            params = [parameters[key] for key in sorted(parameters)]
            request_body = operation.get("requestBody")
            if request_body is not None:
                request_body = dict(_resolve(request_body, doc, result, f"{path}/requestBody"))
            elif is_v2:
                body_parameters = [p for p in params if p["in"] in {"body", "formData"}]
                request_body = {"parameters": body_parameters, "media_types": deepcopy(operation.get("consumes", doc.get("consumes", [])))} if body_parameters else None
            security = deepcopy(operation.get("security", doc.get("security", [])))
            if not isinstance(security, list) or any(not isinstance(requirement, dict) for requirement in security):
                result.diagnose(f"{path}/security", "security must be an array of requirement objects")
            for server in sorted(set(servers)):
                url = server.rstrip("/") + "/" + path.lstrip("/")
                endpoint = {"url": url, "path": path, "method": method.upper(),
                            "operation_id": operation.get("operationId"), "parameters": params,
                            "request_body": request_body, "security": security}
                result.inventory["endpoints"].append(deepcopy(endpoint))
                _endpoint(result, url, operation, **{k: v for k, v in endpoint.items() if k != "url"})
                for parameter in params:
                    _emit(result, "parameter", url, "parameter", parameter, name=parameter["name"],
                          location=parameter["in"], method=method.upper(),
                          required=parameter.get("required", parameter["in"] == "path"),
                          schema=deepcopy(parameter.get("schema", {key: parameter[key] for key in ("type", "format", "items", "enum") if key in parameter})))
                if request_body is not None:
                    _emit(result, "note", url, "request_body", request_body, method=method.upper(), request_body=request_body)
                _emit(result, "note", url, "auth_requirements", security, method=method.upper(), security=security)
                _plan(result, {"protocol": "http", **endpoint})
    return result


def import_graphql(document, *, endpoint="", source="memory", import_id=None):
    """Import a recorded introspection response (or its __schema object)."""
    result, doc = _load(document, "graphql", source, import_id)
    if doc is None:
        return result
    result.source_schema = "graphql/introspection"
    data = doc.get("data", doc)
    data = _mapping(data, result, "data")
    schema = data.get("__schema", data if "types" in data else None)
    schema = _mapping(schema, result, "__schema")
    if not schema:
        result.diagnose("__schema", "introspection schema missing", status="invalid")
        return result
    if doc.get("errors"):
        result.diagnose("errors", "source introspection response contains errors")
    types = {}
    for index, value in enumerate(_sequence(schema.get("types", []), result, "types")):
        value = _mapping(value, result, f"types/{index}")
        name = value.get("name")
        if not isinstance(name, str):
            result.diagnose(f"types/{index}", "type requires a name")
            continue
        if name in types and types[name] != value:
            result.diagnose(f"types/{name}", "conflicting duplicate type retained first")
        types.setdefault(name, deepcopy(value))
    result.inventory = {"types": [types[key] for key in sorted(types)], "operations": []}
    _endpoint(result, endpoint, {}, api_protocol="graphql", method="POST")
    for name in sorted(types):
        _emit(result, "note", endpoint, "graphql_type", types[name], name=name, type=types[name])
    for kind in ("query", "mutation", "subscription"):
        root = schema.get(f"{kind}Type")
        root = root if isinstance(root, dict) else {}
        name = root.get("name")
        if not name:
            continue
        if name not in types:
            result.diagnose(kind, f"root type {name} is absent from types")
            continue
        fields = _sequence(types[name].get("fields", []), result, f"types/{name}/fields")
        seen = set()
        for value in sorted((item for item in fields if isinstance(item, dict)), key=_canonical):
            if not value.get("name"):
                result.diagnose(f"types/{name}/fields", "field requires a name")
                continue
            if _canonical(value) in seen:
                continue
            seen.add(_canonical(value))
            args = _sequence(value.get("args", []), result, f"{name}/{value['name']}/args")
            operation = {"operation": kind, "root_type": name, "name": value["name"],
                         "arguments": deepcopy(args), "return_type": deepcopy(value.get("type"))}
            result.inventory["operations"].append(operation)
            _emit(result, "note", endpoint, "graphql_operation", value, **operation)
            for argument in args:
                argument = _mapping(argument, result, "args")
                if argument.get("name"):
                    _emit(result, "parameter", endpoint, "graphql_argument", argument,
                          name=argument["name"], location="graphql_argument", operation=value["name"],
                          operation_type=kind, schema=argument.get("type"), default=argument.get("defaultValue"))
            _plan(result, {"protocol": "graphql", "url": endpoint, **operation})
    return result


def import_grpc_descriptor_set(document, *, endpoint="", source="memory", import_id=None):
    """Import FileDescriptorSet protobuf bytes or protobuf JSON, without reflection I/O."""
    try:
        from google.protobuf import descriptor_pb2, json_format
        from google.protobuf.message import DecodeError
    except ImportError:
        result = _initial_result(document, "grpc", source, import_id)
        result.source_schema = "protobuf/FileDescriptorSet"
        result.diagnose("$", "protobuf is not installed; descriptor import unavailable", status="unsupported")
        return result
    descriptor = descriptor_pb2.FileDescriptorSet()
    if isinstance(document, (bytes, bytearray)):
        try:
            descriptor.ParseFromString(bytes(document))
        except DecodeError as exc:
            result = _initial_result(document, "grpc", source, import_id)
            result.source_schema = "protobuf/FileDescriptorSet"
            result.diagnose("$", f"invalid descriptor-set bytes: {exc}", status="invalid")
            return result
        document = json_format.MessageToDict(descriptor, preserving_proto_field_name=True)
    elif hasattr(document, "DESCRIPTOR") and document.DESCRIPTOR.full_name == "google.protobuf.FileDescriptorSet":
        document = json_format.MessageToDict(document, preserving_proto_field_name=True)
    result, doc = _load(document, "grpc", source, import_id)
    result.source_schema = "protobuf/FileDescriptorSet"
    if doc is None:
        return result
    try:
        json_format.ParseDict(doc, descriptor)
    except (ValueError, TypeError, json_format.ParseError) as exc:
        result.diagnose("$", f"invalid descriptor-set JSON: {exc}", status="invalid")
        return result
    result.inventory = {"services": [], "messages": [], "enums": []}
    if not descriptor.file:
        result.diagnose("file", "descriptor set contains no files")
    seen = set()
    for file in sorted(descriptor.file, key=lambda item: item.name):
        raw_file = json_format.MessageToDict(file, preserving_proto_field_name=True)
        if _canonical(raw_file) in seen:
            continue
        seen.add(_canonical(raw_file))

        def messages(values, prefix):
            for message in sorted(values, key=lambda item: item.name):
                name = ".".join(filter(None, [prefix, message.name]))
                raw = json_format.MessageToDict(message, preserving_proto_field_name=True)
                item = {"name": name, "file": file.name, "fields": raw.get("field", []), "raw": raw}
                result.inventory["messages"].append(item)
                _emit(result, "note", endpoint, "grpc_message", raw, **{k: v for k, v in item.items() if k != "raw"})
                messages(message.nested_type, name)
                enums(message.enum_type, name)

        def enums(values, prefix):
            for enum in sorted(values, key=lambda item: item.name):
                raw = json_format.MessageToDict(enum, preserving_proto_field_name=True)
                name = ".".join(filter(None, [prefix, enum.name]))
                result.inventory["enums"].append({"name": name, "file": file.name, "values": raw.get("value", [])})
                _emit(result, "note", endpoint, "grpc_enum", raw, name=name, file=file.name)

        messages(file.message_type, file.package)
        enums(file.enum_type, file.package)
        for service in sorted(file.service, key=lambda item: item.name):
            name = ".".join(filter(None, [file.package, service.name]))
            methods = []
            for method in sorted(service.method, key=lambda item: item.name):
                raw = json_format.MessageToDict(method, preserving_proto_field_name=True)
                item = {"service": name, "name": method.name, "path": f"/{name}/{method.name}",
                        "input_type": method.input_type, "output_type": method.output_type,
                        "client_streaming": method.client_streaming, "server_streaming": method.server_streaming}
                methods.append(item)
                _emit(result, "note", endpoint, "grpc_method", raw, **item)
                _plan(result, {"protocol": "grpc", "endpoint": endpoint, **item})
            result.inventory["services"].append({"name": name, "file": file.name, "methods": methods})
            _emit(result, "note", endpoint, "grpc_service", raw_file, name=name, methods=methods)
    return result


def import_asyncapi(document, *, source="memory", import_id=None):
    """Import AsyncAPI 2/3 WebSocket channels/messages; do not open a socket."""
    result, doc = _load(document, "asyncapi", source, import_id)
    if doc is None:
        return result
    version = str(doc.get("asyncapi", ""))
    result.source_schema = f"asyncapi/{version}"
    if not version.startswith(("2.", "3.")):
        result.diagnose("asyncapi", "supported versions: AsyncAPI 2.x and 3.x", status="unsupported")
        return result
    v3 = version.startswith("3.")
    servers = {}
    for name, raw in sorted(_mapping(doc.get("servers", {}), result, "servers").items()):
        server = _resolve(raw, doc, result, f"servers/{name}")
        protocol = str(server.get("protocol", "")).lower()
        if protocol not in {"ws", "wss"}:
            continue
        address = server.get("host") if v3 else server.get("url")
        if not isinstance(address, str):
            result.diagnose(f"servers/{name}", "WebSocket server requires host or URL")
            continue
        if "://" not in address:
            address = f"{protocol}://{address}"
        if v3:
            address += str(server.get("pathname", ""))
        for variable, schema in _mapping(server.get("variables", {}), result, "variables").items():
            if isinstance(schema, dict) and "default" in schema:
                address = address.replace("{" + variable + "}", str(schema["default"]))
        servers[name] = {"url": address, "security": deepcopy(server.get("security", []))}
    result.inventory = {"servers": servers, "channels": [], "messages": []}
    channels = _mapping(doc.get("channels", {}), result, "channels")
    operations = _mapping(doc.get("operations", {}), result, "operations") if v3 else {}
    for name, raw in sorted(channels.items()):
        channel = _resolve(raw, doc, result, f"channels/{name}")
        address = channel.get("address", name) if v3 else name
        if not isinstance(address, str):
            result.diagnose(f"channels/{name}/address", "channel address is absent or not a string")
            continue
        selected = channel.get("servers", list(servers))
        if not isinstance(selected, list):
            result.diagnose(f"channels/{name}/servers", "expected an array")
            selected = []
        server_names = []
        for candidate in selected:
            if isinstance(candidate, str):
                server_names.append(candidate)
            elif isinstance(candidate, dict) and isinstance(candidate.get("$ref"), str):
                server_names.append(candidate["$ref"].rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~"))
        actions = []
        if v3:
            for op_name, raw_op in sorted(operations.items()):
                op = _resolve(raw_op, doc, result, f"operations/{op_name}")
                referenced = op.get("channel", {})
                if isinstance(referenced, dict) and referenced.get("$ref") == "#/channels/" + name.replace("~", "~0").replace("/", "~1"):
                    actions.append({"name": op_name, "action": op.get("action"), "raw": op})
            message_values = list(_mapping(channel.get("messages", {}), result, "messages").values())
        else:
            message_values = []
            for action in ("publish", "subscribe"):
                if action in channel:
                    op = _resolve(channel[action], doc, result, f"channels/{name}/{action}")
                    actions.append({"name": op.get("operationId"), "action": action, "raw": op})
                    message_values.append(op.get("message", {}))
        messages = []
        for value in message_values:
            value = _resolve(value, doc, result, f"channels/{name}/message")
            alternatives = value.get("oneOf", [value])
            for message in _sequence(alternatives, result, "message/oneOf"):
                message = _resolve(message, doc, result, "message")
                if message and message not in messages:
                    messages.append(deepcopy(message))
        inventory = {"name": name, "address": address, "actions": actions, "messages": messages,
                     "parameters": deepcopy(channel.get("parameters", {})), "servers": sorted(set(server_names))}
        result.inventory["channels"].append(inventory)
        for message in messages:
            record = {"channel": name, **message}
            if record not in result.inventory["messages"]:
                result.inventory["messages"].append(record)
            _emit(result, "note", address, "websocket_message", message, channel=name,
                  name=message.get("name"), payload_schema=message.get("payload"), headers_schema=message.get("headers"))
        for server_name in sorted(set(server_names)):
            if server_name not in servers:
                result.diagnose(f"channels/{name}/servers", f"unknown or non-WebSocket server: {server_name}")
                continue
            server = servers[server_name]
            url = server["url"].rstrip("/") + "/" + address.lstrip("/")
            _endpoint(result, url, channel, api_protocol="websocket", channel=name, messages=messages,
                      actions=actions, security=server["security"])
            for parameter_name, raw_parameter in _mapping(channel.get("parameters", {}), result, "parameters").items():
                parameter = _resolve(raw_parameter, doc, result, "parameter")
                _emit(result, "parameter", url, "websocket_parameter", parameter, name=parameter_name,
                      location="channel", channel=name, schema=parameter.get("schema"))
            _plan(result, {"protocol": "websocket", "url": url, "channel": name,
                           "actions": actions, "messages": messages, "security": server["security"]})
    return result
