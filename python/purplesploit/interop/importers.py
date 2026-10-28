"""Common offline importer registry over existing producer adapters.

Supported formats are explicit: nmap-xml (file or XML), nuclei-jsonl,
netexec-log (protocol/arguments optional), bloodhound-json (collector subset),
aws-json/azure-json/gcp-json/entra-json (existing inventory envelopes),
kubernetes-json/docker-json/podman-json/crictl-json/trivy-json/grype-json,
and aranum-bundle (directory, inventory.json plus optional companions).
Ambiguous JSON requires an explicit format name. No tool is executed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Any, Callable

from purplesploit.core.execution import Observation
from purplesploit.core.findings import Finding
from purplesploit.core.timestamps import parse_iso_datetime
from .canonical import CanonicalDocument, load_json, stable_id


UNKNOWN_TIME = None  # Missing producer timestamps remain unknown, never import time.


def _source(source):
    if isinstance(source, Path):
        return source if source.is_dir() else source.read_text(encoding="utf-8-sig")
    if isinstance(source, str) and "\n" not in source and not source.lstrip().startswith(("{", "[", "<")):
        try:
            path = Path(source)
            if path.exists():
                return _source(path)
        except OSError:
            pass
    return deepcopy(source)


def _json(source):
    value = _source(source)
    return load_json(value) if isinstance(value, str) else value


@dataclass
class ImportResult:
    format: str
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[Any] = field(default_factory=list)
    extensions: dict[str, Any] = field(default_factory=dict)
    graph: dict[str, Any] | None = None

    def to_document(self):
        observations = [item.to_dict() for item in self.observations]
        projections = {"host": "assets", "computer": "assets", "service": "services",
                       "identity": "identities", "user": "identities", "group": "identities",
                       "role": "identities", "resource": "resources", "policy": "resources"}
        collections = {key: [] for key in set(projections.values())}
        for observation in observations:
            if observation["kind"] in projections:
                collections[projections[observation["kind"]]].append({"id": observation["observation_id"], **observation})
        return CanonicalDocument.from_components(observations=observations, findings=self.findings,
                                                 graph=self.graph, extensions={"import": self.extensions}, **collections)


class Importer(ABC):
    name: str

    @abstractmethod
    def detect(self, source: Any) -> bool: ...

    @abstractmethod
    def parse(self, source: Any, **options) -> ImportResult: ...


class AdapterImporter(Importer):
    def __init__(self, name: str, detector: Callable, parser: Callable):
        self.name, self.detector, self.parser = name, detector, parser

    def detect(self, source):
        try:
            return bool(self.detector(_source(source)))
        except (ValueError, TypeError, KeyError, AttributeError, OSError):
            return False

    def parse(self, source, **options):
        try:
            result = self.parser(source, **options)
        except (TypeError, KeyError, AttributeError, IndexError) as exc:
            raise ValueError(f"Malformed {self.name}: {exc}") from exc
        result.format = self.name
        result.observations.sort(key=lambda item: item.observation_id)
        result.findings.sort(key=lambda item: item.id)
        return result


class ImporterRegistry:
    def __init__(self):
        self.importers: dict[str, Importer] = {}

    def register(self, importer: Importer):
        if importer.name in self.importers:
            raise ValueError(f"Importer already registered: {importer.name}")
        self.importers[importer.name] = importer
        return importer

    def detect(self, source) -> Importer:
        matches = [item for item in self.importers.values() if item.detect(source)]
        if not matches:
            raise ValueError("Unsupported import format; select a supported format explicitly")
        if len(matches) > 1:
            raise ValueError("Ambiguous import format: " + ", ".join(item.name for item in matches))
        return matches[0]

    def parse(self, source, *, format: str | None = None, **options):
        if format is not None and format not in self.importers:
            raise ValueError(f"Unsupported import format: {format}")
        importer = self.importers[format] if format else self.detect(source)
        return importer.parse(source, **options)


def _observations(values, source, module):
    records = []
    execution_id = stable_id("import", source)
    for item in values:
        value = item.to_dict() if isinstance(item, Observation) else deepcopy(item)
        value.setdefault("attributes", {})
        value["observed_at"] = value["attributes"].get("observed_at") or value["attributes"].get("timestamp") or UNKNOWN_TIME
        value["source_execution_id"] = value.get("source_execution_id") or execution_id
        value["module_path"] = value.get("module_path") or module
        # Recompute after provenance defaults; source timestamps do not affect identity.
        value["observation_id"] = value.get("observation_id") or ""
        records.append(Observation.from_dict(value))
    return records


def _nmap(source, **options):
    from purplesploit.modules.recon.nmap_importer import parse_nmap_xml, observations_for_hosts, _scripts
    import defusedxml.ElementTree as ET
    loaded = _source(source)
    if isinstance(source, Path) or isinstance(source, str) and loaded != source:
        parsed = parse_nmap_xml(source, **options)
        values = parsed["observations"]
    else:
        try:
            root = ET.fromstring(loaded)
        except (ET.ParseError, TypeError) as exc:
            raise ValueError(f"Malformed Nmap XML: {exc}") from exc
        if root.tag != "nmaprun":
            raise ValueError("Expected nmaprun XML root")
        hosts = []
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            addresses = [item.get("addr") for item in host.findall("address") if item.get("addrtype") in {"ipv4", "ipv6"}]
            services = {}
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                values = dict(service.attrib) if service is not None else {}
                number, protocol = int(port.get("portid")), port.get("protocol", "tcp")
                if not 1 <= number <= 65535 or protocol not in {"tcp", "udp", "sctp"}:
                    continue
                services[f"{number}/{protocol}"] = {**values, "port": number, "protocol": protocol, "service": values.get("name", "unknown"), "version": " ".join(filter(None, (values.get("product"), values.get("version")))), "scripts": _scripts(port)}
            hosts.append({"ip": next(iter(addresses), ""), "services": services})
        values = observations_for_hosts(hosts, source_execution_id=stable_id("nmap", loaded), metadata={"source_schema": "nmap/xml", "source_tool_version": root.get("version")})
    return ImportResult("nmap-xml", _observations(values, loaded, "recon/nmap"), extensions={"source": loaded})


def _nuclei(source, **options):
    from purplesploit.modules.recon.nuclei import NucleiModule
    loaded = _source(source)
    if not isinstance(loaded, str):
        loaded = json.dumps(loaded)
    try:
        load_json(loaded)
    except json.JSONDecodeError:
        for line in loaded.splitlines():
            if line.strip():
                try:
                    load_json(line)
                except json.JSONDecodeError:
                    pass  # The existing parser reports malformed lines.
    # Only invoke the pure parser. Constructing a module may load a database.
    parsed = NucleiModule.parse_output(SimpleNamespace(_get_target=lambda: ""), loaded)
    if not parsed["findings"] and parsed["parse_errors"]:
        raise ValueError(f"Malformed Nuclei JSONL: {parsed['parse_errors']}")
    if not parsed["findings"]:
        raise ValueError("No supported Nuclei finding records")
    findings = []
    for raw, record in zip(parsed["findings"], parsed["finding_records"]):
        record["id"] = stable_id("nuclei", raw)
        record["discovered_at"] = raw.get("timestamp") or UNKNOWN_TIME
        record["metadata"] = {"source_format": "nuclei-jsonl", "source_record": raw}
        info = raw.get("info") or {}
        classification = info.get("classification") or {}
        for source_key, target_key in (("cve-id", "cve_ids"), ("cwe-id", "cwe_ids")):
            ids = classification.get(source_key) or []
            record[target_key] = [ids] if isinstance(ids, str) else ids
        record["cvss_score"] = classification.get("cvss-score")
        record["cvss_vector"] = classification.get("cvss-metrics")
        record["remediation"] = info.get("remediation", "")
        references = info.get("reference") or []
        record["references"] = [references] if isinstance(references, str) else references
        findings.append(Finding.from_dict(record))
    return ImportResult("nuclei-jsonl", _observations(parsed["observations"], loaded, "recon/nuclei"), findings, parsed["parse_errors"], {"source": loaded})


def _netexec(source, *, protocol=None, arguments=(), username=None):
    from purplesploit.modules.network.nxc_common import parse_nxc_output
    loaded = _source(source)
    if not isinstance(loaded, str):
        raise ValueError("NetExec import expects text")
    protocols = set(re.findall(r"^(SMB|LDAP|MSSQL|SSH|WINRM|RDP)\s", loaded, re.M))
    if protocol is None and len(protocols) != 1:
        raise ValueError("NetExec requires one identifiable protocol or explicit protocol")
    protocol = str(protocol or next(iter(protocols))).lower()
    if protocol not in {"smb", "ldap", "mssql", "ssh", "winrm", "rdp"}:
        raise ValueError("Unsupported NetExec protocol")
    values = parse_nxc_output(loaded, protocol, arguments, username)
    return ImportResult("netexec-log", _observations(values, loaded, f"network/nxc_{protocol}"), diagnostics=["NetExec enumeration sections may require the original arguments option."], extensions={"source": loaded, "protocol": protocol, "arguments": list(arguments)})


def _bloodhound(source, **options):
    from .bloodhound import import_bloodhound
    loaded = _source(source)
    graph = import_bloodhound(loaded).to_dict()
    values = []
    for node in graph["nodes"]:
        node["discovered_at"] = UNKNOWN_TIME
        values.append({"kind": node["type"], "target": node["label"], "attributes": {"raw_source_id": node["metadata"].get("raw_source_id"), "graph_node": node}})
    for edge in graph["edges"]:
        edge["created_at"] = UNKNOWN_TIME
    return ImportResult("bloodhound-json", _observations(values, loaded, "interop/bloodhound"), extensions={"source": loaded}, graph=graph, diagnostics=["BloodHound collector AD subset; graph metadata retains unsupported records."])


def _inventory(source, *, adapter, name, **options):
    loaded = _json(source)
    result = adapter(loaded, **options)
    observations = _observations(result.observations, loaded, f"interop/{name}")
    diagnostics, findings = list(result.diagnostics), []
    if getattr(result, "status", None) == "invalid":
        raise ValueError(f"Invalid {name}: {diagnostics}")
    for observation in observations:
        if observation.kind != "finding":
            continue
        attributes = observation.attributes
        severity = attributes.get("severity", "info")
        if severity not in {"critical", "high", "medium", "low", "info"}:
            diagnostics.append(f"Unmapped severity {severity!r} projected to info; original observation retained.")
            severity = "info"
        findings.append(Finding(id=observation.observation_id, title=attributes.get("title") or attributes.get("name") or observation.target,
                                severity=severity, target=attributes.get("affected_resource") or observation.target,
                                description=attributes.get("description") or "", cve_ids=attributes.get("cve_ids", []),
                                module_name=f"interop/{name}", discovered_at=observation.observed_at,
                                metadata={"source_observation": observation.to_dict()}))
    adapter_metadata = result.to_dict()
    adapter_metadata.pop("observations", None)
    return ImportResult(name, observations, findings, diagnostics, {"source": loaded, "adapter": adapter_metadata})


def _aranum(source, **options):
    from .aranum import import_aranum_bundle
    root = Path(source)
    if not root.is_dir():
        raise ValueError("Aranum import requires its bundle directory")
    bundle = import_aranum_bundle(root, **options)
    observations = bundle.observations
    if not (root / "bundle-manifest.json").is_file():
        # Preserve the persisted pre-P1 registry projection exactly.  The direct
        # importer still exposes P2b diagnostics for legacy/pre-manifest callers.
        legacy_record_types = {
            "snapshot_metadata", "inventory_host", "inventory_endpoint",
            "canonical_finding", "posture_subject", "posture_check",
            "service_execution", "task_execution",
        }
        observations = [
            item for item in observations
            if item.attributes.get("record_type") in legacy_record_types
        ]
    # The producer bundle contains all supported and unknown companion payloads.
    documents = {}
    try:
        source_paths = sorted(root.glob("*.json*"))
    except OSError:
        source_paths = []
    for path in source_paths:
        try:
            documents[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
    by_id = {item.observation_id: item for item in observations}
    for finding in bundle.findings:
        observation = by_id.get(finding.id)
        timestamp = observation.observed_at if observation is not None else None
        finding.discovered_at = parse_iso_datetime(timestamp) if timestamp else None
        for evidence in finding.evidence:
            evidence.captured_at = finding.discovered_at
    return ImportResult(
        "aranum-bundle",
        _observations(observations, documents, "interop/aranum"),
        list(bundle.findings),
        [],
        {"source": documents, "status": bundle.status},
    )


def _object_matches(source, predicate):
    value = _json(source)
    return isinstance(value, dict) and predicate(value)


def default_registry():
    from . import cloud, containers
    registry = ImporterRegistry()
    registry.register(AdapterImporter("nmap-xml", lambda value: isinstance(value, str) and "<nmaprun" in value, _nmap))
    registry.register(AdapterImporter("nuclei-jsonl", lambda value: isinstance(value, str) and ('"template-id"' in value or '"templateID"' in value) or isinstance(value, dict) and ("template-id" in value or "templateID" in value), _nuclei))
    registry.register(AdapterImporter("netexec-log", lambda value: isinstance(value, str) and bool(re.search(r"^(SMB|LDAP|MSSQL|SSH|WINRM|RDP)\s", value, re.M)), _netexec))
    registry.register(AdapterImporter("bloodhound-json", lambda value: _object_matches(value, lambda obj: isinstance(obj.get("meta"), dict) and "type" in obj["meta"] or bool(obj) and all(isinstance(item, dict) and "meta" in item for item in obj.values())) or isinstance(value, list) and bool(value) and all(isinstance(item, dict) and "meta" in item for item in value), _bloodhound))
    registry.register(AdapterImporter(
        "aranum-bundle",
        lambda value: isinstance(value, Path) and value.is_dir() and any(
            (value / name).exists() for name in ("bundle-manifest.json", "inventory.json")
        ),
        _aranum,
    ))
    adapters = {
        "aws-json": (cloud.import_aws_inventory, lambda obj: "account" in obj or "caller_identity" in obj),
        "azure-json": (cloud.import_azure_inventory, lambda obj: "subscriptions" in obj or "tenant" in obj),
        "gcp-json": (cloud.import_gcp_inventory, lambda obj: "projects" in obj or "project" in obj or "iamPolicy" in obj),
        "entra-json": (cloud.import_entra_inventory, lambda obj: "organization" in obj or "directoryRoles" in obj or "oauth2PermissionGrants" in obj),
        "kubernetes-json": (containers.import_kubernetes_inventory, lambda obj: "apiVersion" in obj and "kind" in obj or any(key in obj for key in ("pods", "deployments", "statefulsets", "namespaces", "contexts"))),
        "docker-json": (containers.import_docker_inventory, lambda obj: "Id" in obj and "Config" in obj or isinstance(obj.get("containers"), list) and any("Config" in item for item in obj["containers"])),
        "podman-json": (containers.import_podman_inventory, lambda obj: "ImageName" in obj and "State" in obj),
        "crictl-json": (containers.import_crictl_inventory, lambda obj: isinstance(obj.get("containers"), list) and any("metadata" in item and "id" in item for item in obj["containers"])),
        "trivy-json": (containers.import_trivy_json, lambda obj: "Results" in obj and "SchemaVersion" in obj),
        "grype-json": (containers.import_grype_json, lambda obj: "matches" in obj and "descriptor" in obj),
    }
    for name, (adapter, predicate) in adapters.items():
        def detector(value, check=predicate):
            document = _json(value)
            return check(document) if isinstance(document, dict) else isinstance(document, list) and bool(document) and all(isinstance(item, dict) and check(item) for item in document)

        def parser(source, function=adapter, format_name=name, **options):
            return _inventory(source, adapter=function, name=format_name, **options)
        registry.register(AdapterImporter(name, detector, parser))
    return registry


REGISTRY = default_registry()


def detect(source):
    return REGISTRY.detect(source)


def parse(source, *, format=None, **options):
    return REGISTRY.parse(source, format=format, **options)
