"""Offline, deterministic ATT&CK Navigator, STIX 2.1 and graph interchange.

These are supported-subset adapters, not an ATT&CK knowledge base or a lossless
STIX converter. Technique mappings are supplied by the caller. Manifest entries
describe capability, never executed coverage. STIX custom ``x_purplesploit``
properties retain source records; unsupported input stays in ``raw`` and explicit
diagnostics. No external references are fetched and no dependency is required.
"""

from __future__ import annotations

from copy import deepcopy
import csv
from purplesploit.core.output_security import restore_spreadsheet_value, spreadsheet_safe
from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
from ipaddress import ip_address
import json
import math
import re
from typing import Any, Mapping
from uuid import NAMESPACE_URL, UUID, uuid5

from purplesploit.core.attack_graph import AttackGraph, EdgeType, NodeStatus, NodeType
from purplesploit.core.execution import Observation
from purplesploit.core.findings import Finding


SCHEMA_VERSION = "purplesploit/attack-formats/1"
EPOCH = "1970-01-01T00:00:00.000Z"
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
DOMAINS = {"enterprise-attack", "mobile-attack", "ics-attack"}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _record(value):
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    return deepcopy(dict(value))


def _id(kind, value):
    return f"{kind}--{uuid5(NAMESPACE_URL, _json([SCHEMA_VERSION, kind, value]))}"


def _strings(value):
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value or [] if isinstance(item, (str, int))]


def _timestamp(value):
    """Normalize supplied time; an explicit epoch sentinel denotes unknown time."""
    if not value:
        return EPOCH
    if isinstance(value, datetime):
        stamp = value
    else:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class AttackImportResult:
    """Partial imports keep original data and never silently discard records."""

    format: str
    source: str = "memory"
    raw: Any = None
    status: str = "ok"
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    diagnostics: list[dict] = field(default_factory=list)
    extensions: dict = field(default_factory=dict)
    graph: AttackGraph | None = None
    schema_version: str = SCHEMA_VERSION

    def diagnose(self, path, message, status="partial"):
        self.diagnostics.append({"path": path, "message": message})
        if self.status == "ok" or status == "invalid":
            self.status = status

    def to_dict(self):
        return {"format": self.format, "source": self.source, "raw": deepcopy(self.raw),
                "status": self.status, "schema_version": self.schema_version,
                "observations": [item.to_dict() for item in self.observations],
                "findings": [item.to_dict() for item in self.findings],
                "coverage": deepcopy(self.coverage), "relationships": deepcopy(self.relationships),
                "diagnostics": deepcopy(self.diagnostics), "extensions": deepcopy(self.extensions),
                "graph": self.graph.to_dict() if self.graph is not None else None}

    def merge_into(self, observations):
        known = {item.observation_id for item in observations}
        added = 0
        for item in self.observations:
            if item.observation_id not in known:
                observations.append(item)
                known.add(item.observation_id)
                added += 1
        return added


def _load(document, format_name, source):
    result = AttackImportResult(format_name, source, raw=deepcopy(document))
    try:
        document = json.loads(document) if isinstance(document, (str, bytes)) else deepcopy(document)
        if not isinstance(document, dict):
            raise ValueError("document must be a JSON object")
        _json(document)
    except (ValueError, TypeError, UnicodeError) as exc:
        result.diagnose("$", str(exc), "invalid")
        return result, None
    result.raw = document
    return result, document


def _techniques(record):
    values = []
    for container in (record, record.get("metadata", {}), record.get("attributes", {}),
                      record.get("raw_result", {})):
        if not isinstance(container, Mapping):
            continue
        for key in ("mitre_techniques", "techniques", "technique_ids", "attack_techniques"):
            raw = container.get(key, [])
            raw = [raw] if isinstance(raw, str) else raw
            if isinstance(raw, list):
                values.extend(item.get("techniqueID", item.get("id", ""))
                              if isinstance(item, dict) else item for item in raw)
        for key in ("techniqueID", "technique_id", "control_id"):
            values.append(container.get(key, ""))
        standards = container.get("standards", []) or []
        standards = standards if isinstance(standards, list) else [standards]
        for standard in standards:
            values.append(standard.get("id", "") if isinstance(standard, dict) else standard)
    return sorted({value.upper() for value in values
                   if isinstance(value, str) and TECHNIQUE.fullmatch(value.upper())})


def _evidence(record):
    values = []
    for key in ("evidence_ids", "evidence_refs", "observation_ids", "source_observation_ids"):
        values.extend(_strings(record.get(key, [])))
    for item in record.get("evidence", []) or []:
        if isinstance(item, dict) and item.get("id"):
            values.append(str(item["id"]))
    return sorted(set(values))


def _coverage_rows(coverage):
    if coverage is None:
        return []
    if hasattr(coverage, "checks") and hasattr(coverage, "plans"):
        from purplesploit.core.assessment import compute_coverage

        coverage = compute_coverage(coverage)
    if isinstance(coverage, Mapping):
        return coverage.get("checks", coverage.get("coverage", []))
    return coverage


def export_navigator_layer(findings=(), *, executions=(), operations=(), coverage=None,
                           name="PurpleSploit assessment", domain="enterprise-attack",
                           attack_version=None):
    """Return Navigator v4.5 JSON for supplied mappings only.

    Scores count completed executions and explicitly tested assessment records.
    A finding contributes one evidence-bearing mapping; a manifest entry adds
    capability metadata with score zero. No full-matrix coverage is inferred.
    """
    if domain not in DOMAINS:
        raise ValueError(f"unsupported Navigator domain: {domain}")
    groups = {}

    def add(item, kind):
        item = _record(item)
        techniques = _techniques(item)
        if kind == "execution":
            for observation in item.get("observations", []):
                add(observation, "observation")
        for technique in techniques:
            row = groups.setdefault(technique, {"records": [], "evidence": set()})
            state = str(item.get("state", item.get("outcome", item.get("status", "mapped"))))
            completed = kind == "finding" or (kind == "observation" and item.get("confidence", "observed") == "observed")
            if kind == "execution":
                completed = item.get("success") is True and state == "success" and bool(item.get("finished_at"))
            if kind == "coverage":
                completed = item.get("tested") is True or state in {"tested", "automated", "manual"}
            identifier = str(item.get("id", item.get("request_id", item.get("observation_id",
                             item.get("case_id", "")))))
            row["records"].append({"kind": kind, "id": identifier, "status": state, "contributes_score": completed,
                                   "comment": str(item.get("note", item.get("title", item.get("comment", ""))))})
            row["evidence"].update(_evidence(item))
            if kind == "observation" and identifier:
                row["evidence"].add(identifier)

    for kind, items in (("finding", findings), ("execution", executions),
                        ("capability", operations), ("coverage", _coverage_rows(coverage))):
        for item in items:
            add(item, kind)
    techniques = []
    for technique, row in sorted(groups.items()):
        records = sorted({_json(record): record for record in row["records"]}.values(), key=_json)
        # Deduplicate contributions from the same source record.
        score = sum(record["contributes_score"] for record in records)
        techniques.append({"techniqueID": technique, "score": score, "enabled": True,
                           "comment": "; ".join(f"{r['kind']}:{r['id']} [{r['status']}] {r['comment']}".rstrip()
                                                for r in records),
                           "metadata": [{"name": "purplesploit:records", "value": _json(records)},
                                        {"name": "purplesploit:evidence_ids", "value": _json(sorted(row["evidence"]))}]})
    versions = {"layer": "4.5", "navigator": "4.9.1"}
    if attack_version is not None:
        versions["attack"] = str(attack_version)
    return {"name": name, "versions": versions, "domain": domain,
            "description": "Supplied technique mappings only; score counts evidence mappings/completed checks, not ATT&CK matrix coverage.",
            "techniques": techniques, "sorting": 0,
            "metadata": [{"name": "purplesploit:schema", "value": SCHEMA_VERSION},
                         {"name": "purplesploit:scope", "value": "supplied_mappings_only"}]}


def import_navigator_layer(document, *, source="memory"):
    """Import explicit layer rows as inferred annotations, never tested claims."""
    result, doc = _load(document, "navigator", source)
    if doc is None:
        return result
    if doc.get("domain") not in DOMAINS or not isinstance(doc.get("techniques"), list):
        result.diagnose("$", "Navigator requires a supported domain and techniques array", "invalid")
        return result
    result.extensions = {key: deepcopy(value) for key, value in doc.items() if key != "techniques"}
    seen = set()
    for index, raw in enumerate(doc["techniques"]):
        path = f"techniques/{index}"
        if not isinstance(raw, dict) or not TECHNIQUE.fullmatch(str(raw.get("techniqueID", ""))):
            result.diagnose(path, "invalid techniqueID; row retained in raw")
            continue
        score = raw.get("score")
        if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score)):
            result.diagnose(path, "score must be finite numeric")
            continue
        if "enabled" in raw and not isinstance(raw["enabled"], bool):
            result.diagnose(path, "enabled must be boolean")
            continue
        identifier = str(uuid5(NAMESPACE_URL, _json([source, doc.get("domain"), raw])))
        if identifier in seen:
            result.diagnose(path, "duplicate identical layer row")
            continue
        seen.add(identifier)
        row = {"id": identifier, "technique_id": raw["techniqueID"], "state": "imported",
               "tested": False, "score": score, "enabled": raw.get("enabled", True),
               "comment": raw.get("comment", ""), "source": source, "raw": deepcopy(raw)}
        result.coverage.append(row)
        result.observations.append(Observation(
            "note", raw["techniqueID"], attributes={"record_type": "technique_coverage", **row},
            source_execution_id=f"import:navigator:{uuid5(NAMESPACE_URL, source)}",
            module_path="interop/attack_formats", operation_name="Import Navigator layer",
            observed_at=None, confidence="inferred", observation_id=identifier))
    return result


def _custom(kind, record):
    return {"schema_version": SCHEMA_VERSION, "kind": kind, "source_record": deepcopy(record)}


def _sdo(kind, identity, timestamp, **values):
    return {"type": kind, "spec_version": "2.1", "id": _id(kind, identity),
            "created": timestamp, "modified": timestamp, **values}


def export_stix_bundle(observations=(), *, findings=(), graph=None, name="PurpleSploit",
                       timestamp=None):
    """Export supported observed entities, findings-as-notes and references.

    IP/domain/URL/user-account SCOs preserve observed values. Generic resources
    are grouping SDOs, avoiding an invented infrastructure classification.
    Findings are note SDOs: not every assessment finding is a vulnerability.
    Custom provenance carries fields that have no standard STIX representation.
    Unknown times use the documented epoch sentinel; inferred records never
    create observed-data. UUID5 identifiers and ordering are deterministic.
    """
    stamp = _timestamp(timestamp)
    producer = _sdo("identity", ["producer", name], stamp, name=name,
                    identity_class="organization")
    objects = {producer["id"]: producer}
    observations = sorted((_record(item) for item in observations), key=_json)
    findings = sorted((_record(item) for item in findings), key=_json)
    references = {}
    pending = []

    def technique_ref(technique):
        pattern = _sdo("attack-pattern", ["mitre-attack", technique], stamp, name=technique,
                       external_references=[{"source_name": "mitre-attack", "external_id": technique}])
        objects[pattern["id"]] = pattern
        references.setdefault(technique, pattern["id"])
        return pattern["id"]

    def emit(record, *, graph_node=False):
        attrs = record.get("properties" if graph_node else "attributes", {})
        kind = record.get("type" if graph_node else "kind", "resource")
        target = str(attrs.get("identifier") or record.get("target") or record.get("label") or record.get("id") or "")
        source_id = str(record.get("id" if graph_node else "observation_id", ""))
        source_key = [source_id, record]  # conflicting source IDs cannot overwrite each other
        details = _custom(kind, record)
        if graph_node:
            details["graph_node"] = True
        details["time_unknown"] = not bool(record.get("discovered_at" if graph_node else "observed_at"))
        object_stamp = _timestamp(record.get("discovered_at" if graph_node else "observed_at") or timestamp)
        obj = None
        if kind in {"host", "computer", "domain"}:
            value = str(attrs.get("ip") or attrs.get("host") or record.get("target") or target)
            try:
                address = ip_address(value)
                obj = {"type": "ipv4-addr" if address.version == 4 else "ipv6-addr", "value": str(address)}
            except ValueError:
                if re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9_](?:[a-zA-Z0-9_.-]*[a-zA-Z0-9_])?", value):
                    obj = {"type": "domain-name", "value": value}
        elif kind == "user":
            obj = {"type": "user-account", "account_login": str(attrs.get("username") or attrs.get("name") or target)}
        elif kind == "identity":
            obj = _sdo("identity", source_key, object_stamp, name=target,
                       identity_class=attrs.get("identity_class") if attrs.get("identity_class") in {
                           "individual", "group", "system", "organization", "class", "unknown"} else "unknown")
        elif kind == "resource" and re.match(r"^https?://", target):
            obj = {"type": "url", "value": target}
        if obj is None:
            obj = _sdo("grouping", source_key, object_stamp, name=target or kind,
                       context="unspecified", object_refs=[producer["id"]])
        obj.setdefault("spec_version", "2.1")
        obj.setdefault("id", _id(obj["type"], source_key))
        obj["x_purplesploit"] = details
        objects[obj["id"]] = obj
        # Both stable source IDs and logical endpoint identifiers are resolvable.
        references.setdefault(source_id, obj["id"])
        references.setdefault(target, obj["id"])
        if record.get("target"):
            references.setdefault(str(record["target"]), obj["id"])
        for technique in _techniques(record):
            technique_ref(technique)
            pending.append((obj["id"], {"type": "references", "target": technique,
                                       "record_type": "technique_mapping"}))
        if not graph_node and record.get("confidence", "observed") == "observed" and record.get("observed_at"):
            observed = _sdo("observed-data", [source_key, "observed"], object_stamp,
                            first_observed=object_stamp, last_observed=object_stamp, number_observed=1,
                            object_refs=[obj["id"]], x_purplesploit=details)
            # STIX observed-data object_refs contain SCOs; SDO annotations stay custom.
            if "created" not in obj:
                objects[observed["id"]] = observed
        relations = attrs.get("relationships", []) or []
        relations = [relations] if isinstance(relations, dict) else relations
        for relation in relations:
            if isinstance(relation, dict):
                pending.append((obj["id"], relation))
        return obj["id"]

    for observation in observations:
        emit(observation)
    if graph is not None:
        graph_data = graph.to_dict() if hasattr(graph, "to_dict") else _record(graph)
        for node in sorted(graph_data.get("nodes", []), key=_json):
            emit(node, graph_node=True)
        for edge in sorted(graph_data.get("edges", []), key=_json):
            pending.append((references.get(edge.get("source")), {**edge, "target": edge.get("target"), "graph_edge": True}))
    for finding in findings:
        refs = [references[finding["target"]]] if finding.get("target") in references else []
        for technique in _techniques(finding):
            refs.append(technique_ref(technique))
        note = _sdo("note", [finding.get("id"), finding], _timestamp(finding.get("discovered_at") or timestamp),
                    abstract=finding.get("title") or "Assessment finding",
                    content=finding.get("description") or finding.get("title") or "Assessment finding",
                    object_refs=sorted(set(refs or [producer["id"]])), x_purplesploit=_custom("finding", finding))
        objects[note["id"]] = note
    for source_ref, relation in pending:
        target_ref = references.get(str(relation.get("target", relation.get("target_id", ""))))
        if not source_ref or not target_ref:
            # Keep unresolved source relationship in its entity's source_record.
            continue
        if relation.get("direction") == "in":
            source_ref, target_ref = target_ref, source_ref
        rel = _sdo("relationship", [source_ref, target_ref, relation], stamp,
                   relationship_type="related-to", source_ref=source_ref, target_ref=target_ref,
                   x_purplesploit={"schema_version": SCHEMA_VERSION, "edge_type": relation.get("type", "references"),
                                   "source_record": deepcopy(relation)})
        objects[rel["id"]] = rel
    ordered = sorted(objects.values(), key=lambda value: value["id"])
    return {"type": "bundle", "id": _id("bundle", ordered), "objects": ordered}


def _valid_stix_id(identifier, kind=None):
    try:
        prefix, value = identifier.split("--", 1)
        UUID(value)
        return bool(prefix) and (kind is None or kind == prefix)
    except (AttributeError, ValueError, TypeError):
        return False


def validate_stix_bundle(document):
    """Return JSON-shape diagnostics for the supported STIX subset, offline."""
    errors = []
    if not isinstance(document, dict) or document.get("type") != "bundle" or not _valid_stix_id(document.get("id"), "bundle"):
        return [{"path": "$", "message": "bundle requires type=bundle and a valid bundle ID"}]
    if not isinstance(document.get("objects"), list):
        return [{"path": "objects", "message": "objects must be an array"}]
    required = {"ipv4-addr": ["value"], "ipv6-addr": ["value"], "domain-name": ["value"],
                "url": ["value"], "identity": ["name", "identity_class"], "attack-pattern": ["name"],
                "vulnerability": ["name"], "note": ["content", "object_refs"],
                "grouping": ["context", "object_refs"], "relationship": ["relationship_type", "source_ref", "target_ref"],
                "observed-data": ["first_observed", "last_observed", "number_observed", "object_refs"]}
    scos = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "user-account", "software", "file", "artifact"}
    for index, obj in enumerate(document["objects"]):
        path = f"objects/{index}"
        if not isinstance(obj, dict):
            errors.append({"path": path, "message": "object must be an object"})
            continue
        kind = obj.get("type")
        if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9-]*", kind):
            errors.append({"path": path, "message": "type must be a STIX type string"})
            continue
        if not _valid_stix_id(obj.get("id"), kind) or obj.get("spec_version", "2.1") != "2.1":
            errors.append({"path": path, "message": "invalid STIX 2.1 type, ID or spec_version"})
        for key in required.get(kind, []):
            if key not in obj or obj[key] is None or obj[key] == "" or obj[key] == []:
                errors.append({"path": f"{path}/{key}", "message": "required field missing or empty"})
        if kind == "user-account" and not any(obj.get(key) for key in ("user_id", "account_login", "display_name")):
            errors.append({"path": path, "message": "user-account requires identifying properties"})
        if kind not in scos:
            for key in ("created", "modified"):
                try:
                    if not isinstance(obj.get(key), str) or not obj[key].endswith("Z"):
                        raise ValueError("timestamp requires UTC Z")
                    _timestamp(obj[key])
                except (ValueError, TypeError):
                    errors.append({"path": f"{path}/{key}", "message": "invalid or missing UTC timestamp"})
            if isinstance(obj.get("created"), str) and isinstance(obj.get("modified"), str):
                try:
                    if _timestamp(obj["modified"]) < _timestamp(obj["created"]):
                        errors.append({"path": path, "message": "modified precedes created"})
                except ValueError:
                    pass
        if kind == "observed-data":
            for key in ("first_observed", "last_observed"):
                try:
                    if not isinstance(obj.get(key), str) or not obj[key].endswith("Z"):
                        raise ValueError("timestamp requires UTC Z")
                    _timestamp(obj[key])
                except (ValueError, TypeError):
                    errors.append({"path": f"{path}/{key}", "message": "invalid observed timestamp"})
            number = obj.get("number_observed")
            if type(number) is not int or not 1 <= number <= 999999999:
                errors.append({"path": path, "message": "number_observed must be a positive integer"})
            try:
                if _timestamp(obj.get("last_observed")) < _timestamp(obj.get("first_observed")):
                    errors.append({"path": path, "message": "last_observed precedes first_observed"})
            except ValueError:
                pass
        if kind in {"ipv4-addr", "ipv6-addr"}:
            try:
                address = ip_address(obj.get("value"))
                if address.version != (4 if kind == "ipv4-addr" else 6):
                    raise ValueError("address version mismatch")
            except (ValueError, TypeError):
                errors.append({"path": f"{path}/value", "message": "invalid address"})
        if "object_refs" in obj and (not isinstance(obj["object_refs"], list) or
                                     any(not _valid_stix_id(ref) for ref in obj["object_refs"])):
            errors.append({"path": f"{path}/object_refs", "message": "object_refs must be STIX ID array"})
        if kind == "relationship" and any(not _valid_stix_id(obj.get(key)) for key in ("source_ref", "target_ref")):
            errors.append({"path": path, "message": "invalid relationship endpoints"})
    return errors


def import_stix_bundle(document, *, source="memory"):
    """Import supported SCO/SDO/SRO records, preserving raw source properties.

    Generic STIX relationships become graph ``references`` edges with the
    original relationship_type retained. Exported graph edge types are restored
    only when they are recognized PurpleSploit edge types.
    """
    result, doc = _load(document, "stix", source)
    if doc is None:
        return result
    issues = validate_stix_bundle(doc)
    for issue in issues:
        result.diagnose(issue["path"], issue["message"], "invalid" if issue["path"] in {"$", "objects"} else "partial")
    if result.status == "invalid":
        return result
    result.extensions = {key: deepcopy(value) for key, value in doc.items()
                         if key not in {"type", "id", "objects"}}
    invalid = {int(item["path"].split("/")[1]) for item in issues if item["path"].startswith("objects/")}
    entities, objects, seen, observed_times = {}, {}, set(), {}
    for index, obj in enumerate(doc["objects"]):
        if index in invalid:
            continue
        identifier = obj["id"]
        if identifier in seen:
            result.diagnose(f"objects/{index}", "duplicate STIX ID; first object retained")
            continue
        seen.add(identifier)
        objects[identifier] = obj
        if obj["type"] == "observed-data":
            for ref in obj.get("object_refs", []):
                observed_times[ref] = obj.get("last_observed")
    for identifier, obj in objects.items():
        for ref in obj.get("object_refs", []):
            if ref not in objects:
                result.diagnose(identifier, f"unresolved object_ref: {ref}")
    supported = {"ipv4-addr": "host", "ipv6-addr": "host", "domain-name": "host",
                 "url": "resource", "user-account": "user", "identity": "identity",
                 "grouping": "resource", "software": "resource", "file": "resource", "artifact": "resource"}
    for identifier, obj in sorted(objects.items()):
        kind = obj["type"]
        custom = obj.get("x_purplesploit", {})
        custom = custom if isinstance(custom, dict) else {}
        original = custom.get("source_record", {})
        if kind in {"note", "vulnerability"}:
            if kind == "note" and custom.get("kind") != "finding":
                result.diagnose(identifier, "non-finding STIX note retained without finding conversion")
                continue
            try:
                if custom.get("kind") == "finding" and isinstance(original, dict):
                    finding = Finding.from_dict(original)
                else:
                    finding = Finding(id=str(uuid5(NAMESPACE_URL, identifier)), title=obj["name"],
                                      description=obj.get("description", ""), discovered_at=_timestamp(obj.get("created")),
                                      cve_ids=[ref["external_id"] for ref in obj.get("external_references", [])
                                               if isinstance(ref, dict) and str(ref.get("external_id", "")).startswith("CVE-")],
                                      metadata={"stix_id": identifier, "raw": deepcopy(obj)})
            except (ValueError, TypeError, KeyError) as exc:
                result.diagnose(identifier, f"finding conversion failed: {exc}")
                continue
            result.findings.append(finding)
            attrs = {"identifier": finding.id, "title": finding.title, "severity": finding.severity.value,
                     "source_stix_id": identifier, "raw": deepcopy(obj)}
            observation = Observation("finding", finding.target or finding.id, attributes=attrs,
                                      observed_at=_timestamp(obj.get("created")), confidence="inferred",
                                      source_execution_id=f"import:stix:{source}", module_path="interop/attack_formats",
                                      observation_id=str(uuid5(NAMESPACE_URL, _json([source, identifier]))))
            result.observations.append(observation)
            entities[identifier] = observation
        elif kind in supported:
            if custom.get("graph_node") and isinstance(original, dict):
                graph_kind = original.get("type", "resource")
                observation_kind = "finding" if graph_kind == "vulnerability" else graph_kind
                attrs = deepcopy(original.get("properties", {}))
                target = str(original.get("label", identifier))
                attrs["identifier"] = str(original.get("id", identifier))
                attrs["graph_metadata"] = deepcopy(original.get("metadata", {}))
            elif isinstance(original, dict) and original.get("kind") in {item.value for item in NodeType} | {"finding"}:
                observation_kind = original["kind"]
                attrs = deepcopy(original.get("attributes", {}))
                target = str(original.get("target", identifier))
            else:
                observation_kind = supported[kind]
                target = str(obj.get("value") or obj.get("account_login") or obj.get("name") or identifier)
                attrs = {"identifier": identifier, "name": obj.get("name", target)}
            # STIX IDs are unique within a bundle even when producer source IDs collide.
            existing_relationships = attrs.get("relationships", [])
            if isinstance(existing_relationships, dict):
                attrs["relationships"] = [existing_relationships]
            elif not isinstance(existing_relationships, list):
                attrs["relationships"] = []
                result.diagnose(identifier, "malformed source relationships retained in raw")
            attrs.update({"source_stix_id": identifier, "raw": deepcopy(obj), "source_file": source})
            observation = Observation(observation_kind, target, attributes=attrs,
                                      observed_at=observed_times.get(identifier),
                                      confidence="observed" if identifier in observed_times else "inferred",
                                      source_execution_id=f"import:stix:{source}", module_path="interop/attack_formats",
                                      observation_id=str(uuid5(NAMESPACE_URL, _json([source, identifier]))))
            result.observations.append(observation)
            entities[identifier] = observation
        elif kind == "attack-pattern":
            for ref in obj.get("external_references", []):
                if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack" and TECHNIQUE.fullmatch(str(ref.get("external_id", ""))):
                    result.coverage.append({"technique_id": ref["external_id"], "state": "imported", "tested": False,
                                            "source_stix_id": identifier, "raw": deepcopy(obj)})
            observation = Observation("resource", obj["name"], attributes={
                "identifier": identifier, "record_type": "attack_pattern_reference", "source_stix_id": identifier,
                "raw": deepcopy(obj)}, observed_at=None, confidence="inferred",
                source_execution_id=f"import:stix:{source}", module_path="interop/attack_formats",
                observation_id=str(uuid5(NAMESPACE_URL, _json([source, identifier]))))
            result.observations.append(observation)
            entities[identifier] = observation
        elif kind not in {"relationship", "observed-data"}:
            result.diagnose(identifier, f"unsupported STIX type: {kind}; retained in raw")
    for identifier, obj in sorted(objects.items()):
        if obj["type"] != "note" or identifier not in entities:
            continue
        for ref in obj.get("object_refs", []):
            if ref in entities:
                target = entities[ref]
                relation = {"type": "references", "target_kind": target.kind,
                            "target": target.attributes.get("identifier", target.target),
                            "source_stix_id": identifier, "stix_object_ref": ref}
                entities[identifier].attributes.setdefault("relationships", []).append(relation)
                result.relationships.append({"source": entities[identifier].observation_id, **deepcopy(relation)})
    for identifier, obj in sorted(objects.items()):
        if obj["type"] != "relationship":
            continue
        source_observation = entities.get(obj["source_ref"])
        target_observation = entities.get(obj["target_ref"])
        if source_observation is None or target_observation is None:
            result.diagnose(identifier, "unresolved or unsupported relationship endpoint; retained in raw")
            continue
        custom = obj.get("x_purplesploit", {})
        edge_type = custom.get("edge_type", "references") if isinstance(custom, dict) else "references"
        if edge_type not in {item.value for item in EdgeType}:
            result.diagnose(identifier, f"unsupported graph edge type: {edge_type}; projected as references")
            edge_type = "references"
        relation = {"type": edge_type, "target": target_observation.attributes.get("identifier", target_observation.target),
                    "target_kind": target_observation.kind, "source_stix_id": identifier,
                    "stix_relationship_type": obj["relationship_type"], "raw": deepcopy(obj)}
        source_observation.attributes.setdefault("relationships", []).append(relation)
        result.relationships.append({"source": source_observation.observation_id,
                                     "target": target_observation.observation_id, **deepcopy(relation)})
    result.graph = AttackGraph()
    result.graph.ingest_observations(result.observations)
    times = {item.observation_id: _timestamp(item.observed_at) for item in result.observations}
    for node in result.graph.nodes.values():
        values = [times[ref] for ref in node.metadata.get("source_observation_ids", []) if ref in times]
        node.discovered_at = datetime.fromisoformat(min(values, default=EPOCH).replace("Z", "+00:00"))
    for edge in result.graph.edges.values():
        values = [times[ref] for ref in edge.properties.get("source_observation_ids", []) if ref in times]
        edge.created_at = datetime.fromisoformat(min(values, default=EPOCH).replace("Z", "+00:00"))
    return result


def export_graph_json(graph):
    """Return deterministic generic graph JSON, retaining edge provenance."""
    data = deepcopy(graph.to_dict() if hasattr(graph, "to_dict") else graph)
    for key in ("nodes", "edges", "attack_paths"):
        data[key] = sorted(data.get(key, []), key=lambda item: str(item.get("id", "")))
    return data


def import_graph_json(document, *, source="memory"):
    result, doc = _load(document, "graph-json", source)
    if doc is None:
        return result
    nodes, edges = [], []
    node_ids, edge_ids = set(), set()
    for key, records, ids in (("nodes", nodes, node_ids), ("edges", edges, edge_ids)):
        if not isinstance(doc.get(key, []), list):
            result.diagnose(key, "expected array", "invalid")
            continue
        for index, raw in enumerate(doc.get(key, [])):
            try:
                if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
                    raise ValueError("record requires string id")
                record = deepcopy(raw)
                if record["id"] in ids:
                    raise ValueError("duplicate source ID; first record retained")
                if key == "nodes":
                    NodeType(record["type"])
                    NodeStatus(record.get("status", "discovered"))
                    if not isinstance(record.get("label"), str):
                        raise ValueError("node requires label")
                    record.setdefault("discovered_at", EPOCH)
                    datetime.fromisoformat(record["discovered_at"].replace("Z", "+00:00"))
                    record.setdefault("metadata", {})
                else:
                    EdgeType(record["type"])
                    if record.get("source") not in node_ids or record.get("target") not in node_ids:
                        raise ValueError("unresolved edge endpoint")
                    record.setdefault("created_at", EPOCH)
                    datetime.fromisoformat(record["created_at"].replace("Z", "+00:00"))
                    record.setdefault("weight", 1.0)
                    if isinstance(record["weight"], bool) or not isinstance(record["weight"], (int, float)) or not math.isfinite(record["weight"]):
                        raise ValueError("edge weight must be finite numeric")
                if not isinstance(record.get("properties", {}), dict):
                    raise ValueError("properties must be an object")
                if key == "nodes" and not isinstance(record.get("metadata", {}), dict):
                    raise ValueError("metadata must be an object")
                known = ({"id", "type", "label", "status", "properties", "metadata", "discovered_at"}
                         if key == "nodes" else {"id", "source", "target", "type", "label", "weight", "properties", "created_at"})
                extra = {name: deepcopy(value) for name, value in record.items() if name not in known}
                if extra:
                    record.setdefault("metadata" if key == "nodes" else "properties", {}).setdefault("interop_extensions", {}).update(extra)
                ids.add(record["id"])
                records.append(record)
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                result.diagnose(f"{key}/{index}", str(exc))
    paths = doc.get("attack_paths", [])
    paths = paths if isinstance(paths, list) else []
    valid_paths = []
    for index, path in enumerate(paths):
        if (isinstance(path, dict) and set(path).issubset({"id", "nodes", "edges", "risk_score", "description", "techniques"})
                and isinstance(path.get("id"), str) and isinstance(path.get("nodes", []), list)
                and isinstance(path.get("edges", []), list)
                and all(isinstance(item, str) for item in path.get("nodes", []) + path.get("edges", []))):
            valid_paths.append(path)
        else:
            result.diagnose(f"attack_paths/{index}", "unsupported path retained in raw")
    metadata = doc.get("metadata", {})
    if not isinstance(metadata, dict):
        result.diagnose("metadata", "metadata must be an object")
        metadata = {}
    result.graph = AttackGraph.from_dict({"nodes": nodes, "edges": edges, "attack_paths": valid_paths,
                                          "metadata": deepcopy(metadata)})
    result.extensions = {key: deepcopy(value) for key, value in doc.items()
                         if key not in {"nodes", "edges", "attack_paths", "statistics", "metadata"}}
    return result


def export_graph_csv(graph):
    """Return nodes/edges CSV plus a JSON metadata sidecar for round trips."""
    data = export_graph_json(graph)
    result = {}
    for key, fields in (("nodes", ["id", "type", "label", "status", "properties", "metadata", "discovered_at"]),
                        ("edges", ["id", "source", "target", "type", "label", "weight", "properties", "created_at"])):
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in data[key]:
            writer.writerow({name: spreadsheet_safe(
                _json(value) if isinstance(value, (dict, list)) else value
            ) for name, value in row.items()})
        result[key] = output.getvalue()
    result["metadata"] = _json({"metadata": data.get("metadata", {}),
                                "attack_paths": data.get("attack_paths", []),
                                "csv_formula_neutralized": True})
    return result


def import_graph_csv(document, *, source="memory"):
    """Import CSV texts from export_graph_csv or AttackGraph.to_csv."""
    result = AttackImportResult("graph-csv", source, raw=deepcopy(document))
    if not isinstance(document, Mapping):
        result.diagnose("$", "expected nodes/edges CSV mapping", "invalid")
        return result
    data = {"nodes": [], "edges": []}
    neutralized = False
    if "metadata" in document:
        try:
            neutralized = bool(json.loads(document["metadata"]).get("csv_formula_neutralized"))
        except (AttributeError, TypeError, ValueError):
            pass
    for key in ("nodes", "edges"):
        try:
            text = document.get(key, "")
            if not isinstance(text, str):
                raise ValueError("CSV text must be a string")
            reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
            required = {"id", "type", "label"} if key == "nodes" else {"id", "source", "target", "type"}
            if text and not required.issubset(reader.fieldnames or []):
                raise ValueError("CSV is missing required column headers")
            for index, row in enumerate(reader):
                try:
                    if neutralized:
                        row = {name: restore_spreadsheet_value(value) for name, value in row.items()}
                    for name in ("properties", "metadata"):
                        if name in row:
                            row[name] = json.loads(row[name] or "{}")
                    if key == "edges":
                        row["weight"] = float(row.get("weight") or 1)
                    data[key].append(row)
                except (TypeError, ValueError) as exc:
                    result.diagnose(f"{key}/{index}", str(exc))
        except (ValueError, TypeError, csv.Error) as exc:
            result.diagnose(key, str(exc), "invalid")
    if "metadata" in document:
        try:
            metadata = json.loads(document["metadata"])
            if not isinstance(metadata, dict):
                raise ValueError("metadata sidecar must be an object")
            data.update({key: metadata[key] for key in ("metadata", "attack_paths") if key in metadata})
        except (ValueError, TypeError) as exc:
            result.diagnose("metadata", str(exc))
    imported = import_graph_json(data, source=source)
    result.graph, result.extensions = imported.graph, imported.extensions
    if imported.status == "invalid":
        result.status = "invalid"
    for diagnostic in imported.diagnostics:
        result.diagnose(diagnostic["path"], diagnostic["message"])
    return result


# Short names for callers that already select the format in their command/API.
export_navigator = export_navigator_layer
import_navigator = import_navigator_layer
export_stix = export_stix_bundle
import_stix = import_stix_bundle
