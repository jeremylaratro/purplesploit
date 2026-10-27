"""Versioned, lossless offline interchange and supported Tier-1 projections.

The canonical document is JSON, independent of persistence. External formats
project their supported fields and carry a namespaced canonical snapshot for a
lossless PurpleSploit round trip. Consumers that discard that extension retain
only the documented native subset; mapping diagnostics make this explicit.
"""

from __future__ import annotations

from copy import deepcopy
import csv
from purplesploit.core.output_security import spreadsheet_safe
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
import hashlib
import io
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "purplesploit/canonical/1"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "canonical-v1.schema.json"
NAMESPACE = "purplesploit.canonical"
COLLECTIONS = ("assets", "services", "identities", "resources", "executions", "observations", "findings", "evidence")
ID_KEYS = {"executions": "request_id", "observations": "observation_id"}


def _known_fields(kind):
    from purplesploit.core.execution import ExecutionResult, Observation
    from purplesploit.core.findings import Evidence, Finding
    model = {"findings": Finding, "evidence": Evidence, "observations": Observation,
             "executions": ExecutionResult}.get(kind)
    if model:
        return set(model.__dataclass_fields__) | {"extensions", "source_id", "rule_id", "fingerprints", "locations", "asset_ids", "evidence_refs", "ref", "media_type"}
    return {"id", "kind", "type", "name", "label", "target", "address", "addresses", "hostname", "hostnames", "port", "protocol", "service", "version", "properties", "metadata", "extensions", "status", "discovered_at", "source", "target", "weight", "created_at", "observation_id", "attributes", "source_execution_id", "module_path", "operation_name", "observed_at", "confidence", "engagement_id", "asset_id", "source_id", "evidence_refs"}


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json(value):
    """Decode without silently overwriting duplicate source keys."""
    return json.loads(value, object_pairs_hook=_pairs)


def _plain(value):
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("Canonical object keys must be strings")
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, set):
        return sorted((_plain(item) for item in value), key=_json)
    return value


def stable_id(kind: str, value: Any) -> str:
    return f"{kind}:" + hashlib.sha256(_json(_plain(value)).encode()).hexdigest()[:32]


def _preserve_fields(value, unknown, label):
    if not unknown:
        return
    extensions = value.setdefault("extensions", {})
    if not isinstance(extensions, dict):
        raise ValueError(f"{label} extensions must be an object")
    fields = extensions.setdefault("source_fields", {})
    if not isinstance(fields, dict):
        raise ValueError(f"{label} extensions.source_fields must be an object")
    for name, item in unknown.items():
        if name in fields and fields[name] != item:
            raise ValueError(f"{label} conflicting preserved source field: {name}")
        fields[name] = item


def _records(values, kind):
    if not isinstance(values, list):
        raise ValueError(f"{kind} must be an array")
    result = []
    for value in values:
        value = _plain(value)
        if not isinstance(value, dict):
            raise ValueError(f"{kind} entries must be objects")
        key = ID_KEYS.get(kind, "id")
        value.setdefault(key, stable_id(kind, value))
        unknown = {name: value.pop(name) for name in list(value) if name not in _known_fields(kind)}
        _preserve_fields(value, unknown, kind)
        result.append(value)
    return sorted(result, key=lambda item: (str(item.get(ID_KEYS.get(kind, "id"), "")), _json(item)))


def _structural(value, schema, path="$", root=None):
    """Validate the schema's supported keywords without an optional dependency."""
    root = root or schema
    if "$ref" in schema:
        target = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        return _structural(value, target, path, root)
    if "anyOf" in schema:
        for option in schema["anyOf"]:
            try:
                _structural(value, option, path, root)
                return
            except ValueError:
                pass
        raise ValueError(f"{path}: no supported shape matched")
    types = {"object": lambda x: isinstance(x, dict), "array": lambda x: isinstance(x, list),
             "string": lambda x: isinstance(x, str), "integer": lambda x: type(x) is int,
             "number": lambda x: type(x) in (int, float), "boolean": lambda x: type(x) is bool,
             "null": lambda x: x is None}
    expected = schema.get("type")
    if expected and not any(types[name](value) for name in (expected if isinstance(expected, list) else [expected])):
        raise ValueError(f"{path}: expected {expected}")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path}: unsupported value {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: invalid value {value!r}")
    if isinstance(value, str) and len(value) < schema.get("minLength", 0):
        raise ValueError(f"{path}: empty string")
    if type(value) in (int, float):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise ValueError(f"{path}: out of range")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                raise ValueError(f"{path}.{key}: required")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                _structural(item, properties[key], f"{path}.{key}", root)
            elif schema.get("additionalProperties") is False:
                raise ValueError(f"{path}.{key}: unknown field; use extensions")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _structural(item, schema.get("items", {}), f"{path}[{index}]", root)


def validate_document(value: dict, *, use_jsonschema: bool = True) -> None:
    try:
        _json(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Canonical document must contain finite JSON values") from exc
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    _structural(value, schema)
    if use_jsonschema:
        try:
            import jsonschema
        except ImportError:
            pass
        else:
            try:
                jsonschema.Draft202012Validator(schema).validate(value)
            except jsonschema.ValidationError as exc:
                raise ValueError(f"Canonical schema: {exc.message}") from exc
    for kind in (*COLLECTIONS, "nodes", "edges"):
        records = value["graph"][kind] if kind in {"nodes", "edges"} else value[kind]
        key = ID_KEYS.get(kind, "id")
        identities = [item[key] for item in records]
        if len(set(identities)) != len(identities):
            raise ValueError(f"Duplicate {kind} {key}")
    nodes = {item["id"] for item in value["graph"]["nodes"]}
    for edge in value["graph"]["edges"]:
        if edge["source"] not in nodes or edge["target"] not in nodes:
            raise ValueError("Graph edge references an absent node")


@dataclass
class CanonicalDocument:
    """Immutable-by-copy JSON boundary. No timestamps or random IDs are invented."""
    data: dict[str, Any]

    @classmethod
    def from_mapping(cls, value: dict) -> "CanonicalDocument":
        value = _plain(deepcopy(value))
        if not isinstance(value, dict):
            raise ValueError("Canonical document must be an object")
        value.setdefault("schema_version", SCHEMA_VERSION)
        value.setdefault("engagement", None)
        value.setdefault("assessment", None)
        value.setdefault("extensions", {})
        if not isinstance(value["extensions"], dict):
            raise ValueError("extensions must be an object")
        known = {*COLLECTIONS, "schema_version", "engagement", "assessment", "graph", "extensions"}
        unknown = {key: value.pop(key) for key in list(value) if key not in known}
        _preserve_fields(value, unknown, "document")
        for kind in COLLECTIONS:
            value[kind] = _records(value.get(kind, []), kind)
        graph = value.setdefault("graph", {})
        if not isinstance(graph, dict):
            raise ValueError("graph must be an object")
        graph.setdefault("extensions", {})
        unknown = {name: graph.pop(name) for name in list(graph) if name not in {"nodes", "edges", "extensions", "metadata", "attack_paths", "statistics"}}
        _preserve_fields(graph, unknown, "graph")
        for kind in ("nodes", "edges"):
            graph[kind] = _records(graph.get(kind, []), kind)
        result = cls(value)
        result.validate()
        return result

    @classmethod
    def from_components(cls, *, engagement=None, assessment=None, graph=None, **collections):
        graph = _plain(graph) if graph is not None else {}
        if graph:
            # Native graph uses source/target already; retain paths/statistics too.
            graph = deepcopy(graph)
        return cls.from_mapping({"engagement": _plain(engagement), "assessment": _plain(assessment),
                                 "graph": graph, **{key: _plain(value) for key, value in collections.items()}})

    @classmethod
    def from_json(cls, value: str):
        return cls.from_mapping(load_json(value))

    def to_dict(self):
        return deepcopy(self.data)

    def to_json(self, *, indent: int | None = 2):
        return json.dumps(self.data, sort_keys=True, ensure_ascii=False, indent=indent, allow_nan=False) + "\n"

    def validate(self, *, use_jsonschema=True):
        validate_document(self.data, use_jsonschema=use_jsonschema)

    def to_components(self):
        """Return lossless mappings; callers choose native model conversion."""
        return self.to_dict()


@dataclass
class MappingResult:
    data: Any = None
    document: CanonicalDocument | None = None
    diagnostics: list[str] = field(default_factory=list)


def _document(value):
    document = value if isinstance(value, CanonicalDocument) else CanonicalDocument.from_mapping(value)
    document.validate()
    return document


def export_csv(value) -> MappingResult:
    """Mixed finding/asset CSV with a document row and JSON extension column."""
    document = _document(value)
    output = io.StringIO(newline="")
    columns = ("record_type", "id", "title", "severity", "description", "target", "port", "protocol", "canonical_json")
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerow({"record_type": "document", "canonical_json": _json(document.to_dict())})
    for kind in ("assets", "findings"):
        for record in document.data[kind]:
            writer.writerow({"record_type": kind[:-1],
                             **{key: spreadsheet_safe(record.get(key, "")) for key in columns[1:-1]},
                             "canonical_json": _json(record)})
    return MappingResult(data=output.getvalue(), diagnostics=["CSV native subset: assets/findings; canonical_json document row preserves all other fields."])


def import_csv(source: str) -> MappingResult:
    if not isinstance(source, str):
        raise ValueError("CSV import requires text")
    reader = csv.DictReader(io.StringIO(source.lstrip("\ufeff")))
    if not reader.fieldnames or "record_type" not in reader.fieldnames:
        raise ValueError("CSV requires record_type (finding or asset)")
    if len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise ValueError("CSV has duplicate columns")
    rows, snapshot, diagnostics = {"assets": [], "findings": []}, None, []
    for index, row in enumerate(reader, 2):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"Malformed CSV row {index}")
        kind = row["record_type"]
        if kind == "document":
            if snapshot is not None or not row.get("canonical_json"):
                raise ValueError("CSV requires exactly one valid document snapshot when supplied")
            if any(value for key, value in row.items() if key not in {"record_type", "canonical_json"}):
                raise ValueError("CSV document row contains fields outside its snapshot")
            snapshot = CanonicalDocument.from_json(row["canonical_json"])
            continue
        if kind not in {"finding", "asset"}:
            raise ValueError(f"Unsupported CSV record_type at row {index}: {kind!r}")
        if row.get("canonical_json"):
            record = load_json(row["canonical_json"])
            if not isinstance(record, dict):
                raise ValueError(f"CSV canonical_json row {index} must be an object")
            for key, value in row.items():
                if key in {"record_type", "canonical_json"}:
                    continue
                expected = record.get(key)
                expected = "" if expected is None else str(expected)
                if value != expected and value != spreadsheet_safe(expected):
                    raise ValueError(f"CSV row {index} {key} conflicts with canonical_json")
        else:
            record = {key: value for key, value in row.items() if value and key in {"id", "title", "severity", "description", "target", "protocol"}}
            if row.get("port"):
                record["port"] = int(row["port"])
            unknown = {key: value for key, value in row.items() if key not in {"record_type", "canonical_json", "id", "title", "severity", "description", "target", "port", "protocol"}}
            if unknown:
                record["extensions"] = {"csv": unknown}
            if kind == "finding":
                record.setdefault("title", "Imported finding")
                record.setdefault("severity", "info")
        rows[kind + "s"].append(record)
    if snapshot is not None:
        for kind in rows:
            if _records(rows[kind], kind) != snapshot.data[kind]:
                raise ValueError("CSV snapshot conflicts with native rows")
        document = snapshot
        diagnostics.append("Restored canonical document snapshot.")
    else:
        document = CanonicalDocument.from_mapping(rows)
        diagnostics.append("Imported CSV native finding/asset subset.")
    return MappingResult(document=document, diagnostics=diagnostics)


def export_sarif(value) -> MappingResult:
    document = _document(value)
    rules, results = {}, []
    for finding in document.data["findings"]:
        rule = str(finding.get("rule_id") or finding.get("module_name") or next(iter(finding.get("cwe_ids", [])), None) or "purplesploit.finding")
        rules.setdefault(rule, {"id": rule, "shortDescription": {"text": finding.get("title", "Finding")}})
        severity = finding.get("severity", "info")
        score = finding.get("cvss_score")
        if score is None:
            score = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.0}.get(severity, 0)
        result = {"ruleId": rule, "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(severity, "note"),
                  "message": {"text": finding.get("description") or finding.get("title", "Finding")},
                  "partialFingerprints": {**finding.get("fingerprints", {}), "purplesploit/id/v1": finding["id"]},
                  "properties": {NAMESPACE: deepcopy(finding), "security-severity": str(score)}}
        location = finding.get("url") or finding.get("target")
        if location:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": location}}}]
        if finding.get("locations"):
            result["locations"] = deepcopy(finding["locations"])
        results.append(result)
    data = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "PurpleSploit", "rules": [rules[key] for key in sorted(rules)]}}, "results": results, "properties": {NAMESPACE: document.to_dict()}}]}
    return MappingResult(data=data, diagnostics=["SARIF 2.1 native subset: findings, rules, severity, locations, fingerprints; run properties preserve canonical data."])


def _load_json(value):
    return load_json(value) if isinstance(value, str) else deepcopy(value)


def import_sarif(value) -> MappingResult:
    value = _load_json(value)
    if not isinstance(value, dict) or value.get("version") != "2.1.0" or not isinstance(value.get("runs"), list):
        raise ValueError("Expected SARIF 2.1.0 runs array")
    if any(not isinstance(run, dict) or not isinstance(run.get("properties", {}), dict) for run in value["runs"]):
        raise ValueError("SARIF runs and properties must be objects")
    snapshots = [run.get("properties", {}).get(NAMESPACE) for run in value["runs"]]
    if len(snapshots) == 1 and snapshots[0] is not None:
        document = CanonicalDocument.from_mapping(snapshots[0])
        if export_sarif(document).data != value:
            raise ValueError("SARIF canonical snapshot conflicts with native payload; remove the run snapshot to import native edits")
        return MappingResult(document=document, diagnostics=["Restored canonical SARIF run properties."])
    findings, diagnostics = [], []
    for run_index, run in enumerate(value["runs"]):
        if not isinstance(run.get("tool"), dict) or not isinstance(run["tool"].get("driver"), dict) or not isinstance(run["tool"]["driver"].get("name"), str):
            raise ValueError("SARIF run requires tool.driver.name")
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        if not isinstance(rules, list) or any(not isinstance(rule, dict) or not isinstance(rule.get("id"), str) for rule in rules):
            raise ValueError("SARIF rules must be objects with string IDs")
        rule_map = {rule.get("id"): rule for rule in rules}
        if not isinstance(run.get("results", []), list):
            raise ValueError("SARIF results must be an array")
        for item in run.get("results", []):
            if not isinstance(item, dict):
                raise ValueError("SARIF result must be an object")
            if not isinstance(item.get("message"), dict) or not any(isinstance(item["message"].get(key), str) for key in ("text", "markdown")):
                raise ValueError("SARIF result requires message text or markdown")
            if item.get("properties", {}).get(NAMESPACE):
                findings.append(deepcopy(item["properties"][NAMESPACE]))
                continue
            rule_id = item.get("ruleId")
            if rule_id is None and "ruleIndex" in item:
                if type(item["ruleIndex"]) is not int or item["ruleIndex"] < 0:
                    raise ValueError("Invalid SARIF ruleIndex")
                try:
                    rule_id = rules[item["ruleIndex"]]["id"]
                except (IndexError, KeyError, TypeError) as exc:
                    raise ValueError("Invalid SARIF ruleIndex") from exc
            rule = rule_map.get(rule_id, {})
            fingerprints = item.get("partialFingerprints") or item.get("fingerprints") or {}
            if not isinstance(fingerprints, dict) or any(not isinstance(part, str) for part in fingerprints.values()):
                raise ValueError("SARIF fingerprints must be an object of strings")
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            identity = fingerprints.get("purplesploit/id/v1") or item.get("guid") or stable_id("sarif", [tool_name, rule_id, fingerprints or item])
            location = next(iter(item.get("locations", [])), {}).get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            score = item.get("properties", {}).get("security-severity", rule.get("properties", {}).get("security-severity"))
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError) as exc:
                raise ValueError("Invalid SARIF security-severity") from exc
            severity = ("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info") if score is not None else {"error": "high", "warning": "medium", "note": "info", "none": "info"}.get(item.get("level", "warning"), "info")
            findings.append({"id": identity, "source_id": identity, "title": rule.get("shortDescription", {}).get("text") or str(rule_id or "SARIF finding"), "description": item.get("message", {}).get("text", item.get("message", {}).get("markdown", "")), "severity": severity, "target": location, "rule_id": rule_id, "cvss_score": score, "fingerprints": fingerprints, "locations": deepcopy(item.get("locations", [])), "extensions": {"sarif": {"result": item, "rule": rule, "run_index": run_index}}})
    findings = _unique_findings(findings, diagnostics)
    return MappingResult(document=CanonicalDocument.from_mapping({"findings": findings, "extensions": {"sarif": value}}), diagnostics=[*diagnostics, "SARIF source envelope retained under extensions.sarif."])


def _unique_findings(findings, diagnostics):
    seen, result = {}, []
    for finding in findings:
        original = finding["id"]
        if original in seen:
            if seen[original] == finding:
                diagnostics.append(f"Identical duplicate source finding {original} collapsed.")
                continue
            finding = deepcopy(finding)
            finding.setdefault("extensions", {})["duplicate_source_id"] = original
            finding["id"] = stable_id("source-occurrence", finding)
            diagnostics.append(f"Conflicting duplicate source ID {original} preserved as {finding['id']}.")
            if finding["id"] in seen and seen[finding["id"]] == finding:
                diagnostics.append(f"Identical duplicate occurrence {finding['id']} collapsed.")
                continue
        seen[finding["id"]] = finding
        result.append(finding)
    return result


def export_defectdojo(value) -> MappingResult:
    document = _document(value)
    records = []
    for finding in document.data["findings"]:
        record = {"title": finding.get("title", "Finding"), "description": finding.get("description", ""),
                  "severity": {"info": "Info"}.get(finding.get("severity"), str(finding.get("severity", "info")).capitalize()),
                  "mitigation": finding.get("remediation", ""), "references": "\n".join(finding.get("references", [])),
                  "unique_id_from_tool": finding["id"], "vuln_id_from_tool": finding.get("rule_id", finding.get("module_name", "")),
                  "active": finding.get("status") not in {"remediated", "verified", "false_positive"},
                  "verified": finding.get("status") in {"confirmed", "reported", "verified"},
                  "false_p": finding.get("status") == "false_positive", "duplicate": bool(finding.get("duplicate_of")),
                  "purplesploit": deepcopy(finding)}
        if finding.get("target") or finding.get("url"):
            record["endpoints"] = [{"host": finding.get("target") or finding.get("url"), **({"port": finding["port"]} if finding.get("port") else {})}]
        if finding.get("cvss_score") is not None:
            record["cvssv3_score"] = finding["cvss_score"]
        records.append(record)
    return MappingResult(data={"findings": records, "purplesploit": {"canonical": document.to_dict()}}, diagnostics=["DefectDojo Generic Findings native subset; purplesploit extension preserves lifecycle, graph, assessment and unsupported fields."])


def import_defectdojo(value) -> MappingResult:
    value = _load_json(value)
    if not isinstance(value, dict) or not isinstance(value.get("findings"), list):
        raise ValueError("Expected DefectDojo Generic Findings findings array")
    if not isinstance(value.get("purplesploit", {}), dict):
        raise ValueError("DefectDojo purplesploit extension must be an object")
    if value.get("purplesploit", {}).get("canonical") is not None:
        document = CanonicalDocument.from_mapping(value["purplesploit"]["canonical"])
        if export_defectdojo(document).data != value:
            raise ValueError("DefectDojo canonical snapshot conflicts with native payload; remove the root snapshot to import native edits")
        return MappingResult(document=document, diagnostics=["Restored canonical DefectDojo extension."])
    findings, diagnostics = [], []
    for item in value["findings"]:
        if not isinstance(item, dict) or not isinstance(item.get("title"), str) or not item["title"]:
            raise ValueError("DefectDojo finding requires a title")
        if item.get("purplesploit"):
            findings.append(deepcopy(item["purplesploit"]))
            continue
        if not isinstance(item.get("endpoints", []), list):
            raise ValueError("DefectDojo endpoints must be an array")
        severity = str(item.get("severity", "Info")).lower()
        severity = "info" if severity == "informational" else severity
        endpoint = next(iter(item.get("endpoints", [])), {})
        if not isinstance(endpoint, (str, dict)):
            raise ValueError("DefectDojo endpoints must contain strings or objects")
        target = endpoint if isinstance(endpoint, str) else endpoint.get("host", "")
        source_id = item.get("unique_id_from_tool")
        record = {"id": str(source_id) if source_id is not None else stable_id("defectdojo", item), "source_id": str(source_id) if source_id is not None else None, "title": item["title"], "severity": severity,
                  "description": item.get("description", ""), "remediation": item.get("mitigation", ""), "target": target,
                  "references": item.get("references", "").splitlines() if isinstance(item.get("references", ""), str) else item["references"],
                  "status": "false_positive" if item.get("false_p") else "remediated" if item.get("active") is False else "confirmed" if item.get("verified") else "draft",
                  "extensions": {"defectdojo": deepcopy(item)}}
        if isinstance(endpoint, dict) and endpoint.get("port") is not None:
            record["port"] = int(endpoint["port"])
        if item.get("duplicate"):
            diagnostics.append(f"Source finding {record['id']} is marked duplicate; Generic Findings provides no canonical duplicate target.")
        findings.append(record)
    return MappingResult(document=CanonicalDocument.from_mapping({"findings": _unique_findings(findings, diagnostics), "extensions": {"defectdojo": value}}), diagnostics=diagnostics)


# Explicit names used by integrations which distinguish Generic Findings.
export_defectdojo_generic = export_defectdojo
import_defectdojo_generic = import_defectdojo
