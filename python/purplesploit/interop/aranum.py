"""Offline ingestion of current Aranum output, without an Aranum dependency.

``import_aranum_bundle(root)`` reads snapshots, never launches a producer.
``bundle.merge_into(observations, findings)`` imports exact occurrences once.
Producer metadata lives in Observation.attributes so it survives the common
execution envelope without imposing Aranum fields on every other backend.
"""

from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from purplesploit.core.auto_enum import AutoEnumPipeline
from purplesploit.core.execution import Observation
from purplesploit.core.findings import Evidence, Finding, FindingStatus, Severity


INVENTORY_SCHEMA = "aranum/inventory-unversioned;adapter=1"


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ValueError("Aranum port must be an integer")
    number = int(value)
    if str(number) != str(value) or not 1 <= number <= 65535:
        raise ValueError(f"Invalid Aranum port: {value!r}")
    return number


def _host(record: dict) -> str:
    return str(record.get("ip") or record.get("host") or record.get("target") or "")


def _artifacts(record: Any, root: Path) -> list[dict[str, Any]]:
    """Keep literal references; resolve only files which actually exist."""
    references: list[str] = []

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"evidence_path", "evidence_paths", "artifact", "artifacts", "source"}:
                    candidates = item if isinstance(item, list) else [item]
                    references.extend(candidate for candidate in candidates if isinstance(candidate, str) and candidate)
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(record)
    result = []
    for reference in dict.fromkeys(references):
        path = Path(reference)
        candidate = path if path.is_absolute() else root / path
        exists = candidate.is_file()
        result.append({"reference": reference, "resolved_path": str(candidate.resolve()) if exists else None,
                       "exists": exists})
    return result


@dataclass
class AranumBundle:
    """Portable observations plus an explicit, narrower lifecycle projection.

    run_id is None when the producer did not publish one. The fingerprint then
    identifies this exact snapshot, never a claimed producer run or cache key.
    """

    run_root: Path
    bundle_fingerprint: str
    run_id: str | None
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def merge_into(self, observations: list[Observation], findings: list[Finding]) -> dict[str, int]:
        """Append unseen occurrences, preserving existing operator-edited objects."""
        observation_ids = {item.observation_id for item in observations}
        finding_ids = {item.id for item in findings}
        added_observations = [item for item in self.observations if item.observation_id not in observation_ids]
        added_findings = [item for item in self.findings if item.id not in finding_ids]
        observations.extend(added_observations)
        findings.extend(added_findings)
        return {"observations": len(added_observations), "findings": len(added_findings)}

    def seed_auto_enum(self, pipeline: AutoEnumPipeline) -> int:
        """Seed explicit open inventory endpoints; portless hosts remain observations."""
        seeds = []
        for item in self.observations:
            if item.kind != "service" or item.attributes.get("record_type") != "inventory_endpoint":
                continue
            if item.attributes["raw"].get("state", "open") != "open":
                continue
            seeds.append({**item.to_dict(), **item.attributes})
        return pipeline.ingest_seeds(seeds, source="aranum")


def seed_auto_enum(bundle: AranumBundle, pipeline: AutoEnumPipeline) -> int:
    """Seed a pipeline; call pipeline.run(targets, skip_discovery=True) to follow up.

    Callers choose service_rules explicitly before run; this helper never launches
    the default collection of overlapping follow-ups as a side effect of import.
    """
    return bundle.seed_auto_enum(pipeline)


def import_aranum_bundle(run_root: str | Path, *, tool_version: str | None = None) -> AranumBundle:
    """Read inventory.json and optional findings v2, posture v1 and run snapshots.

    The explicit root is also the base for evidence paths. Unknown companion
    schemas fail clearly instead of being interpreted as the supported schema.
    No installed producer, network connection, datastore or launcher is needed.
    """
    root = Path(run_root).resolve()
    documents = {}
    for name in ("inventory.json", "findings.json", "posture.json", "run-state.json"):
        path = root / name
        if name != "inventory.json" and not path.exists():
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError(f"{name} must contain an object")
        documents[name] = document
    for name, expected in (("findings.json", "2"), ("posture.json", "1"), ("run-state.json", "1")):
        if name in documents and str(documents[name].get("schema_version")) != expected:
            raise ValueError(f"Unsupported {name} schema: {documents[name].get('schema_version')!r}")
    inventory = documents["inventory.json"]
    if not isinstance(inventory.get("hosts"), list) or not isinstance(inventory.get("entries"), list):
        raise ValueError("inventory.json requires hosts[] and entries[]")
    queue_path = root / "queue.state.jsonl"
    queue = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines() if line.strip()] if queue_path.exists() else []
    if any(not isinstance(item, dict) for item in queue):
        raise ValueError("queue.state.jsonl records must be objects")
    fingerprint = _digest({**documents, "queue.state.jsonl": queue})
    run_ids = {str(doc["run_id"]) for doc in [*documents.values(), *queue] if doc.get("run_id") is not None}
    if len(run_ids) > 1:
        raise ValueError("Aranum bundle contains conflicting run IDs")
    run_id = next(iter(run_ids), None)
    occurrence = run_id if run_id is not None else f"bundle:{fingerprint}"
    bundle = AranumBundle(root, fingerprint, run_id)
    seen: set[str] = set()

    def add(filename, record, record_type, *, kind="note", target="", record_key=None, **extra):
        document = documents.get(filename, {})
        schema = INVENTORY_SCHEMA if filename == "inventory.json" else f"aranum/{filename.removesuffix('.json')}/{document.get('schema_version', 'unversioned')}"
        source_id = record.get("finding_id") or record.get("source_id") or record.get("task_id") or record.get("id")
        key = record_key if record_key is not None else source_id or _digest(record)
        identity = ["aranum", schema, filename, record_type, occurrence, key]
        identifier = str(uuid5(NAMESPACE_URL, json.dumps(identity, sort_keys=True)))
        protocol = record.get("proto") or record.get("protocol") or None
        raw_service = record.get("service")
        service = AutoEnumPipeline.SERVICE_ALIASES.get(str(raw_service).lower(), raw_service) if raw_service else None
        if service == "http" and record.get("tunnel") in {"ssl", "tls"}:
            service = "https"
        subject = {"host": target, "port": _port(record.get("port")), "transport": protocol,
                   "service": service, "version": record.get("version"), "hostname": record.get("hostname"),
                   "url": record.get("url")}
        attributes = {"source_tool": "aranum", "source_tool_version": tool_version or document.get("tool_version"),
                      "source_schema": schema, "source_id": source_id, "run_id": run_id,
                      "bundle_fingerprint": fingerprint, "source_file": filename,
                      "record_type": record_type, "subject": subject, "raw": record,
                      "raw_service": raw_service, "hostname": record.get("hostname"),
                      "product": record.get("product"), "extrainfo": record.get("extrainfo"),
                      "tunnel": record.get("tunnel"), "categories": record.get("categories"),
                      "artifacts": _artifacts(record, root), **extra}
        observed_at = record.get("observed_at") or record.get("ts") or document.get("generated_utc")
        attributes["observed_at"] = observed_at
        observation = Observation(kind=kind, target=target, port=subject["port"], protocol=protocol,
                                  service=service, version=record.get("version"), attributes=attributes,
                                  source_execution_id=f"aranum:{occurrence}", module_path="interop/aranum",
                                  observed_at=observed_at, observation_id=identifier)
        if identifier not in seen:
            bundle.observations.append(observation)
            seen.add(identifier)
        return observation

    for filename, document in documents.items():
        # Preserve partial flags, summaries, quarantined records and diagnostics.
        metadata = {key: value for key, value in document.items() if key not in {"hosts", "entries", "findings", "domains", "services"}}
        add(filename, metadata, "snapshot_metadata", record_key="metadata")
    for record in inventory["hosts"]:
        add("inventory.json", record, "inventory_host", kind="host", target=_host(record))
    for record in inventory["entries"]:
        add("inventory.json", record, "inventory_endpoint", kind="service", target=_host(record))

    findings_document = documents.get("findings.json", {})
    for record in findings_document.get("findings", []):
        observation = add("findings.json", record, "canonical_finding", kind="finding", target=_host(record),
                          source_triage_status=record.get("triage_status"),
                          lifecycle_status="draft" if record.get("triage_status") == "new" else None)
        if any(item.id == observation.observation_id for item in bundle.findings):
            continue
        severity = str(record.get("severity", "info")).lower()
        finding = Finding(id=observation.observation_id, title=record.get("title") or record.get("line", ""),
                          severity=Severity(severity) if severity in {item.value for item in Severity} else Severity.INFO,
                          status=FindingStatus.DRAFT, target=observation.target, port=observation.port,
                          service=observation.service, protocol=observation.protocol, url=record.get("url"),
                          description=record.get("line", ""), module_name="interop/aranum",
                          raw_output=json.dumps(observation.attributes, sort_keys=True),
                          tags=list(record.get("tags") or []))
        if record.get("triage_status") != "new":
            finding.notes.append(f"Source triage status {record.get('triage_status')!r} is unmapped; DRAFT is the projection default.")
        for artifact in observation.attributes["artifacts"]:
            finding.evidence.append(Evidence(id=str(uuid5(NAMESPACE_URL, f"{finding.id}:{artifact['reference']}")),
                                            finding_id=finding.id, title=artifact["reference"],
                                            file_path=artifact["resolved_path"],
                                            description=f"Aranum source reference: {artifact['reference']}"))
        bundle.findings.append(finding)

    posture = documents.get("posture.json", {})
    for scope, records in (("host", posture.get("hosts", {})), ("domain", posture.get("domains", {}))):
        for target, host_record in records.items():
            add("posture.json", host_record, "posture_subject", kind=scope, target=target,
                record_key=[scope, target], scope=scope)
            for collection in ("checks", "domain_observations"):
                for check_id, record in host_record.get(collection, {}).items():
                    add("posture.json", record, "posture_check", kind="policy", target=target,
                        record_key=[scope, target, collection, check_id], check_id=check_id,
                        scope="domain" if collection == "domain_observations" else scope,
                        status=record.get("status"), observed_from=record.get("observed_from"),
                        artifacts=_artifacts({"source": host_record.get("source"), **record}, root))
    for record in documents.get("run-state.json", {}).get("services", []):
        add("run-state.json", record, "service_execution", target=_host(record), status=record.get("status"))
    for record in queue:
        add("queue.state.jsonl", record, "task_execution", target=_host(record), status=record.get("status"))
    return bundle
