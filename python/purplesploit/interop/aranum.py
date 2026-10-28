"""Forgiving, offline ingestion of Aranum bundles.

``import_aranum_bundle(root)`` never launches Aranum. The bundle manifest is
the import spine when present, while pre-manifest inventory bundles remain
readable. Producer records are retained in ``Observation.raw`` and malformed
input is represented as data-quality observations instead of aborting import.
The marker vocabulary is ``error``, ``interrupted``, ``unlisted``, ``partial``,
``quarantine``, ``redact``, ``stale``, ``unknown``, and ``digest_mismatch``.
"""

from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Callable
from uuid import NAMESPACE_URL, uuid5

from jsonschema import validators

from purplesploit.core.auto_enum import AutoEnumPipeline
from purplesploit.core.execution import AuthContext, Observation
from purplesploit.core.findings import Evidence, Finding, FindingStatus, Severity


INVENTORY_SCHEMA = "aranum/inventory-unversioned;adapter=1"
SCHEMA_FILES = {
    "bundle-manifest.json": "bundle-manifest-1.schema.json",
    "dispatchers.json": "dispatchers-1.schema.json",
    "findings.json": "findings-2.schema.json",
    "inventory.json": "inventory-1.schema.json",
    "posture.json": "posture-1.schema.json",
}
SCHEMA_ROOT = Path(__file__).resolve().parents[1] / "schemas" / "aranum"


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _exception_summary(exc: BaseException, limit: int = 300) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return f"{type(exc).__name__}: {text}"[:limit]


def _port(value: Any, on_error: Callable[[str], None] | None = None) -> int | None:
    """Normalize Aranum ports; zero/empty means a host-scoped record."""
    if value in (None, "", 0, "0"):
        return None
    try:
        if isinstance(value, bool):
            raise ValueError("boolean port")
        number = int(value)
        if str(number) != str(value) or not 1 <= number <= 65535:
            raise ValueError(f"invalid port {value!r}")
        return number
    except (TypeError, ValueError, OverflowError) as exc:
        if on_error is not None:
            on_error(f"invalid port {value!r}: {_exception_summary(exc)}")
        return None


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
                    references.extend(
                        candidate for candidate in candidates
                        if isinstance(candidate, str) and candidate
                    )
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(record)
    result = []
    for reference in dict.fromkeys(references):
        try:
            path = Path(reference)
            candidate = path if path.is_absolute() else root / path
            exists = candidate.is_file()
            resolved = str(candidate.resolve()) if exists else None
        except (OSError, TypeError, ValueError):
            exists, resolved = False, None
        result.append({"reference": reference, "resolved_path": resolved, "exists": exists})
    return result


def _auth_context(value: Any, on_error: Callable[[str], None]) -> AuthContext | None:
    """Project the open producer auth object onto PurpleSploit's stable fields."""
    if value is None:
        return None
    if not isinstance(value, dict):
        on_error("auth_context must be an object")
        return None
    projected = {
        "account_ref": value.get("account_ref", value.get("account_label")),
        "scope": value.get("scope"),
        "domain": value.get("domain"),
        "local_host": value.get("local_host"),
        "auth_method": value.get("auth_method"),
    }
    try:
        return AuthContext.from_dict(projected)
    except (TypeError, ValueError) as exc:
        on_error(f"invalid auth_context: {_exception_summary(exc)}")
        return None


def _step_text(value: Any) -> str:
    """Render KB fix/test steps without discarding their open-object fields."""
    if value is None:
        return ""
    values = value if isinstance(value, list) else [value]
    lines = []
    for item in values:
        if isinstance(item, dict):
            label = str(item.get("label") or "").strip()
            detail = str(item.get("text") or item.get("cmd") or item.get("step") or "").strip()
            extras = {key: val for key, val in item.items() if key not in {"label", "text", "cmd", "step"}}
            rendered = ": ".join(part for part in (label, detail) if part)
            if not rendered and extras:
                rendered = json.dumps(extras, sort_keys=True, ensure_ascii=False)
            lines.append(rendered)
        else:
            lines.append(str(item))
    return "\n".join(line for line in lines if line)


@dataclass
class AranumBundle:
    """Portable observations and findings from one producer occurrence."""

    run_root: Path
    bundle_fingerprint: str
    run_id: str | None
    status: str = "interrupted"
    extensions: dict[str, Any] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    kb: dict[str, Any] = field(default_factory=dict)

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
        """Seed explicit or findings-derived open endpoints."""
        seeds = []
        for item in self.observations:
            if item.kind != "service" or item.attributes.get("record_type") != "inventory_endpoint":
                continue
            if item.raw.get("state", "open") != "open":
                continue
            seeds.append({**item.to_dict(), **item.attributes})
        return pipeline.ingest_seeds(seeds, source="aranum")


def seed_auto_enum(bundle: AranumBundle, pipeline: AutoEnumPipeline) -> int:
    """Seed a pipeline without launching follow-ups as an import side effect."""
    return bundle.seed_auto_enum(pipeline)


def import_aranum_bundle(run_root: str | Path, *, tool_version: str | None = None) -> AranumBundle:
    """Import a bundle manifest-first and retain every salvageable record."""
    root = Path(run_root).resolve()
    pending_quality: list[tuple[str, str, str, Any]] = []

    def pending(marker: str, reason: str, source: str = "bundle", raw: Any = None) -> None:
        pending_quality.append((marker, reason[:500], source, raw))

    def load_object(path: Path, relative: str) -> dict[str, Any] | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError(f"{relative} must contain an object")
            return value
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            pending("error", f"{relative}: {_exception_summary(exc)}", relative)
            return None

    manifest_path = root / "bundle-manifest.json"
    try:
        manifest_present = manifest_path.is_file()
    except OSError as exc:
        pending("error", f"bundle-manifest.json: {_exception_summary(exc)}", "bundle-manifest.json")
        manifest_present = False
    manifest = load_object(manifest_path, "bundle-manifest.json") if manifest_present else None

    declared_paths: set[str] = set()
    if manifest is not None:
        files = manifest.get("files", [])
        if not isinstance(files, list):
            pending("error", "bundle-manifest.json: files must be an array", "bundle-manifest.json", files)
            files = []
        for item in files:
            path_value = item.get("path") if isinstance(item, dict) else item
            if not isinstance(path_value, str) or not path_value:
                pending("error", "bundle-manifest.json: invalid files entry", "bundle-manifest.json", item)
                continue
            declared_paths.add(Path(path_value).as_posix())
            candidate = root / path_value
            try:
                exists = candidate.is_file()
                if not exists:
                    pending("error", f"listed doc missing: {path_value}", "bundle-manifest.json", item)
            except OSError:
                pending("error", f"listed doc missing: {path_value}", "bundle-manifest.json", item)
                exists = False
            if exists and isinstance(item, dict) and "sha256" in item:
                try:
                    actual_digest = sha256(candidate.read_bytes()).hexdigest()
                except OSError as exc:
                    pending("error", f"{path_value}: {_exception_summary(exc)}", path_value, item)
                else:
                    if actual_digest != item.get("sha256"):
                        pending(
                            "digest_mismatch",
                            f"digest mismatch: {path_value}",
                            "bundle-manifest.json",
                            item,
                        )

        try:
            json_paths = sorted(path for path in root.rglob("*.json") if path.is_file())
        except OSError as exc:
            pending("error", f"bundle scan: {_exception_summary(exc)}")
            json_paths = []
        for path in json_paths:
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if relative in {"bundle-manifest.json", "inventory.json"} or relative in declared_paths:
                continue
            pending("unlisted", f"unlisted doc: {relative}", relative)

    documents: dict[str, dict[str, Any]] = {}
    supported = ("inventory.json", "findings.json", "posture.json", "run-state.json", "dispatchers.json")
    for name in supported:
        path = root / name
        try:
            exists = path.is_file()
        except OSError as exc:
            pending("error", f"{name}: {_exception_summary(exc)}", name)
            continue
        if not exists:
            continue
        if manifest is not None and name != "inventory.json" and name not in declared_paths:
            continue
        document = load_object(path, name)
        if document is not None:
            documents[name] = document

    queue: list[dict[str, Any]] = []
    queue_path = root / "queue.state.jsonl"
    try:
        if queue_path.is_file() and (manifest is None or "queue.state.jsonl" in declared_paths):
            for line_number, line in enumerate(queue_path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("record must be an object")
                    queue.append(record)
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    pending("error", f"queue.state.jsonl:{line_number}: {_exception_summary(exc)}", "queue.state.jsonl")
    except (OSError, UnicodeError) as exc:
        pending("error", f"queue.state.jsonl: {_exception_summary(exc)}", "queue.state.jsonl")

    fingerprint = _digest({**documents, "queue.state.jsonl": queue})
    findings_document = documents.get("findings.json", {})
    if manifest is not None:
        run_id_value = manifest.get("run_id")
    else:
        run_id_value = findings_document.get("run_id")
        if run_id_value is None:
            # Preserve inventory-only pre-P1 identities that were pinned by run-state.
            legacy_ids = {
                str(doc["run_id"]) for doc in [*documents.values(), *queue]
                if doc.get("run_id") is not None
            }
            if len(legacy_ids) == 1:
                run_id_value = next(iter(legacy_ids))
            elif len(legacy_ids) > 1:
                pending("error", "Aranum bundle contains conflicting run IDs")
    run_id = str(run_id_value) if run_id_value is not None else None
    occurrence = run_id if run_id is not None else f"bundle:{fingerprint}"
    status = str(manifest.get("status") or "unknown") if manifest is not None else "interrupted"
    bundle = AranumBundle(root, fingerprint, run_id, status, {"status": status})
    seen: set[str] = set()

    def quality(marker: str, reason: str, source: str = "bundle", raw: Any = None) -> None:
        record = raw if isinstance(raw, dict) else {"marker": marker, "reason": reason, "value": raw}
        identity = ["aranum", "data_quality", occurrence, marker, source, reason]
        identifier = str(uuid5(NAMESPACE_URL, json.dumps(identity, sort_keys=True)))
        if identifier in seen:
            return
        observation = Observation(
            kind="note", target=_host(record),
            attributes={
                "run_id": run_id, "bundle_fingerprint": fingerprint,
                "source_file": source, "record_type": "data_quality",
                "marker": marker, "reason": reason,
                "subject": {"host": _host(record), "port": None, "transport": None,
                            "service": None, "version": None, "hostname": None, "url": None},
                "artifacts": _artifacts(record, root), "observed_at": None,
            },
            source_tool="aranum", source_tool_version=tool_version,
            source_schema="aranum/data-quality/1", raw=record,
            source_execution_id=f"aranum:{occurrence}", module_path="interop/aranum",
            observed_at=None, observation_id=identifier,
        )
        bundle.observations.append(observation)
        seen.add(identifier)

    for item in pending_quality:
        quality(*item)
    if manifest is None:
        quality("interrupted", "no bundle-manifest.json", "bundle-manifest.json")

    def add(filename, record, record_type, *, kind="note", target="", record_key=None,
            auth_context=None, **extra):
        if not isinstance(record, dict):
            quality("error", f"{filename} {record_type} record must be an object", filename, {"value": record})
            return None
        document = manifest if filename == "bundle-manifest.json" else documents.get(filename, {})
        document = document or {}
        schema = (
            INVENTORY_SCHEMA if filename == "inventory.json"
            else f"aranum/{filename.removesuffix('.json')}/{document.get('schema_version', 'unversioned')}"
        )
        source_id = (
            record.get("finding_id") or record.get("_finding_id") or record.get("source_id")
            or record.get("_source_id") or record.get("task_id") or record.get("id")
        )
        key = record_key if record_key is not None else source_id or _digest(record)
        identity = ["aranum", schema, filename, record_type, occurrence, key]
        identifier = str(uuid5(NAMESPACE_URL, json.dumps(identity, sort_keys=True)))
        protocol = record.get("proto") or record.get("protocol") or None
        raw_service = record.get("service")
        service = AutoEnumPipeline.SERVICE_ALIASES.get(str(raw_service).lower(), raw_service) if raw_service else None
        if service == "http" and record.get("tunnel") in {"ssl", "tls"}:
            service = "https"
        port = _port(record.get("port"), lambda reason: quality("error", reason, filename, record))
        subject = {
            "host": target, "port": port, "transport": protocol, "service": service,
            "version": record.get("version"), "hostname": record.get("hostname"), "url": record.get("url"),
        }
        attributes = {
            "run_id": run_id, "bundle_fingerprint": fingerprint,
            "source_file": filename, "record_type": record_type, "subject": subject,
            "raw_service": raw_service, "hostname": record.get("hostname"),
            "product": record.get("product"), "extrainfo": record.get("extrainfo"),
            "tunnel": record.get("tunnel"), "categories": record.get("categories"),
            "artifacts": _artifacts(record, root), **extra,
        }
        observed_at = record.get("observed_at") or record.get("ts") or document.get("generated_utc")
        attributes["observed_at"] = observed_at
        context = _auth_context(
            auth_context if auth_context is not None else record.get("auth_context"),
            lambda reason: quality("error", reason, filename, record),
        )
        try:
            observation = Observation(
                kind=kind, target=target, port=port, protocol=protocol,
                service=service, version=record.get("version"), attributes=attributes,
                source_tool="aranum",
                source_tool_version=(tool_version or document.get("tool_version")
                                     or document.get("aranum_version")
                                     or (manifest or {}).get("tool_version")),
                source_schema=schema, source_id=str(source_id) if source_id is not None else None,
                raw=record, auth_context=context,
                source_execution_id=f"aranum:{occurrence}", module_path="interop/aranum",
                observed_at=observed_at, observation_id=identifier,
            )
        except (TypeError, ValueError) as exc:
            quality("error", f"{filename} {record_type}: {_exception_summary(exc)}", filename, record)
            return None
        if identifier not in seen:
            bundle.observations.append(observation)
            seen.add(identifier)
        return observation

    def validate_document(filename: str, document: dict[str, Any]) -> None:
        schema_filename = SCHEMA_FILES[filename]
        try:
            digests = json.loads((SCHEMA_ROOT / "schema-digests.json").read_text(encoding="utf-8"))
            expected = digests.get(schema_filename)
            schema_path = SCHEMA_ROOT / schema_filename
            actual = sha256(schema_path.read_bytes()).hexdigest()
            if not isinstance(expected, str) or actual != expected:
                quality("error", f"schema digest drift: {schema_filename}", filename)
                return
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            validator_class = validators.validator_for(schema)
            validator_class.check_schema(schema)
            error = next(iter(validator_class(schema).iter_errors(document)), None)
            if error is not None:
                quality("error", f"{filename}: {error.message}"[:500], filename, document)
        except Exception as exc:
            quality("error", f"schema digest drift: {schema_filename}", filename,
                    {"error": _exception_summary(exc)})

    if manifest is not None:
        validate_document("bundle-manifest.json", manifest)
    for filename, document in documents.items():
        if filename in SCHEMA_FILES:
            validate_document(filename, document)

    if manifest is not None:
        add("bundle-manifest.json", manifest, "snapshot_metadata", record_key="metadata")
    for filename, document in documents.items():
        metadata = {
            key: value for key, value in document.items()
            if key not in {"hosts", "entries", "findings", "domains", "services"}
        }
        add(filename, metadata, "snapshot_metadata", record_key="metadata")

    inventory = documents.get("inventory.json", {})
    hosts = inventory.get("hosts", [])
    entries = inventory.get("entries", [])
    if not isinstance(hosts, list):
        quality("error", "inventory.json: hosts must be an array", "inventory.json", inventory)
        hosts = []
    if not isinstance(entries, list):
        quality("error", "inventory.json: entries must be an array", "inventory.json", inventory)
        entries = []
    for record in hosts:
        add("inventory.json", record, "inventory_host", kind="host", target=_host(record) if isinstance(record, dict) else "")
    for record in entries:
        add("inventory.json", record, "inventory_endpoint", kind="service", target=_host(record) if isinstance(record, dict) else "")

    kb = findings_document.get("kb") if isinstance(findings_document.get("kb"), dict) else {}
    bundle.kb = kb
    kb_checks = kb.get("checks") if isinstance(kb.get("checks"), dict) else {}
    kb_classes = kb.get("classes") if isinstance(kb.get("classes"), dict) else {}
    findings_records = findings_document.get("findings", [])
    if not isinstance(findings_records, list):
        quality("error", "findings.json: findings must be an array", "findings.json", findings_document)
        findings_records = []
    finding_seed_records: list[dict[str, Any]] = []
    for record in findings_records:
        if not isinstance(record, dict):
            add("findings.json", record, "canonical_finding", kind="finding")
            continue
        observation = add(
            "findings.json", record, "canonical_finding", kind="finding", target=_host(record),
            source_triage_status=record.get("triage_status"),
            lifecycle_status="draft" if record.get("triage_status") == "new" else None,
        )
        if observation is None:
            continue
        kb_id = str(record.get("kb_id") or record.get("rule_id") or "")
        entry = kb_checks.get(kb_id) or kb_classes.get(kb_id) or kb_checks.get(str(record.get("rule_id") or ""))
        entry = entry if isinstance(entry, dict) else {}
        remediation_value = entry.get("remediation") if "remediation" in entry else entry.get("fix")
        validation_value = entry.get("validation") if "validation" in entry else entry.get("test")
        attack_ids = record.get("attack_ids")
        if not isinstance(attack_ids, list):
            attack_ids = entry.get("attack_ids") if isinstance(entry.get("attack_ids"), list) else []
        references = entry.get("refs") if isinstance(entry.get("refs"), list) else []
        tags = record.get("tags")
        if not isinstance(tags, list):
            tags = [tags] if isinstance(tags, str) and tags else []
        source_identity = (
            record.get("_source_id") or record.get("source_id")
            or record.get("_finding_id") or record.get("finding_id")
        )
        logical_id = record.get("_logical_finding_id") or record.get("logical_id")
        severity = str(record.get("severity", "info")).lower()
        finding = Finding(
            id=observation.observation_id,
            title=str(record.get("title") or record.get("line") or ""),
            severity=Severity(severity) if severity in {item.value for item in Severity} else Severity.INFO,
            status=FindingStatus.DRAFT, target=observation.target, port=observation.port,
            service=observation.service, protocol=observation.protocol, url=record.get("url"),
            description=str(entry.get("line") or record.get("line") or entry.get("title") or ""),
            impact=str(entry.get("impact") or entry.get("why") or ""),
            remediation=_step_text(remediation_value), references=[str(item) for item in references],
            mitre_techniques=[str(item) for item in attack_ids],
            module_name="interop/aranum", raw_output=json.dumps(observation.raw, sort_keys=True),
            tags=tags, discovered_at=None,
            metadata={
                "validation": validation_value if validation_value is not None else [],
                "kb_id": kb_id or None,
                "kb_digest": kb.get("digest"),
                "source_note": record.get("line"),
                "source_observation": observation.to_dict(),
                "source_identity": source_identity,
                "logical_id": logical_id,
                "auth_context": record.get("auth_context"),
            },
        )
        if record.get("triage_status") not in {None, "new"}:
            finding.notes.append(
                f"Source triage status {record.get('triage_status')!r} is unmapped; DRAFT is the projection default."
            )
        for artifact in observation.attributes["artifacts"]:
            finding.evidence.append(Evidence(
                id=str(uuid5(NAMESPACE_URL, f"{finding.id}:{artifact['reference']}")),
                finding_id=finding.id, title=artifact["reference"],
                file_path=artifact["resolved_path"],
                description=f"Aranum source reference: {artifact['reference']}",
                captured_at=None,
            ))
        bundle.findings.append(finding)
        finding_seed_records.append(record)

    summary = findings_document.get("summary") if isinstance(findings_document.get("summary"), dict) else {}
    coverage = summary.get("coverage", [])
    if not isinstance(coverage, list):
        quality("error", "findings.json: summary.coverage must be an array", "findings.json", summary)
        coverage = []
    for index, record in enumerate(coverage):
        add("findings.json", record, "coverage", kind="service",
            target=_host(record) if isinstance(record, dict) else "", record_key=["coverage", index],
            status=record.get("status") if isinstance(record, dict) else None,
            reason=record.get("reason") if isinstance(record, dict) else None)

    per_host = findings_document.get("per_host", [])
    if isinstance(per_host, dict):
        per_host_rows = [({"host": host, **value} if isinstance(value, dict) else {"host": host, "value": value})
                         for host, value in per_host.items()]
    elif isinstance(per_host, list):
        per_host_rows = per_host
    else:
        quality("error", "findings.json: per_host must be an array or object", "findings.json")
        per_host_rows = []
    for index, record in enumerate(per_host_rows):
        add("findings.json", record, "per_host_rollup", kind="host",
            target=_host(record) if isinstance(record, dict) else "", record_key=["per_host", index])

    if "inventory.json" not in documents:
        seed_rows = [*finding_seed_records, *(item for item in coverage if isinstance(item, dict))]
        seeded_hosts: set[str] = set()
        seeded_endpoints: set[tuple[str, int, str | None]] = set()
        for record in seed_rows:
            target = _host(record)
            if target and target not in seeded_hosts:
                add("findings.json", {"host": target}, "inventory_host", kind="host",
                    target=target, record_key=["derived-host", target])
                seeded_hosts.add(target)
            port = _port(record.get("port"))
            endpoint = (target, port, record.get("protocol") or record.get("proto"))
            if target and port is not None and endpoint not in seeded_endpoints:
                add("findings.json", record, "inventory_endpoint", kind="service",
                    target=target, record_key=["derived-endpoint", *endpoint])
                seeded_endpoints.add(endpoint)

    posture = documents.get("posture.json", {})
    for scope, records in (("host", posture.get("hosts", {})), ("domain", posture.get("domains", {}))):
        if not isinstance(records, dict):
            quality("error", f"posture.json: {scope}s must be an object", "posture.json", posture)
            continue
        for target, host_record in records.items():
            if not isinstance(host_record, dict):
                add("posture.json", host_record, "posture_subject", kind=scope, target=str(target))
                continue
            subject_auth = host_record.get("auth_context")
            add("posture.json", host_record, "posture_subject", kind=scope, target=str(target),
                record_key=[scope, target], scope=scope, auth_context=subject_auth)
            for collection in ("checks", "domain_observations"):
                values = host_record.get(collection, {})
                if isinstance(values, dict):
                    items = values.items()
                elif isinstance(values, list):
                    items = ((str(item.get("id") or index) if isinstance(item, dict) else str(index), item)
                             for index, item in enumerate(values))
                else:
                    quality("error", f"posture.json: {collection} must be an array or object", "posture.json", host_record)
                    continue
                for check_id, record in items:
                    add(
                        "posture.json", record, "posture_check", kind="policy", target=str(target),
                        record_key=[scope, target, collection, check_id], check_id=check_id,
                        scope="domain" if collection == "domain_observations" else scope,
                        status=record.get("status") if isinstance(record, dict) else None,
                        observed_from=record.get("observed_from") if isinstance(record, dict) else None,
                        artifacts=_artifacts({"source": host_record.get("source"), **record}, root)
                        if isinstance(record, dict) else [], auth_context=subject_auth,
                    )

    auth_outcomes = findings_document.get("auth_outcomes", [])
    if not isinstance(auth_outcomes, list):
        quality("error", "findings.json: auth_outcomes must be an array", "findings.json", findings_document)
        auth_outcomes = []
    for index, record in enumerate(auth_outcomes):
        add(
            "findings.json", record, "auth_outcome", kind="identity",
            target=_host(record) if isinstance(record, dict) else "", record_key=["auth_outcome", index],
            transport=record.get("transport") if isinstance(record, dict) else None,
            outcome=record.get("outcome") if isinstance(record, dict) else None,
            auth_context=record.get("auth_context") if isinstance(record, dict) else None,
        )

    services = documents.get("run-state.json", {}).get("services", [])
    if isinstance(services, list):
        for record in services:
            add("run-state.json", record, "service_execution",
                target=_host(record) if isinstance(record, dict) else "",
                status=record.get("status") if isinstance(record, dict) else None)
    else:
        quality("error", "run-state.json: services must be an array", "run-state.json")
    for record in queue:
        add("queue.state.jsonl", record, "task_execution", target=_host(record), status=record.get("status"))

    if status in {"partial", "interrupted", "failed", "stale", "unknown"}:
        quality("error" if status == "failed" else status, f"bundle status: {status}",
                "bundle-manifest.json", manifest)
    if manifest is not None:
        stages = manifest.get("stages", {})
        if isinstance(stages, dict):
            for stage_name, stage in stages.items():
                if not isinstance(stage, dict):
                    quality("error", f"invalid stage record: {stage_name}", "bundle-manifest.json")
                    continue
                stage_status = stage.get("status")
                if stage_status in {"partial", "failed"}:
                    quality("partial" if stage_status == "partial" else "error",
                            f"stage {stage_name} status: {stage_status}", "bundle-manifest.json", stage)
    for filename, document in documents.items():
        if document.get("partial") is True:
            quality("partial", f"{filename}: partial", filename, document)
        errors = document.get("errors", [])
        if isinstance(errors, list):
            for error in errors:
                quality("error", f"{filename}: {str(error)[:350]}", filename, error)
        quarantine = document.get("posture_quarantine", document.get("quarantine", []))
        if isinstance(quarantine, list):
            for record in quarantine:
                quality("quarantine", f"{filename}: quarantined record", filename, record)
        if document.get("redacted") is True:
            quality("redact", f"{filename}: redacted", filename, document)

    return bundle
