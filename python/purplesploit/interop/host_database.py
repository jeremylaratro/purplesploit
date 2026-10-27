"""Offline Linux host and database inventory normalization.

These importers consume collector output only.  They do not open SSH or
database connections, and retain the source records so richer projections can
be added without losing evidence.
"""

from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
from typing import Any, Iterable, Mapping
from uuid import NAMESPACE_URL, uuid5

from purplesploit.core.attack_graph import AttackGraph
from purplesploit.core.execution import Observation


HOST_DATABASE_SCHEMA = "purplesploit/host-database-inventory/1"
DATABASE_ENGINES = {"postgresql", "mysql", "mariadb", "redis", "mongodb", "mssql"}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("items", "value", "rows", "results"):
            if isinstance(value.get(key), list):
                return value[key]
        return [value]
    return [value]


def _mapping(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return dict(value)


@dataclass
class HostDatabaseInventory:
    source_type: str
    import_id: str
    source_execution_id: str
    observations: list[Observation] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    schema_version: str = HOST_DATABASE_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "import_id": self.import_id,
            "source_execution_id": self.source_execution_id,
            "schema_version": self.schema_version,
            "observations": [item.to_dict() for item in self.observations],
            "diagnostics": list(self.diagnostics),
        }

    def merge_into(self, destination: list[Observation]) -> int:
        known = {item.observation_id for item in destination}
        additions = [item for item in self.observations if item.observation_id not in known]
        destination.extend(additions)
        return len(additions)

    def populate_graph(self, graph: AttackGraph) -> int:
        return len(graph.ingest_observations(self.observations))


class _InventoryBuilder:
    def __init__(self, source_type: str, raw: Any, run_id: str | None):
        digest = sha256(_json(raw).encode()).hexdigest()
        self.import_id = str(uuid5(NAMESPACE_URL, f"host-database:{source_type}:{run_id or digest}"))
        self.result = HostDatabaseInventory(
            source_type=source_type,
            import_id=self.import_id,
            source_execution_id=f"host-database:{source_type}:{run_id or digest[:20]}",
        )
        self.run_id = run_id
        self.seen: set[str] = set()

    def add(
        self,
        kind: str,
        target: str,
        record_type: str,
        raw: Any,
        *,
        key: str,
        port: int | None = None,
        protocol: str | None = None,
        service: str | None = None,
        version: str | None = None,
        relationships: Iterable[dict[str, Any]] = (),
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        identifier = str(uuid5(NAMESPACE_URL, _json([self.import_id, record_type, key])))
        if identifier in self.seen:
            return
        details = {
            "identifier": key,
            "record_type": record_type,
            "import_id": self.import_id,
            "run_id": self.run_id,
            "relationships": list(relationships),
        }
        if attributes:
            details.update(attributes)
        self.result.observations.append(
            Observation(
                kind=kind,
                target=target,
                port=port,
                protocol=protocol,
                service=service,
                version=version,
                attributes=details,
                source_schema=HOST_DATABASE_SCHEMA,
                raw=raw,
                source_execution_id=self.result.source_execution_id,
                module_path=f"interop/{self.result.source_type}",
                confidence="observed",
                observation_id=identifier,
            )
        )
        self.seen.add(identifier)


def import_linux_snapshot(
    document: Mapping[str, Any],
    *,
    run_id: str | None = None,
) -> HostDatabaseInventory:
    """Import structured output from an SSH/local Linux collector."""
    data = _mapping(document, name="Linux snapshot")
    host = str(data.get("host") or data.get("hostname") or data.get("target") or "")
    if not host:
        raise ValueError("Linux snapshot requires host or hostname")
    builder = _InventoryBuilder("linux", data, run_id)
    builder.add(
        "host",
        host,
        "linux_host",
        data.get("system", {}),
        key=f"host:{host}",
        attributes={
            "hostname": data.get("hostname") or host,
            "os": data.get("os") or data.get("system", {}).get("os"),
            "kernel": data.get("kernel") or data.get("system", {}).get("kernel"),
        },
    )
    sections = {
        "packages": "package",
        "services": "system_service",
        "cron": "cron",
        "timers": "systemd_timer",
        "permissions": "permission",
        "credential_artifacts": "credential_artifact",
    }
    for section, record_type in sections.items():
        for index, item in enumerate(_list(data.get(section))):
            raw = item if isinstance(item, dict) else {"value": item}
            name = str(
                raw.get("id")
                or raw.get("name")
                or raw.get("path")
                or raw.get("unit")
                or raw.get("command")
                or raw.get("value")
                or index
            )
            relationship = {
                "type": "contains",
                "target": f"linux:{host}:{record_type}:{name}",
                "target_kind": "resource",
            }
            builder.add(
                "resource",
                f"linux:{host}:{record_type}:{name}",
                record_type,
                raw,
                key=f"{section}:{name}",
                relationships=[{
                    "type": "contains",
                    "target": f"host:{host}",
                    "target_kind": "host",
                    "direction": "in",
                }],
                attributes={"name": name, "host": host, "category": section},
            )
            # Keep the explicit intended subject for interchange consumers.
            builder.result.observations[-1].attributes["host_relationship"] = relationship
    if len(builder.result.observations) == 1:
        builder.result.diagnostics.append("Linux snapshot contains host metadata only")
    return builder.result

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def import_linpeas_output(
    text: str,
    *,
    host: str,
    run_id: str | None = None,
) -> HostDatabaseInventory:
    """Preserve useful linPEAS sections without claiming exploitability."""
    if not isinstance(text, str):
        raise ValueError("linPEAS output must be text")
    if not host:
        raise ValueError("linPEAS import requires host")
    clean = ANSI_RE.sub("", text).replace("\r", "")
    builder = _InventoryBuilder("linpeas", {"host": host, "output": clean}, run_id)
    builder.add("host", host, "linux_host", {"host": host}, key=f"host:{host}")
    heading = "unclassified"
    counters: dict[str, int] = {}
    for line in clean.splitlines():
        value = line.strip(" \t=*#-")
        if not value:
            continue
        if line.startswith(("╔", "═", "[ section ]")) or (
            len(value) < 90 and value.upper() == value and any(char.isalpha() for char in value)
        ):
            heading = value.casefold().replace(" ", "_")[:80]
            continue
        lowered = value.casefold()
        category = None
        if any(token in lowered for token in ("password", "private key", "credential", "token")):
            category = "credential_artifact"
        elif any(token in lowered for token in ("writable", "sudo", "cap_set", "suid")):
            category = "permission"
        elif "timer" in heading or "cron" in heading:
            category = "scheduled_task"
        if not category:
            continue
        counters[category] = counters.get(category, 0) + 1
        key = f"{category}:{counters[category]}:{sha256(value.encode()).hexdigest()[:12]}"
        builder.add(
            "note",
            host,
            category,
            {"line": value, "section": heading},
            key=key,
            attributes={"section": heading, "line": value, "host": host},
        )
    if len(builder.result.observations) == 1:
        builder.result.diagnostics.append("No supported linPEAS inventory lines were recognized")
    return builder.result


def _valid_port(value: Any, default: int) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        raise ValueError("Database port must be an integer")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("Database port must be between 1 and 65535")
    return port


def import_database_inventory(
    engine: str,
    document: Mapping[str, Any],
    *,
    host: str | None = None,
    port: int | None = None,
    run_id: str | None = None,
) -> HostDatabaseInventory:
    """Import common database users, roles, databases and data-object lists."""
    engine = engine.casefold()
    if engine not in DATABASE_ENGINES:
        raise ValueError(f"Unsupported database engine: {engine}")
    data = _mapping(document, name="Database inventory")
    host = str(host or data.get("host") or data.get("target") or "")
    if not host:
        raise ValueError("Database inventory requires host")
    defaults = {
        "postgresql": 5432,
        "mysql": 3306,
        "mariadb": 3306,
        "redis": 6379,
        "mongodb": 27017,
        "mssql": 1433,
    }
    port = _valid_port(port or data.get("port"), defaults[engine])
    builder = _InventoryBuilder(f"database/{engine}", data, run_id)
    service_key = f"{host}:{port}/tcp"
    builder.add(
        "service",
        host,
        "database_service",
        data.get("server", {}),
        key=service_key,
        port=port,
        protocol="tcp",
        service=engine,
        version=str(data.get("version")) if data.get("version") is not None else None,
        attributes={"host": host, "name": engine},
    )
    for role in _list(data.get("roles")):
        raw = role if isinstance(role, dict) else {"name": role}
        name = str(raw.get("name") or raw.get("role") or raw.get("RoleName") or "")
        if name:
            builder.add(
                "role",
                f"db:{engine}:{host}:{name}",
                "database_role",
                raw,
                key=f"role:{name}",
                attributes={"name": name, "engine": engine, "host": host},
            )
    for user in _list(data.get("users")):
        raw = user if isinstance(user, dict) else {"name": user}
        name = str(raw.get("name") or raw.get("user") or raw.get("username") or "")
        if not name:
            continue
        relationships = []
        for role in _list(raw.get("roles")):
            role_name = role.get("name") if isinstance(role, dict) else role
            relationships.append({
                "type": "assumes",
                "target": f"db:{engine}:{host}:{role_name}",
                "target_kind": "role",
            })
        builder.add(
            "identity",
            f"db:{engine}:{host}:user:{name}",
            "database_user",
            raw,
            key=f"user:{name}",
            relationships=relationships,
            attributes={"name": name, "engine": engine, "host": host},
        )
    for database in _list(data.get("databases")):
        raw = database if isinstance(database, dict) else {"name": database}
        name = str(raw.get("name") or raw.get("database") or raw.get("db") or "")
        if not name:
            continue
        database_key = f"db:{engine}:{host}:{name}"
        builder.add(
            "resource",
            database_key,
            "database",
            raw,
            key=f"database:{name}",
            relationships=[{
                "type": "contains",
                "target": service_key,
                "target_kind": "service",
                "direction": "in",
            }],
            attributes={"name": name, "engine": engine, "host": host},
        )
        for object_type in ("schemas", "tables", "collections", "keys"):
            for item in _list(raw.get(object_type)):
                item_raw = item if isinstance(item, dict) else {"name": item}
                object_name = str(item_raw.get("name") or item_raw.get("key") or "")
                if not object_name:
                    continue
                object_key = f"{database_key}:{object_type}:{object_name}"
                builder.add(
                    "resource",
                    object_key,
                    f"database_{object_type.rstrip('s')}",
                    item_raw,
                    key=f"database:{name}:{object_type}:{object_name}",
                    relationships=[{
                        "type": "contains",
                        "target": database_key,
                        "target_kind": "resource",
                        "direction": "in",
                    }],
                    attributes={
                        "name": object_name,
                        "database": name,
                        "engine": engine,
                        "host": host,
                    },
                )
    return builder.result
