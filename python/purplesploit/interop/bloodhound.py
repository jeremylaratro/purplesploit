"""Offline BloodHound AD collector interchange, legacy v5 and CE v6 subset.

Import accepts a collector {meta: {type}, data: [...]} envelope, a list of
envelopes, a mapping of type to envelope, a JSON file, or a directory of JSON
files. Legacy envelopes with an array named after meta.type are also accepted.
Supported objects: users, groups, computers, domains. Supported relations:
Members/PrimaryGroupSID, Sessions/PrivilegedSessions/RegistrySessions,
LocalAdmins (and CE LocalGroups named Administrators or SID ending -544),
and domain Trusts. MemberOf is principal->group, AdminTo is principal->computer,
HasSession is computer->user, TrustedBy is trusted domain->trusting domain.
References with a known type create placeholders, updated by later imports.
Unknown object types/records are retained in graph.metadata for inspection.

Export returns one v5/v6 collector envelope per supported type, for writing to
separate JSON files. Only nodes carrying raw BloodHound ObjectIdentifiers are
exported; arbitrary host names are not invented as AD SIDs. This is a supported
AD subset, not OpenGraph, AzureHound, an ACL exporter, or a promise of full
collector parity. Generic graph JSON/CSV retain all other node/edge types.
Raw IDs/types and synthetic stable observation IDs retain source provenance.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from purplesploit.core.attack_graph import AttackGraph, EdgeType, NodeType


OBJECT_TYPES = {"users": NodeType.USER, "groups": NodeType.GROUP,
                "computers": NodeType.COMPUTER, "domains": NodeType.DOMAIN}
REFERENCE_TYPES = {kind.value: kind for kind in OBJECT_TYPES.values()}


def _envelopes(source: Any):
    if isinstance(source, Path) or isinstance(source, str) and not source.lstrip().startswith(("{", "[")):
        path = Path(source)
        if path.is_dir():
            for child in sorted(path.glob("*.json")):
                yield from _envelopes(child)
        else:
            yield from _envelopes(json.loads(path.read_text(encoding="utf-8-sig")))
    elif isinstance(source, str):
        yield from _envelopes(json.loads(source))
    elif isinstance(source, list):
        for item in source:
            yield from _envelopes(item)
    elif isinstance(source, dict):
        if "meta" in source:
            yield source
        else:
            for kind, value in source.items():
                if isinstance(value, list):
                    yield {"meta": {"type": kind}, "data": value}
                elif isinstance(value, dict):
                    yield from _envelopes(value)
    else:
        raise ValueError("Expected a BloodHound collector envelope or JSON path")


def _rows(value):
    if isinstance(value, dict):
        value = value.get("Results", [])
    return value if isinstance(value, list) else []


def import_bloodhound(source: Any, graph: AttackGraph | None = None) -> AttackGraph:
    """Merge supported records idempotently; preserve unknown records in metadata."""
    graph = graph if graph is not None else AttackGraph()
    report = graph.metadata.setdefault("bloodhound", {"unsupported_records": []})
    index = {node.metadata["raw_source_id"]: node for node in graph.nodes.values()
             if node.metadata.get("raw_source_id") and node.metadata.get("source_format") == "bloodhound"}
    pending = []

    def unsupported(kind, record):
        value = {"type": kind, "record": record}
        if value not in report["unsupported_records"]:
            report["unsupported_records"].append(value)

    def put(raw_id, node_type, properties=None, provenance=None, placeholder=False):
        properties = properties or {}
        metadata = {"source_format": "bloodhound", "raw_source_id": str(raw_id),
                    "raw_source_type": node_type.value.capitalize(), "placeholder": placeholder}
        metadata.update(provenance or {})
        node = graph.add_node(node_type, properties.get("name") or str(raw_id),
                              identifier=f"bloodhound:{raw_id}", properties=properties, metadata=metadata)
        if not placeholder:
            node.label = properties.get("name") or node.label
        index[str(raw_id)] = node
        return node

    def reference(value, default=None, provenance=None):
        if isinstance(value, str):
            raw_id, node_type = value, default
        elif isinstance(value, dict):
            raw_id = value.get("ObjectIdentifier") or value.get("MemberId")
            raw_type = value.get("ObjectType") or value.get("MemberType")
            node_type = REFERENCE_TYPES.get(str(raw_type).lower()) if raw_type else default
        else:
            return None
        if not raw_id:
            return None
        if raw_id in index:
            node = index[raw_id]
            # Reference evidence contributes to existing endpoint provenance too.
            return put(raw_id, node.node_type, provenance=provenance,
                       placeholder=node.metadata.get("placeholder", False))
        if node_type is None:
            unsupported("reference", value)
            return None
        return put(raw_id, node_type, provenance=provenance, placeholder=True)

    for envelope in _envelopes(source):
        kind = str(envelope.get("meta", {}).get("type", "")).lower()
        for record in _rows(envelope.get("data", envelope.get(kind, []))):
            if not isinstance(record, dict) or kind not in OBJECT_TYPES or not record.get("ObjectIdentifier"):
                unsupported(kind, record)
                continue
            raw_id = str(record["ObjectIdentifier"])
            digest = hashlib.sha256(json.dumps([kind, record], sort_keys=True).encode()).hexdigest()
            provenance = {"source_observation_ids": [f"bloodhound:{digest}"],
                          "source_records": [{"id": raw_id, "type": kind,
                                              "version": envelope.get("meta", {}).get("version")} ]}
            node = put(raw_id, OBJECT_TYPES[kind], record.get("Properties"), provenance)
            pending.append((node, record, provenance))

    for node, record, provenance in pending:
        def link(source_node, target_node, kind, extras=None):
            if source_node and target_node:
                graph.add_edge(source_node.id, target_node.id, kind,
                               properties={**provenance, **(extras or {})})

        primary = record.get("PrimaryGroupSID")
        if primary:
            link(node, reference(primary, NodeType.GROUP, provenance), EdgeType.MEMBER_OF)
        if node.node_type == NodeType.GROUP:
            for member in _rows(record.get("Members", [])):
                link(reference(member, provenance=provenance), node, EdgeType.MEMBER_OF)
        if node.node_type == NodeType.COMPUTER:
            for field in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
                for session in _rows(record.get(field, [])):
                    if not isinstance(session, dict):
                        unsupported(field, session)
                        continue
                    computer = reference(session.get("ComputerSID") or node.metadata["raw_source_id"],
                                         NodeType.COMPUTER, provenance)
                    user = reference(session.get("UserSID"), NodeType.USER, provenance)
                    link(computer, user, EdgeType.HAS_SESSION)
            for member in _rows(record.get("LocalAdmins", [])):
                link(reference(member, provenance=provenance), node, EdgeType.ADMIN_TO)
            for group in _rows(record.get("LocalGroups", [])):
                if not isinstance(group, dict):
                    continue
                name = str(group.get("Name", "")).rsplit("\\", 1)[-1].lower()
                sid = str(group.get("ObjectIdentifier", ""))
                if name == "administrators" or sid.endswith("-544"):
                    for member in _rows(group.get("Results", group.get("Members", []))):
                        link(reference(member, provenance=provenance), node, EdgeType.ADMIN_TO)
        if node.node_type == NodeType.DOMAIN:
            for trust in _rows(record.get("Trusts", [])):
                if not isinstance(trust, dict) or not trust.get("TargetDomainSid"):
                    unsupported("trust", trust)
                    continue
                target = reference(trust["TargetDomainSid"], NodeType.DOMAIN, provenance)
                direction = str(trust.get("TrustDirection", "")).lower()
                if direction in {"1", "inbound", "3", "bidirectional"}:
                    link(node, target, EdgeType.TRUSTED_BY, {"trust": trust})
                if direction in {"2", "outbound", "3", "bidirectional"}:
                    link(target, node, EdgeType.TRUSTED_BY, {"trust": trust})
                if direction not in {"1", "2", "3", "inbound", "outbound", "bidirectional"}:
                    unsupported("trust_direction", trust)
    return graph


def export_bloodhound(graph: AttackGraph, version: int = 5) -> dict[str, dict]:
    """Return per-type collector envelopes for the subset described above.

    Only supported relations are emitted. Missing session/local-admin collection
    is marked Collected=False; the exporter never claims empty collection ran.
    Native graph properties/provenance remain in generic JSON/CSV exports.
    """
    if version not in {5, 6}:
        raise ValueError("Supported BloodHound collector versions are 5 and 6")
    result = {kind: {"data": [], "meta": {"type": kind, "count": 0, "version": version}}
              for kind in OBJECT_TYPES}
    exported = {}
    for node in sorted(graph.nodes.values(), key=lambda item: item.id):
        if node.node_type not in OBJECT_TYPES.values() or node.metadata.get("source_format") != "bloodhound":
            continue
        raw_id = node.metadata.get("raw_source_id")
        if not raw_id:
            continue
        record = {"ObjectIdentifier": raw_id, "Properties": {**node.properties, "name": node.label},
                  "Aces": [], "IsDeleted": False, "IsACLProtected": False}
        if node.node_type == NodeType.GROUP:
            record["Members"] = []
        if node.node_type == NodeType.COMPUTER:
            record.update({field: {"Results": [], "Collected": False, "FailureReason": None}
                           for field in ("Sessions", "PrivilegedSessions", "RegistrySessions", "LocalAdmins")})
            record.update(PrimaryGroupSID=None, AllowedToDelegate=[], AllowedToAct=[],
                          DumpSMSAPassword=[], HasSIDHistory=[], Status=None)
        if node.node_type == NodeType.USER:
            record.update(PrimaryGroupSID=None, AllowedToDelegate=[], HasSIDHistory=[], SPNTargets=[])
        if node.node_type == NodeType.DOMAIN:
            record.update(Trusts=[], Links=[], ChildObjects=[], GPOChanges={})
        kind = next(kind for kind, node_type in OBJECT_TYPES.items() if node_type == node.node_type)
        result[kind]["data"].append(record)
        exported[node.id] = record
    for edge in sorted(graph.edges.values(), key=lambda item: item.id):
        if edge.source_id not in exported or edge.target_id not in exported:
            continue
        source, target = exported[edge.source_id], exported[edge.target_id]
        source_type = graph.nodes[edge.source_id].node_type
        if edge.edge_type == EdgeType.MEMBER_OF and "Members" in target:
            target["Members"].append({"ObjectIdentifier": source["ObjectIdentifier"],
                                      "ObjectType": source_type.value.capitalize()})
        elif edge.edge_type == EdgeType.ADMIN_TO and "LocalAdmins" in target:
            target["LocalAdmins"]["Results"].append({"ObjectIdentifier": source["ObjectIdentifier"],
                                                     "ObjectType": source_type.value.capitalize()})
            target["LocalAdmins"]["Collected"] = True
        elif edge.edge_type == EdgeType.HAS_SESSION and "Sessions" in source:
            source["Sessions"]["Results"].append({"ComputerSID": source["ObjectIdentifier"],
                                                  "UserSID": target["ObjectIdentifier"]})
            source["Sessions"]["Collected"] = True
        elif edge.edge_type == EdgeType.TRUSTED_BY and "Trusts" in source:
            source["Trusts"].append({**edge.properties.get("trust", {}),
                                     "TargetDomainSid": target["ObjectIdentifier"],
                                     "TargetDomainName": target["Properties"].get("name", ""),
                                     "TrustDirection": "Inbound"})
    for envelope in result.values():
        envelope["meta"]["count"] = len(envelope["data"])
    return result
