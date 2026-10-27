"""Deterministic, offline cloud and Entra inventory importers.

The adapter consumes already-exported CLI/API JSON.  It never authenticates to
or calls a cloud provider.  Provider records are retained verbatim alongside a
small common observation projection suitable for the attack graph.
"""

from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable, Mapping
from uuid import NAMESPACE_URL, uuid5

from purplesploit.core.attack_graph import AttackGraph
from purplesploit.core.execution import Observation


CLOUD_SCHEMA_VERSION = "purplesploit/cloud-inventory/1"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _records(value: Any) -> list[dict[str, Any]]:
    """Accept common CLI envelopes without guessing scalar records."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in (
            "value", "items", "Items", "Users", "Groups", "Roles", "Policies",
            "Resources", "ServiceAccounts", "serviceAccounts", "bindings",
        ):
            if isinstance(value.get(key), list):
                return [item for item in value[key] if isinstance(item, dict)]
        return [value]
    return []


def _load_documents(source: Mapping[str, Any] | str | Path) -> dict[str, Any]:
    if isinstance(source, Mapping):
        return dict(source)
    path = Path(source)
    if path.is_dir():
        result = {}
        for child in sorted(path.glob("*.json")):
            result[child.stem] = json.loads(child.read_text(encoding="utf-8"))
        return result
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Cloud inventory JSON must contain an object")
    return document


def _first(record: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def _identifier(record: Mapping[str, Any], provider: str, record_type: str) -> str:
    value = _first(
        record,
        "id", "Id", "ID", "arn", "Arn", "resourceId", "ResourceId",
        "objectId", "principalId", "userPrincipalName", "mail", "name",
        "Name", "displayName", "DisplayName", "email", "uniqueId",
    )
    if value not in (None, ""):
        return str(value)
    return f"{provider}:{record_type}:{sha256(_canonical(record).encode()).hexdigest()[:20]}"


def _display(record: Mapping[str, Any], identifier: str) -> str:
    return str(
        _first(
            record, "displayName", "DisplayName", "name", "Name",
            "userPrincipalName", "email", "UserName", "RoleName", "PolicyName",
        )
        or identifier
    )


def _relation(
    relationship: str,
    target: Any,
    target_kind: str,
    *,
    label: str | None = None,
    direction: str = "out",
) -> dict[str, Any] | None:
    if target in (None, ""):
        return None
    value = {
        "type": relationship,
        "target": str(target),
        "target_kind": target_kind,
        "direction": direction,
    }
    if label:
        value["label"] = label
    return value


@dataclass
class CloudInventory:
    provider: str
    import_id: str
    source_execution_id: str
    observations: list[Observation] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    schema_version: str = CLOUD_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "import_id": self.import_id,
            "source_execution_id": self.source_execution_id,
            "schema_version": self.schema_version,
            "observations": [item.to_dict() for item in self.observations],
            "diagnostics": list(self.diagnostics),
        }

    def merge_into(self, observations: list[Observation]) -> int:
        known = {item.observation_id for item in observations}
        additions = [item for item in self.observations if item.observation_id not in known]
        observations.extend(additions)
        return len(additions)

    def populate_graph(self, graph: AttackGraph) -> int:
        return len(graph.ingest_observations(self.observations))


class _Builder:
    def __init__(self, provider: str, documents: dict[str, Any], run_id: str | None):
        self.provider = provider
        self.documents = documents
        digest = sha256(_canonical(documents).encode()).hexdigest()
        self.import_id = str(uuid5(NAMESPACE_URL, f"cloud:{provider}:{run_id or digest}"))
        self.result = CloudInventory(
            provider=provider,
            import_id=self.import_id,
            source_execution_id=f"cloud:{provider}:{run_id or digest[:20]}",
        )
        self._seen: set[str] = set()
        self.run_id = run_id

    def add(
        self,
        kind: str,
        record_type: str,
        record: Mapping[str, Any],
        *,
        identifier: str | None = None,
        relationships: Iterable[dict[str, Any] | None] = (),
        extra: Mapping[str, Any] | None = None,
    ) -> Observation:
        identifier = identifier or _identifier(record, self.provider, record_type)
        source_id = _first(record, "id", "Id", "ID", "arn", "Arn", "objectId") or identifier
        observation_id = str(
            uuid5(
                NAMESPACE_URL,
                _canonical([self.provider, self.import_id, record_type, str(source_id)]),
            )
        )
        attributes = {
            "identifier": identifier,
            "name": _display(record, identifier),
            "provider": self.provider,
            "record_type": record_type,
            "run_id": self.run_id,
            "import_id": self.import_id,
            "relationships": [item for item in relationships if item is not None],
        }
        if extra:
            attributes.update(extra)
        observation = Observation(
            kind=kind,
            target=identifier,
            attributes=attributes,
            source_schema=CLOUD_SCHEMA_VERSION,
            source_id=str(source_id),
            raw=dict(record),
            source_execution_id=self.result.source_execution_id,
            module_path=f"interop/cloud/{self.provider}",
            confidence="observed",
            observation_id=observation_id,
        )
        if observation_id not in self._seen:
            self.result.observations.append(observation)
            self._seen.add(observation_id)
        return observation


def _named(documents: Mapping[str, Any], *keys: str) -> list[dict[str, Any]]:
    for key in keys:
        if key in documents:
            return _records(documents[key])
    return []


def import_aws_inventory(
    source: Mapping[str, Any] | str | Path,
    *,
    run_id: str | None = None,
) -> CloudInventory:
    """Import sanitized AWS CLI/collector JSON envelopes."""
    documents = _load_documents(source)
    builder = _Builder("aws", documents, run_id)
    account_doc = documents.get("account") or documents.get("caller_identity") or {}
    account_records = _records(account_doc)
    account_id = None
    if account_records:
        account = account_records[0]
        account_id = str(_first(account, "Account", "accountId", "id") or "aws:unknown-account")
        builder.add("tenant", "account", account, identifier=f"aws:account:{account_id}")

    owner = f"aws:account:{account_id}" if account_id else None
    for record in _named(documents, "users", "iam_users"):
        identifier = str(_first(record, "Arn", "arn") or f"aws:user:{_identifier(record, 'aws', 'user')}")
        relationships = [_relation("owns", owner, "tenant", direction="in")]
        for group in record.get("Groups", record.get("groups", [])) or []:
            group_id = group.get("Arn") or group.get("GroupName") if isinstance(group, dict) else group
            relationships.append(_relation("member_of", group_id, "group"))
        for policy in record.get("AttachedManagedPolicies", record.get("policies", [])) or []:
            policy_id = policy.get("PolicyArn") or policy.get("arn") if isinstance(policy, dict) else policy
            relationships.append(_relation("has_permission", policy_id, "policy"))
        builder.add("identity", "iam_user", record, identifier=identifier, relationships=relationships)

    for record in _named(documents, "groups", "iam_groups"):
        builder.add("group", "iam_group", record)
    for record in _named(documents, "roles", "iam_roles"):
        identifier = str(_first(record, "Arn", "arn") or f"aws:role:{_identifier(record, 'aws', 'role')}")
        relationships = [_relation("owns", owner, "tenant", direction="in")]
        for policy in record.get("AttachedManagedPolicies", record.get("policies", [])) or []:
            policy_id = policy.get("PolicyArn") or policy.get("arn") if isinstance(policy, dict) else policy
            relationships.append(_relation("has_permission", policy_id, "policy"))
        builder.add("role", "iam_role", record, identifier=identifier, relationships=relationships)
    for record in _named(documents, "policies", "iam_policies"):
        builder.add("policy", "iam_policy", record)
    for record in _named(documents, "resources", "Resources"):
        public = bool(record.get("public") or record.get("Public") or record.get("internet_exposed"))
        relationships = [_relation("owns", owner, "tenant", direction="in")]
        if public:
            relationships.append(_relation("exposed_to", "internet", "resource"))
        role = _first(record, "roleArn", "RoleArn", "iamRole", "serviceRole")
        if role:
            relationships.append(_relation("applies_to", role, "role", direction="in"))
        builder.add("resource", "resource", record, relationships=relationships, extra={"public": public})
    if not builder.result.observations:
        builder.result.diagnostics.append("No recognized AWS inventory records")
    return builder.result

def import_azure_inventory(
    source: Mapping[str, Any] | str | Path,
    *,
    run_id: str | None = None,
) -> CloudInventory:
    """Import Azure Resource Manager and role-assignment JSON."""
    documents = _load_documents(source)
    builder = _Builder("azure", documents, run_id)
    tenant_records = _named(documents, "tenant", "tenants")
    tenant_id = None
    if tenant_records:
        record = tenant_records[0]
        tenant_id = str(_first(record, "tenantId", "id") or "azure:unknown-tenant")
        builder.add("tenant", "tenant", record, identifier=f"azure:tenant:{tenant_id}")
    owner = f"azure:tenant:{tenant_id}" if tenant_id else None
    for record in _named(documents, "users"):
        builder.add("identity", "user", record, relationships=[_relation("owns", owner, "tenant", direction="in")])
    for record in _named(documents, "groups"):
        builder.add("group", "group", record, relationships=[_relation("owns", owner, "tenant", direction="in")])
    for record in _named(documents, "service_principals", "servicePrincipals"):
        builder.add("identity", "service_principal", record, relationships=[_relation("owns", owner, "tenant", direction="in")])
    for record in _named(documents, "role_definitions", "roleDefinitions"):
        builder.add("role", "role_definition", record)
    for record in _named(documents, "role_assignments", "roleAssignments"):
        principal = _first(record, "principalId", "principal_id")
        role = _first(record, "roleDefinitionId", "role_definition_id")
        scope = _first(record, "scope", "Scope")
        relationships = [_relation("assumes", role, "role"), _relation("has_permission", scope, "resource")]
        builder.add("identity", "role_assignment", record, identifier=str(principal or _identifier(record, "azure", "assignment")), relationships=relationships, extra={"assignment": True})
    for record in _named(documents, "resources", "Resources"):
        public = bool(record.get("public") or record.get("publicNetworkAccess") == "Enabled" or record.get("publicIpAddress"))
        relationships = [_relation("owns", owner, "tenant", direction="in")]
        if public:
            relationships.append(_relation("exposed_to", "internet", "resource"))
        builder.add("resource", "resource", record, relationships=relationships, extra={"public": public})
    if not builder.result.observations:
        builder.result.diagnostics.append("No recognized Azure inventory records")
    return builder.result


def import_gcp_inventory(
    source: Mapping[str, Any] | str | Path,
    *,
    run_id: str | None = None,
) -> CloudInventory:
    """Import GCP project, IAM policy and resource JSON."""
    documents = _load_documents(source)
    builder = _Builder("gcp", documents, run_id)
    project_records = _named(documents, "project", "projects")
    project_id = None
    if project_records:
        record = project_records[0]
        project_id = str(_first(record, "projectId", "id", "name") or "gcp:unknown-project")
        builder.add("tenant", "project", record, identifier=f"gcp:project:{project_id}")
    owner = f"gcp:project:{project_id}" if project_id else None
    for record in _named(documents, "service_accounts", "serviceAccounts"):
        builder.add("identity", "service_account", record, relationships=[_relation("owns", owner, "tenant", direction="in")])
    raw_policies = (
        documents.get("iam_policy")
        or documents.get("iamPolicy")
        or documents.get("policies")
        or []
    )
    policy_records = (
        [raw_policies]
        if isinstance(raw_policies, dict) and "bindings" in raw_policies
        else _records(raw_policies)
    )
    for policy in policy_records:
        if "bindings" not in policy:
            builder.add("policy", "iam_policy", policy)
            continue
        for binding in _records(policy.get("bindings")):
            role = str(binding.get("role") or _identifier(binding, "gcp", "role"))
            builder.add("role", "iam_role", binding, identifier=role)
            for member in binding.get("members", []) or []:
                builder.add("identity", "iam_member", {"id": member, "binding": binding}, identifier=str(member), relationships=[_relation("assumes", role, "role")])
    for record in _named(documents, "resources", "Resources"):
        public = bool(record.get("public") or record.get("internet_exposed"))
        relationships = [_relation("owns", owner, "tenant", direction="in")]
        if public:
            relationships.append(_relation("exposed_to", "internet", "resource"))
        builder.add("resource", "resource", record, relationships=relationships, extra={"public": public})
    if not builder.result.observations:
        builder.result.diagnostics.append("No recognized GCP inventory records")
    return builder.result


def import_entra_inventory(
    source: Mapping[str, Any] | str | Path,
    *,
    run_id: str | None = None,
) -> CloudInventory:
    """Import Microsoft Graph/az Entra directory JSON."""
    documents = _load_documents(source)
    builder = _Builder("entra", documents, run_id)
    tenant_records = _named(documents, "organization", "tenant", "tenants")
    tenant_id = None
    if tenant_records:
        record = tenant_records[0]
        tenant_id = str(_first(record, "id", "tenantId") or "entra:unknown-tenant")
        builder.add("tenant", "tenant", record, identifier=f"entra:tenant:{tenant_id}")
    owner = f"entra:tenant:{tenant_id}" if tenant_id else None
    for record in _named(documents, "users"):
        relationships = [_relation("owns", owner, "tenant", direction="in")]
        for group in record.get("groups", []) or []:
            group_id = group.get("id") if isinstance(group, dict) else group
            relationships.append(_relation("member_of", group_id, "group"))
        builder.add("identity", "user", record, relationships=relationships)
    for record in _named(documents, "groups"):
        builder.add("group", "group", record)
    for record in _named(documents, "applications"):
        builder.add("resource", "application", record, relationships=[_relation("owns", owner, "tenant", direction="in")])
    for record in _named(documents, "service_principals", "servicePrincipals"):
        app_id = _first(record, "appId", "applicationId")
        builder.add("identity", "service_principal", record, relationships=[_relation("identifies", app_id, "resource")])
    for record in _named(documents, "directory_roles", "directoryRoles"):
        builder.add("role", "directory_role", record)
    for record in _named(documents, "role_assignments", "roleAssignments"):
        principal = _first(record, "principalId", "subjectId")
        role = _first(record, "roleDefinitionId", "roleId")
        builder.add("identity", "role_assignment", record, identifier=str(principal or _identifier(record, "entra", "assignment")), relationships=[_relation("assumes", role, "role")], extra={"assignment": True})
    for record in _named(documents, "oauth2_permission_grants", "oauth2PermissionGrants"):
        principal = _first(record, "clientId", "principalId")
        resource = _first(record, "resourceId", "consentType")
        builder.add("identity", "oauth2_permission_grant", record, identifier=str(principal or _identifier(record, "entra", "grant")), relationships=[_relation("has_permission", resource, "resource")], extra={"scopes": record.get("scope", "").split()})
    if not builder.result.observations:
        builder.result.diagnostics.append("No recognized Entra inventory records")
    return builder.result
