"""Offline Kubernetes, container-runtime and image-scanner JSON adapters.

Inputs are recorded JSON objects, JSON text or local paths. No commands, clients,
network requests or referenced-file reads occur. Secret/config-map payloads and
kubeconfig credentials are omitted from retained provenance. Packages are
``resource`` observations with ``record_type=package``; scanner verdicts are
``finding`` observations, not claims that a vulnerability was exploited.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from functools import wraps
from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

from purplesploit.core.execution import Observation


CONTAINER_SCHEMA_VERSION = "purplesploit/container-inventory/1"
_HIDDEN = {
    "data", "stringdata", "binarydata", "token", "password", "client-key-data",
    "client-certificate-data", "certificate-authority-data", "client-key",
    "client-certificate", "certificate-authority", "users",
}
_KINDS = {
    "contexts": "Context", "clusters": "Cluster", "namespaces": "Namespace",
    "nodes": "Node", "pods": "Pod", "deployments": "Deployment",
    "statefulsets": "StatefulSet", "daemonsets": "DaemonSet", "jobs": "Job",
    "cronjobs": "CronJob", "replicasets": "ReplicaSet", "services": "Service",
    "ingresses": "Ingress", "ingress": "Ingress", "routes": "Route",
    "roles": "Role", "clusterroles": "ClusterRole", "rolebindings": "RoleBinding",
    "clusterrolebindings": "ClusterRoleBinding", "serviceaccounts": "ServiceAccount",
    "networkpolicies": "NetworkPolicy", "secrets": "Secret", "configmaps": "ConfigMap",
}
_CLUSTER_SCOPED = {"Cluster", "Context", "Namespace", "Node", "ClusterRole", "ClusterRoleBinding"}
_WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _unordered(value: Any) -> Any:
    """Collection ordering does not change an inventory's import identity."""
    if isinstance(value, dict):
        return {key: _unordered(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((_unordered(item) for item in value), key=_canonical)
    return value


def _validate_json(value: Any, depth: int = 0) -> None:
    if depth > 80:
        raise ValueError("JSON nesting exceeds 80 levels")
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        for item in value.values():
            _validate_json(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_json(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Nonfinite JSON numbers are unsupported")
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise ValueError("Only JSON values are supported")


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def _load(data: Any, *, jsonl: bool = False) -> tuple[Any, str | None]:
    source = None
    if isinstance(data, Path):
        source = str(data)
        data = data.read_text(encoding="utf-8")
    elif isinstance(data, str) and not data.lstrip().startswith(("{", "[")):
        if "\n" not in data and Path(data).is_file():
            source = str(data)
            data = Path(data).read_text(encoding="utf-8")
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    if isinstance(data, str):
        try:
            data = json.loads(data, object_pairs_hook=_pairs)
        except json.JSONDecodeError:
            if not jsonl:
                raise ValueError("Malformed JSON") from None
            data = [json.loads(line, object_pairs_hook=_pairs) for line in data.splitlines() if line.strip()]
    if isinstance(data, Mapping):
        data = dict(data)
    _validate_json(data)
    if not isinstance(data, (dict, list)):
        raise ValueError("Inventory must be a JSON object or array")
    return deepcopy(data), source


def _raw(value: Any) -> Any:
    """Retain JSON provenance without materializing embedded credential payloads."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            lower = key.lower()
            if lower in {"data", "stringdata", "binarydata"} and isinstance(item, dict):
                result[key + "_keys"] = sorted(item)
                continue
            if lower in _HIDDEN or lower == "annotations" or lower == "env" or key == "Secrets":
                continue
            if lower == "tls" and isinstance(item, dict):
                item = {name: content for name, content in item.items()
                        if name.lower() not in {"key", "certificate", "cacertificate", "destinationcacertificate"}}
            # Trivy secret detector records are outside this inventory adapter.
            if lower in {"match", "secret", "secretvalue", "auth", "registrytoken"}:
                continue
            result[key] = _raw(item)
        return result
    if isinstance(value, list):
        return [_raw(item) for item in value]
    return value


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _part(value: str) -> str:
    return quote(value, safe="")


def _kube_id(cluster: str, kind: str, name: str, namespace: str = "") -> str:
    return "/".join(["k8s:", _part(cluster), kind.lower(), _part(namespace), _part(name)])


def _relation(kind: str, target: str, target_kind: str = "resource", **properties) -> dict:
    return {"type": kind, "target": target, "target_kind": target_kind, **properties}


@dataclass
class ContainerInventory:
    provider: str
    import_id: str
    source_execution_id: str
    source: str | None = None
    run_id: str | None = None
    source_schema: str = ""
    observations: list[Observation] = field(default_factory=list)
    diagnostics: list[dict[str, str]] = field(default_factory=list)
    schema_version: str = CONTAINER_SCHEMA_VERSION
    status: str = "ok"

    @property
    def inventory(self) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {}
        for observation in self.observations:
            result.setdefault(observation.attributes["record_type"], []).append(deepcopy(observation.attributes))
        return result

    def to_dict(self) -> dict:
        return {
            "provider": self.provider, "import_id": self.import_id,
            "source_execution_id": self.source_execution_id, "source": self.source,
            "run_id": self.run_id, "source_schema": self.source_schema,
            "schema_version": self.schema_version, "status": self.status,
            "observations": [item.to_dict() for item in self.observations],
            "diagnostics": deepcopy(self.diagnostics),
        }

    def merge_into(self, observations: list[Observation]) -> int:
        known = {item.observation_id for item in observations}
        additions = [item for item in self.observations if item.observation_id not in known]
        observations.extend(additions)
        return len(additions)

    def populate_graph(self, graph) -> int:
        return len(graph.ingest_observations(self.observations))


class _Builder:
    def __init__(self, provider, document, source, run_id, import_id, source_schema):
        digest = sha256(_canonical(_unordered(_raw(document))).encode()).hexdigest()
        identity = [provider, source, run_id, digest]
        import_id = import_id or str(uuid5(NAMESPACE_URL, _canonical(identity)))
        self.result = ContainerInventory(provider, import_id, f"import:{import_id}", source, run_id, source_schema)
        self.observations: dict[tuple[str, str], Observation] = {}
        self.document = document

    def diagnostic(self, message: str, path: str = "", *, invalid: bool = False):
        self.result.diagnostics.append({"path": path, "message": message})
        self.result.status = "invalid" if invalid else "partial"

    def objects(self, value, path: str) -> list[dict]:
        if value is None:
            return []
        if not isinstance(value, list):
            self.diagnostic("Expected an array of objects", path)
            return []
        result = []
        for index, item in enumerate(value):
            if isinstance(item, dict):
                result.append(item)
            else:
                self.diagnostic("Expected an object; record skipped", f"{path}/{index}")
        return result

    def mapping(self, value, path: str) -> dict:
        if value is None:
            return {}
        if not isinstance(value, dict):
            self.diagnostic("Expected an object", path)
            return {}
        return value

    def add(self, record_type, identifier, record, *, kind="resource", relations=(), **attributes):
        key = kind, identifier
        relations = sorted(relations, key=_canonical)
        if key in self.observations:
            observation = self.observations[key]
            known = observation.attributes["relationships"]
            known.extend(item for item in relations if item not in known)
            known.sort(key=_canonical)
            raw = _raw(record)
            if raw and raw != observation.raw:
                evidence = observation.attributes.setdefault("source_records", [observation.raw])
                if raw not in evidence:
                    evidence.append(raw)
                    evidence.sort(key=_canonical)
            # A complete inventory record replaces an earlier reference stub.
            if observation.attributes.get("reference_only") and not attributes.get("reference_only"):
                observation.attributes.update(attributes)
                observation.attributes["reference_only"] = False
                observation.raw = _raw(record)
                observation.attributes["record_type"] = record_type
            return observation
        attrs = {
            "identifier": identifier, "name": attributes.pop("name", None) or identifier,
            "record_type": record_type, "provider": self.result.provider,
            "schema_version": CONTAINER_SCHEMA_VERSION,
            "source": self.result.source, "source_file": self.result.source,
            "run_id": self.result.run_id, "import_id": self.result.import_id,
            "raw_redacted": True, "relationships": relations,
            **attributes,
        }
        observation = Observation(
            kind=kind, target=identifier, attributes=attrs, observed_at=None,
            source_schema=self.result.source_schema,
            source_id=str(record.get("id") or record.get("Id") or record.get("ID") or identifier),
            raw=_raw(record),
            source_execution_id=self.result.source_execution_id,
            module_path=f"interop/containers/{self.result.provider}",
            observation_id=str(uuid5(NAMESPACE_URL, _canonical([self.result.import_id, kind, identifier]))),
            port=attrs.get("port"), protocol=attrs.get("protocol"),
            service=attrs.get("service"), version=attrs.get("version"),
        )
        self.observations[key] = observation
        return observation

    def finish(self):
        for observation in self.observations.values():
            relationships = observation.attributes["relationships"]
            observation.attributes["relationships"] = [json.loads(item) for item in sorted({_canonical(item) for item in relationships})]
        self.result.observations = sorted(self.observations.values(), key=lambda item: (item.kind, item.target))
        self.result.diagnostics.sort(key=_canonical)
        if not self.result.observations and self.result.status == "ok":
            self.diagnostic("No recognized inventory records")
        return self.result


def _prepare(provider, data, source, run_id, import_id, schema, *, jsonl=False):
    try:
        document, detected_source = _load(data, jsonl=jsonl)
        return _Builder(provider, document, source or detected_source, run_id, import_id, schema)
    except (ValueError, OSError, UnicodeError, RecursionError) as error:
        builder = _Builder(provider, {}, source, run_id, import_id, schema)
        builder.diagnostic(f"Cannot read inventory: {type(error).__name__}", invalid=True)
        return builder


def _guard(provider):
    """Reject unsupported JSON field shapes without returning half-built results."""
    def decorate(function):
        @wraps(function)
        def guarded(data, *args, **kwargs):
            try:
                return function(data, *args, **kwargs)
            except (TypeError, AttributeError, KeyError, ValueError, RecursionError):
                builder = _prepare(provider, {}, kwargs.get("source"), kwargs.get("run_id"),
                                   kwargs.get("import_id"), f"{provider}/json")
                builder.diagnostic("Malformed or unsupported record field shape", invalid=True)
                return builder.finish()
        return guarded
    return decorate


def _port(builder, owner, record, path, *, host=None, external=False, resource_owner=None):
    number = record.get("port", record.get("containerPort", record.get("container_port")))
    if isinstance(number, str) and number.isdecimal():
        number = int(number)
    protocol = record.get("protocol", "TCP")
    if not isinstance(protocol, str) or protocol.lower() not in {"tcp", "udp", "sctp"}:
        builder.diagnostic("Unsupported port protocol", path)
        return None
    protocol = protocol.lower()
    if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 65535:
        builder.diagnostic("Port must be an integer between 1 and 65535", path)
        return None
    identifier = f"{owner}/port/{number}/{protocol}"
    resource_owner = resource_owner or owner
    relations = [_relation("has_service", resource_owner, direction="in")]
    if external:
        relations.append(_relation("exposed_to", host or "network:unspecified", exposure="published"))
    builder.add("port", identifier, record, kind="service", relations=relations,
                name=record.get("name") or f"{number}/{protocol}", port=number,
                protocol=protocol, host=host or resource_owner, resource_owner=resource_owner,
                published=external,
                service=record.get("name") or "unknown")
    return identifier


def _kube_records(builder) -> list[tuple[str | None, dict]]:
    document = builder.document
    records = []

    def collect(value, hint=None, path=""):
        if isinstance(value, list):
            for index, item in enumerate(builder.objects(value, path)):
                collect(item, hint, f"{path}/{index}")
        elif isinstance(value, dict):
            kind = value.get("kind", hint)
            if kind == "List" or (isinstance(kind, str) and kind.endswith("List")) or "items" in value:
                item_hint = kind[:-4] if isinstance(kind, str) and kind.endswith("List") and kind != "List" else hint
                collect(builder.objects(value.get("items"), path + "/items"), item_hint, path + "/items")
            elif kind in set(_KINDS.values()):
                records.append((kind, value))
            else:
                builder.diagnostic("Unsupported or missing Kubernetes kind", path)
        else:
            builder.diagnostic("Expected Kubernetes object", path)

    if isinstance(document, list) or document.get("kind") not in (None, "Config"):
        collect(document)
        return records
    if document.get("kind") == "Config" or "current-context" in document:
        for key in ("contexts", "clusters"):
            for record in builder.objects(document.get(key), key):
                records.append((_KINDS[key], record))
        # kubeconfig user entries are deliberately never retained.
        return records
    for key, value in document.items():
        normalized = key.lower().replace("_", "").replace("-", "")
        if normalized in _KINDS:
            collect(value, _KINDS[normalized], key)
        elif key not in {"cluster", "context", "schema_version", "metadata"}:
            builder.diagnostic("Unrecognized Kubernetes inventory collection", key)
    return records


@_guard("kubernetes")
def import_kubernetes_inventory(data, *, cluster=None, context=None, source=None,
                                run_id=None, import_id=None) -> ContainerInventory:
    """Import kubectl List/single JSON, keyed collections, or kubeconfig metadata.

    ``cluster`` scopes resource identities across exports. Without a supplied
    scope a context/cluster entry is inferred, otherwise ``unknown`` is used and
    diagnosed. Namespace defaults follow Kubernetes' ``default`` namespace.
    """
    builder = _prepare("kubernetes", data, source, run_id, import_id, "kubectl/json")
    if builder.result.status == "invalid":
        return builder.finish()
    records = _kube_records(builder)
    document = builder.document if isinstance(builder.document, dict) else {}
    context = context or _text(document.get("current-context")) or _text(document.get("context"))
    if not cluster:
        for kind, record in records:
            if kind == "Context" and (not context or record.get("name") == context):
                cluster = _text(builder.mapping(record.get("context"), "context").get("cluster"))
                if cluster:
                    break
    cluster = cluster or _text(document.get("cluster"))
    if not cluster:
        names = sorted({record["name"] for kind, record in records if kind == "Cluster" and _text(record.get("name"))})
        cluster = names[0] if len(names) == 1 else "unknown"
    if not isinstance(cluster, str) or not cluster.strip():
        builder.diagnostic("Cluster scope must be a nonempty string", invalid=True)
        return builder.finish()
    if cluster == "unknown":
        builder.diagnostic("Cluster scope absent; pass cluster= to correlate independent exports")
    cluster_id = _kube_id(cluster, "Cluster", cluster)

    def reference(kind, name, namespace="", **attrs):
        namespace = "" if kind in _CLUSTER_SCOPED else namespace
        identity = _kube_id(cluster, kind, name, namespace)
        node_kind = {"ServiceAccount": "identity", "Role": "role", "ClusterRole": "role",
                     "NetworkPolicy": "policy", "User": "user", "Group": "group"}.get(kind, "resource")
        builder.add(kind.lower(), identity, {}, kind=node_kind, name=name,
                    reference_only=True, cluster=cluster, namespace=namespace, **attrs)
        return identity

    reference("Cluster", cluster)
    workloads = []
    services = []
    for kind, record in sorted(records, key=lambda item: (str(item[0]), _canonical(_raw(item[1])))):
        metadata = builder.mapping(record.get("metadata"), f"{kind}/metadata")
        name = _text(metadata.get("name")) or (_text(record.get("name")) if kind in {"Context", "Cluster"} else None)
        if not name:
            builder.diagnostic("Resource missing metadata.name; skipped", str(kind))
            continue
        namespace = "" if kind in _CLUSTER_SCOPED else (_text(metadata.get("namespace")) or "default")
        identifier = _kube_id(name if kind == "Cluster" else cluster, kind, name, namespace)
        relations = []
        owner = cluster_id
        if namespace:
            owner = reference("Namespace", namespace)
        if kind != "Cluster":
            relations.append(_relation("contains", owner, direction="in"))
        for parent in builder.objects(metadata.get("ownerReferences"), f"{kind}/{name}/ownerReferences"):
            if _text(parent.get("name")) and _text(parent.get("kind")):
                target = reference(parent["kind"], parent["name"], namespace)
                relations.append(_relation("contains", target, direction="in", owner_uid=parent.get("uid")))
        spec = builder.mapping(record.get("spec"), f"{kind}/{name}/spec")
        labels = builder.mapping(metadata.get("labels"), f"{kind}/{name}/labels")
        attrs = {"cluster": cluster, "namespace": namespace, "name": name,
                 "uid": metadata.get("uid"), "api_version": record.get("apiVersion"),
                 "labels": deepcopy(labels), "context": context, "reference_only": False}
        node_kind = {"ServiceAccount": "identity", "Role": "role", "ClusterRole": "role",
                     "NetworkPolicy": "policy"}.get(kind, "resource")
        if kind == "Context":
            config = builder.mapping(record.get("context"), f"Context/{name}/context")
            linked_cluster = _text(config.get("cluster"))
            if linked_cluster:
                relations.append(_relation("references", _kube_id(linked_cluster, "Cluster", linked_cluster)))
            if _text(config.get("namespace")):
                relations.append(_relation("references", reference("Namespace", config["namespace"])))
        elif kind in _WORKLOADS:
            pod_spec = spec
            template_labels = labels
            if kind != "Pod":
                if kind == "CronJob":
                    job_template = builder.mapping(spec.get("jobTemplate"), f"{kind}/{name}/jobTemplate")
                    spec = builder.mapping(job_template.get("spec"), f"{kind}/{name}/jobTemplate/spec")
                template = builder.mapping(spec.get("template"), f"{kind}/{name}/template")
                pod_spec = builder.mapping(template.get("spec"), f"{kind}/{name}/template/spec")
                template_metadata = builder.mapping(template.get("metadata"), f"{kind}/{name}/template/metadata")
                template_labels = builder.mapping(template_metadata.get("labels"), f"{kind}/{name}/template/labels")
            workloads.append((identifier, namespace, template_labels, kind))
            service_account = _text(pod_spec.get("serviceAccountName")) or "default"
            relations.append(_relation("references", reference("ServiceAccount", service_account, namespace), "identity"))
            if _text(pod_spec.get("nodeName")):
                relations.append(_relation("runs_on", reference("Node", pod_spec["nodeName"])))
            attrs["host_network"] = pod_spec.get("hostNetwork") is True
            for field_name in ("containers", "initContainers", "ephemeralContainers"):
                for index, container in enumerate(builder.objects(pod_spec.get(field_name), f"{kind}/{name}/{field_name}")):
                    container_name = _text(container.get("name"))
                    if not container_name:
                        builder.diagnostic("Container missing name; skipped", f"{kind}/{name}/{field_name}/{index}")
                        continue
                    container_id = f"{identifier}/container/{_part(container_name)}"
                    container_relations = [_relation("contains", identifier, direction="in")]
                    image = _text(container.get("image"))
                    if image:
                        image_id = f"container:image/{_part(image)}"
                        builder.add("image", image_id, {"reference": image}, name=image, reference_only=True)
                        container_relations.append(_relation("uses_image", image_id))
                        relations.append(_relation("uses_image", image_id))
                    for port in builder.objects(container.get("ports"), f"{kind}/{name}/{container_name}/ports"):
                        _port(builder, container_id, port, f"{kind}/{name}/{container_name}/ports")
                    refs = _pod_references(builder, container, f"{kind}/{name}/{container_name}")
                    for ref_kind, ref_name in refs:
                        container_relations.append(_relation("references", reference(ref_kind, ref_name, namespace)))
                    builder.add("container", container_id, container, relations=container_relations,
                                name=container_name, cluster=cluster, namespace=namespace,
                                container_type=field_name, image=image)
            for ref_kind, ref_name in _pod_references(builder, pod_spec, f"{kind}/{name}"):
                relations.append(_relation("references", reference(ref_kind, ref_name, namespace)))
        elif kind == "Service":
            service_type = spec.get("type", "ClusterIP")
            attrs["service_type"] = service_type
            attrs["selector"] = builder.mapping(spec.get("selector"), f"Service/{name}/selector")
            services.append((identifier, namespace, attrs["selector"]))
            attrs["cluster_ip"] = spec.get("clusterIP")
            # NodePort is reachable at nodes; LoadBalancer needs actual status addresses.
            status = builder.mapping(record.get("status"), f"Service/{name}/status")
            lb = builder.mapping(status.get("loadBalancer"), f"Service/{name}/loadBalancer")
            external = []
            for endpoint in builder.objects(lb.get("ingress"), f"Service/{name}/loadBalancer/ingress"):
                address = _text(endpoint.get("ip")) or _text(endpoint.get("hostname"))
                if address:
                    external.append(address)
            external_ips = spec.get("externalIPs", [])
            if isinstance(external_ips, list):
                external.extend(item for item in external_ips if _text(item))
            else:
                builder.diagnostic("externalIPs must be an array", f"Service/{name}")
            for address in sorted(set(external)):
                relations.append(_relation("exposed_to", f"network:address/{_part(address)}", address=address))
            if service_type == "NodePort":
                relations.append(_relation("exposed_to", f"{cluster_id}/node-network", exposure="nodeport"))
            for port in builder.objects(spec.get("ports"), f"Service/{name}/ports"):
                port_id = _port(builder, identifier, port, f"Service/{name}/ports")
                if port_id:
                    target_port = port.get("targetPort", port.get("port"))
                    builder.observations[("service", port_id)].attributes["target_port"] = target_port
                    node_port = port.get("nodePort")
                    if node_port is not None:
                        published = _port(builder, identifier + "/nodeport", {**port, "port": node_port},
                                          f"Service/{name}/nodePort", external=True,
                                          host=f"{cluster_id}/node-network", resource_owner=identifier)
                        if published:
                            builder.observations[("service", published)].attributes["relationships"].append(
                                _relation("routes_to", port_id, "service"))
        elif kind in {"Ingress", "Route"}:
            backends, hosts, tls_secrets = _ingress(builder, kind, spec, name)
            for backend in backends:
                relations.append(_relation("routes_to", reference("Service", backend["name"], namespace),
                                           backend_port=backend.get("port")))
            for host in hosts:
                relations.append(_relation("exposed_to", f"network:hostname/{_part(host)}", hostname=host))
            for secret_name in tls_secrets:
                relations.append(_relation("references", reference("Secret", secret_name, namespace)))
        elif kind in {"Role", "ClusterRole"}:
            attrs["rules"] = _raw(builder.objects(record.get("rules"), f"{kind}/{name}/rules"))
        elif kind in {"RoleBinding", "ClusterRoleBinding"}:
            role_ref = builder.mapping(record.get("roleRef"), f"{kind}/{name}/roleRef")
            role_kind, role_name = role_ref.get("kind"), _text(role_ref.get("name"))
            role_id = None
            if role_kind not in {"Role", "ClusterRole"} or not role_name or (kind == "ClusterRoleBinding" and role_kind != "ClusterRole"):
                builder.diagnostic("Missing or invalid RBAC roleRef", f"{kind}/{name}")
            else:
                role_id = reference(role_kind, role_name, namespace)
                relations.append(_relation("references", role_id, "role"))
            attrs["role_ref"] = deepcopy(role_ref)
            attrs["subjects"] = []
            for subject in builder.objects(record.get("subjects"), f"{kind}/{name}/subjects"):
                subject_kind, subject_name = subject.get("kind"), _text(subject.get("name"))
                if subject_kind not in {"User", "Group", "ServiceAccount"} or not subject_name:
                    builder.diagnostic("Invalid RBAC subject", f"{kind}/{name}/subjects")
                    continue
                subject_ns = _text(subject.get("namespace")) or namespace
                if subject_kind == "ServiceAccount" and not subject_ns:
                    builder.diagnostic("Cluster binding service-account subject requires namespace", f"{kind}/{name}/subjects")
                    continue
                subject_id = reference(subject_kind, subject_name, subject_ns if subject_kind == "ServiceAccount" else "")
                subject_node_kind = {"ServiceAccount": "identity", "User": "user", "Group": "group"}[subject_kind]
                relations.append(_relation("applies_to", subject_id, subject_node_kind))
                if role_id:
                    subject_observation = builder.observations[(subject_node_kind, subject_id)]
                    subject_observation.attributes["relationships"].append(
                        _relation("has_permission", role_id, "role", binding=identifier,
                                  namespace=namespace, scope="cluster" if kind == "ClusterRoleBinding" else "namespace"))
                attrs["subjects"].append(deepcopy(subject))
        elif kind == "ServiceAccount":
            for field_name, ref_kind in (("secrets", "Secret"), ("imagePullSecrets", "Secret")):
                for ref in builder.objects(record.get(field_name), f"ServiceAccount/{name}/{field_name}"):
                    if _text(ref.get("name")):
                        relations.append(_relation("references", reference(ref_kind, ref["name"], namespace)))
        elif kind == "NetworkPolicy":
            attrs["pod_selector"] = deepcopy(builder.mapping(spec.get("podSelector"), f"NetworkPolicy/{name}/podSelector"))
            attrs["policy_types"] = deepcopy(spec.get("policyTypes", []))
            attrs["ingress"] = _raw(builder.objects(spec.get("ingress"), f"NetworkPolicy/{name}/ingress"))
            attrs["egress"] = _raw(builder.objects(spec.get("egress"), f"NetworkPolicy/{name}/egress"))
        elif kind in {"Secret", "ConfigMap"}:
            # Include key names only; values are neither decoded nor retained.
            attrs["keys"] = sorted({key for field_name in ("data", "stringData", "binaryData")
                                    for key in builder.mapping(record.get(field_name), f"{kind}/{name}/{field_name}")})
            attrs["secret_type"] = record.get("type") if kind == "Secret" else None
        builder.add(kind.lower(), identifier, record, kind=node_kind, relations=relations, **attrs)

    for service_id, namespace, selector in services:
        if selector:
            for workload_id, workload_ns, labels, workload_kind in workloads:
                if workload_ns == namespace and workload_kind == "Pod" and all(labels.get(key) == value for key, value in selector.items()):
                    builder.observations[("resource", service_id)].attributes["relationships"].append(
                        _relation("routes_to", workload_id, selector=deepcopy(selector)))
    for observation in list(builder.observations.values()):
        if observation.attributes["record_type"] == "networkpolicy":
            selector = observation.attributes.get("pod_selector", {})
            for workload_id, namespace, labels, workload_kind in workloads:
                if workload_kind == "Pod" and namespace == observation.attributes["namespace"] and _matches_selector(builder, labels, selector):
                    observation.attributes["relationships"].append(_relation("applies_to", workload_id))
    return builder.finish()


def _matches_selector(builder, labels, selector):
    if ("matchLabels" in selector and not isinstance(selector["matchLabels"], dict)) or (
        "matchExpressions" in selector and not isinstance(selector["matchExpressions"], list)
    ):
        builder.diagnostic("Invalid label-selector shape", "podSelector")
        return False
    matches = builder.mapping(selector.get("matchLabels"), "podSelector/matchLabels")
    if any(labels.get(key) != value for key, value in matches.items()):
        return False
    for expression in builder.objects(selector.get("matchExpressions"), "podSelector/matchExpressions"):
        key, operator, values = expression.get("key"), expression.get("operator"), expression.get("values", [])
        if not _text(key) or not isinstance(values, list):
            builder.diagnostic("Invalid label-selector expression", "podSelector")
            return False
        if operator == "In":
            matched = key in labels and labels[key] in values
        elif operator == "NotIn":
            matched = key not in labels or labels[key] not in values
        elif operator == "Exists":
            matched = key in labels
        elif operator == "DoesNotExist":
            matched = key not in labels
        else:
            builder.diagnostic("Unsupported label-selector operator", "podSelector")
            return False
        if not matched:
            return False
    return True


def _pod_references(builder, spec, path):
    references = set()

    def ref(kind, value):
        if isinstance(value, dict) and _text(value.get("name")):
            references.add((kind, value["name"]))
        elif value is not None:
            builder.diagnostic("Reference requires an object with a name", path)

    for env in builder.objects(spec.get("env"), path + "/env"):
        value_from = builder.mapping(env.get("valueFrom"), path + "/valueFrom")
        ref("Secret", value_from.get("secretKeyRef"))
        ref("ConfigMap", value_from.get("configMapKeyRef"))
    for env in builder.objects(spec.get("envFrom"), path + "/envFrom"):
        ref("Secret", env.get("secretRef"))
        ref("ConfigMap", env.get("configMapRef"))
    for image_secret in builder.objects(spec.get("imagePullSecrets"), path + "/imagePullSecrets"):
        ref("Secret", image_secret)
    for volume in builder.objects(spec.get("volumes"), path + "/volumes"):
        secret = builder.mapping(volume.get("secret"), path + "/volumes/secret")
        if _text(secret.get("secretName")):
            references.add(("Secret", secret["secretName"]))
        ref("ConfigMap", volume.get("configMap"))
        projected = builder.mapping(volume.get("projected"), path + "/volumes/projected")
        for item in builder.objects(projected.get("sources"), path + "/volumes/projected/sources"):
            ref("Secret", item.get("secret"))
            ref("ConfigMap", item.get("configMap"))
    return sorted(references)


def _ingress(builder, kind, spec, name):
    backends, hosts, secrets = [], set(), set()

    def backend(value):
        value = builder.mapping(value, f"{kind}/{name}/backend")
        service = builder.mapping(value.get("service"), f"{kind}/{name}/backend/service")
        service_name = _text(service.get("name")) or _text(value.get("serviceName"))
        port = service.get("port", value.get("servicePort"))
        if isinstance(port, dict):
            port = port.get("number", port.get("name"))
        if service_name:
            backends.append({"name": service_name, "port": port})

    if kind == "Route":
        target = builder.mapping(spec.get("to"), f"Route/{name}/to")
        if target.get("kind", "Service") == "Service" and _text(target.get("name")):
            port = builder.mapping(spec.get("port"), f"Route/{name}/port").get("targetPort")
            backends.append({"name": target["name"], "port": port})
        if _text(spec.get("host")):
            hosts.add(spec["host"])
        for target in builder.objects(spec.get("alternateBackends"), f"Route/{name}/alternateBackends"):
            if target.get("kind", "Service") == "Service" and _text(target.get("name")):
                backends.append({"name": target["name"]})
    else:
        backend(spec.get("defaultBackend", spec.get("backend")))
        for rule in builder.objects(spec.get("rules"), f"Ingress/{name}/rules"):
            if _text(rule.get("host")):
                hosts.add(rule["host"])
            http = builder.mapping(rule.get("http"), f"Ingress/{name}/http")
            for path in builder.objects(http.get("paths"), f"Ingress/{name}/paths"):
                backend(path.get("backend"))
        for tls in builder.objects(spec.get("tls"), f"Ingress/{name}/tls"):
            if _text(tls.get("secretName")):
                secrets.add(tls["secretName"])
    return backends, sorted(hosts), sorted(secrets)


@_guard("container")
def import_container_inventory(data, *, provider="docker", runtime=None, source=None,
                               run_id=None, import_id=None) -> ContainerInventory:
    """Import Docker/Podman inspect/list JSON or crictl images/ps/inspect JSON.

    Keyed ``images``, ``containers``, ``networks`` collections can be combined.
    ``runtime`` distinguishes hosts/runtimes with locally scoped container IDs.
    Docker/Podman formatted JSON-lines output is accepted as well.
    """
    if provider not in {"docker", "podman", "crictl"}:
        raise ValueError("provider must be docker, podman or crictl")
    builder = _prepare(provider, data, source, run_id, import_id, f"{provider}/json", jsonl=True)
    if builder.result.status == "invalid":
        return builder.finish()
    runtime = runtime or "unknown"
    if not isinstance(runtime, str) or not runtime.strip():
        builder.diagnostic("Runtime scope must be a nonempty string", invalid=True)
        return builder.finish()
    if runtime == "unknown":
        builder.diagnostic("Runtime host scope absent; pass runtime= to correlate exports")
    runtime_id = f"container:runtime/{provider}/{_part(runtime)}"
    builder.add("runtime", runtime_id, {}, name=runtime, reference_only=True)
    document = builder.document
    collections = []
    if isinstance(document, list):
        collections.append((None, document))
    elif any(key in document for key in ("images", "containers", "networks")):
        collections.extend((key[:-1], builder.objects(document[key], key)) for key in ("images", "containers", "networks") if key in document)
    elif isinstance(document.get("status"), dict):
        status = deepcopy(document["status"])
        info = document.get("info", {})
        if isinstance(info, dict):
            status.update({key: value for key, value in info.items() if key not in status})
        collections.append((_runtime_type(status) or "container", [status]))
    else:
        collections.append((None, [document]))
    for hint, records in collections:
        for record in sorted(builder.objects(records, hint or "records"), key=lambda item: _canonical(_raw(item))):
            record_type = hint or _runtime_type(record)
            if record_type is None:
                builder.diagnostic("Cannot identify runtime record type; use keyed collections")
                continue
            value = record.get("Id") or record.get("ID") or record.get("id") or record.get("Digest")
            if record_type == "image":
                value = value or record.get("RepoDigests") or record.get("repoDigests") or record.get("Repository")
                if isinstance(value, list):
                    value = next((item for item in value if _text(item)), None)
            if not _text(value):
                builder.diagnostic("Runtime record missing a string ID; skipped", record_type)
                continue
            identifier = f"container:{record_type}/{_part(value)}" if record_type == "image" else f"{runtime_id}/{record_type}/{_part(value)}"
            relations = [_relation("contains", runtime_id, direction="in")]
            name = record.get("Name") or record.get("Names") or record.get("name")
            metadata = builder.mapping(record.get("metadata"), f"{record_type}/metadata")
            if not name:
                name = metadata.get("name") or value
            if isinstance(name, list):
                name = ",".join(item for item in name if isinstance(item, str))
            attrs = {"runtime": runtime, "runtime_provider": provider, "name": str(name), "reference_only": False}
            if record_type == "image":
                tags = record.get("RepoTags", record.get("repoTags", record.get("Names", [])))
                if not tags and _text(record.get("Repository")):
                    tag = _text(record.get("Tag"))
                    tags = [record["Repository"] + (f":{tag}" if tag and tag != "<none>" else "")]
                attrs["tags"] = deepcopy(tags) if isinstance(tags, list) else [tags]
                attrs["digests"] = deepcopy(record.get("RepoDigests", record.get("repoDigests", [])))
                attrs["size"] = record.get("Size", record.get("size"))
                for reference in attrs["tags"] + attrs["digests"]:
                    if _text(reference) and reference != "<none>:<none>":
                        alias_id = f"container:image/{_part(reference)}"
                        if alias_id != identifier:
                            relations.append(_relation("identifies", alias_id, direction="in", reference=reference))
            elif record_type == "container":
                config = builder.mapping(record.get("Config"), "container/Config")
                image = record.get("ImageID") or record.get("imageRef") or record.get("Image") or record.get("image") or config.get("Image")
                if isinstance(image, dict):
                    image = image.get("image")
                if _text(image):
                    image_id = f"container:image/{_part(image)}"
                    builder.add("image", image_id, {"reference": image}, name=image, reference_only=True)
                    relations.append(_relation("uses_image", image_id))
                    attrs["image"] = image
                attrs["state"] = _raw(record.get("State", record.get("state")))
                mounts = record.get("Mounts", record.get("mounts", []))
                for index, mount in enumerate(builder.objects(mounts, "container/mounts")):
                    destination = mount.get("Destination", mount.get("containerPath", mount.get("destination")))
                    if not _text(destination):
                        builder.diagnostic("Mount missing destination; skipped", "container/mounts")
                        continue
                    mount_id = f"{identifier}/mount/{_part(destination)}"
                    builder.add("mount", mount_id, mount, relations=[_relation("contains", identifier, direction="in")],
                                destination=destination, source_path=mount.get("Source", mount.get("hostPath")),
                                read_only=mount.get("RW") is False or mount.get("readonly") is True)
                settings = builder.mapping(record.get("NetworkSettings"), "container/NetworkSettings")
                networks = builder.mapping(settings.get("Networks"), "container/Networks")
                for network_name, network in sorted(networks.items()):
                    network = builder.mapping(network, "container/Networks/" + network_name)
                    network_value = _text(network.get("NetworkID")) or network_name
                    network_id = f"{runtime_id}/network/{_part(network_value)}"
                    builder.add("network", network_id, network, name=network_name, reference_only=True)
                    relations.append(_relation("member_of", network_id, address=network.get("IPAddress")))
                _runtime_ports(builder, identifier, record, config, settings)
            elif record_type == "network":
                attrs["driver"] = record.get("Driver", record.get("driver"))
                attrs["internal"] = record.get("Internal", record.get("internal"))
                attrs["ipam"] = _raw(record.get("IPAM", record.get("subnets", {})))
                members = builder.mapping(record.get("Containers"), "network/Containers")
                for container_id, details in sorted(members.items()):
                    relations.append(_relation("member_of", f"{runtime_id}/container/{_part(container_id)}", direction="in"))
            builder.add(record_type, identifier, record, relations=relations, **attrs)
    return builder.finish()


def _runtime_type(record):
    if any(key in record for key in ("RepoTags", "repoTags", "RepoDigests", "repoDigests", "Repository")):
        return "image"
    if any(key in record for key in ("Image", "ImageID", "image", "imageRef", "Config", "State", "state")):
        return "container"
    if any(key in record for key in ("Driver", "IPAM", "driver", "subnets")):
        return "network"
    return None


def _runtime_ports(builder, identifier, record, config, settings):
    bindings = builder.mapping(settings.get("Ports"), "NetworkSettings/Ports")
    host_config = builder.mapping(record.get("HostConfig"), "HostConfig")
    for key, value in builder.mapping(host_config.get("PortBindings"), "HostConfig/PortBindings").items():
        bindings.setdefault(key, value)
    for key in builder.mapping(config.get("ExposedPorts"), "Config/ExposedPorts"):
        bindings.setdefault(key, None)
    for key, values in sorted(bindings.items()):
        pieces = key.split("/")
        port = {"port": pieces[0], "protocol": pieces[1] if len(pieces) == 2 else "tcp"}
        endpoint = _port(builder, identifier, port, "Ports/" + key)
        if not endpoint:
            continue
        for binding in builder.objects(values, "Ports/" + key):
            address = _text(binding.get("HostIp")) or _text(binding.get("HostIP")) or "0.0.0.0"
            published = _port(builder, identifier + "/published/" + _part(address),
                              {"port": binding.get("HostPort"), "protocol": port["protocol"]},
                              "Ports/" + key, external=True, host=address, resource_owner=identifier)
            if published:
                builder.observations[("service", published)].attributes["relationships"].append(_relation("routes_to", endpoint, "service"))
    # Podman inspect/ps port-mapping objects and Docker Engine list Ports objects.
    ports = record.get("Ports", record.get("ports", record.get("portMappings")))
    if ports is not None:
        if isinstance(ports, str):
            builder.diagnostic("Formatted port strings are not lossless; provide inspect or Engine Ports JSON", "Ports")
        else:
            for port in builder.objects(ports, "Ports"):
                private = port.get("PrivatePort", port.get("container_port", port.get("containerPort")))
                protocol = port.get("Type", port.get("protocol", "tcp"))
                endpoint = _port(builder, identifier, {"port": private, "protocol": protocol}, "Ports")
                public = port.get("PublicPort", port.get("host_port", port.get("hostPort")))
                if public is not None and endpoint:
                    address = port.get("IP", port.get("host_ip", port.get("hostIP", "0.0.0.0")))
                    published = _port(builder, identifier + "/published/" + _part(str(address)),
                                      {"port": public, "protocol": protocol}, "Ports", external=True,
                                      host=address, resource_owner=identifier)
                    if published:
                        builder.observations[("service", published)].attributes["relationships"].append(_relation("routes_to", endpoint, "service"))


def import_docker_inventory(data, **kwargs):
    return import_container_inventory(data, provider="docker", **kwargs)


def import_podman_inventory(data, **kwargs):
    return import_container_inventory(data, provider="podman", **kwargs)


def import_crictl_inventory(data, **kwargs):
    return import_container_inventory(data, provider="crictl", **kwargs)


def _severity(value):
    normalized = value.lower() if isinstance(value, str) else "unknown"
    return {"negligible": "info", "informational": "info", "moderate": "medium"}.get(
        normalized, normalized if normalized in {"critical", "high", "medium", "low", "info"} else "unknown")


def _package(builder, owner, record, *, name, version, package_type=None, source_id=None):
    if not _text(name):
        builder.diagnostic("Package missing name; skipped", "packages")
        return None
    package_key = [owner, source_id or name, version, package_type]
    identifier = "container:package/" + sha256(_canonical(package_key).encode()).hexdigest()[:24]
    builder.add("package", identifier, record, relations=[_relation("contains", owner, direction="in")],
                name=name, version=version, package_type=package_type, package_id=source_id)
    return identifier


def _finding(builder, owner, package, record, *, vulnerability_id, severity, fixed_versions=None,
             title=None, description=None, aliases=None, **extra):
    if not _text(vulnerability_id):
        builder.diagnostic("Finding missing vulnerability identifier; skipped", "findings")
        return
    aliases = [item for item in aliases or [] if _text(item)]
    cves = sorted({item.upper() for item in [vulnerability_id, *aliases] if item.upper().startswith("CVE-")})
    identifier = "container:finding/" + sha256(_canonical([owner, package, vulnerability_id]).encode()).hexdigest()[:24]
    relations = [_relation("has_vulnerability", package or owner, direction="in")]
    observation = builder.add("finding", identifier, record, kind="finding", relations=relations,
                name=title or vulnerability_id, title=title or vulnerability_id,
                description=description, vulnerability_id=vulnerability_id, cves=cves,
                cve_ids=cves, aliases=sorted(set(aliases)), severity=_severity(severity),
                original_severity=severity, fixed_versions=fixed_versions or [],
                package=package, affected_resource=owner, **extra)
    rank = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    attrs = observation.attributes
    if rank[_severity(severity)] > rank[attrs["severity"]]:
        attrs["severity"] = _severity(severity)
        attrs["original_severity"] = severity
    attrs["cves"] = attrs["cve_ids"] = sorted(set(attrs["cves"]) | set(cves))
    attrs["aliases"] = sorted(set(attrs["aliases"]) | set(aliases))
    attrs["fixed_versions"] = sorted(set(attrs["fixed_versions"]) | set(fixed_versions or []))


@_guard("trivy")
def import_trivy_json(data, *, source=None, run_id=None, import_id=None) -> ContainerInventory:
    """Import Trivy image/filesystem/SBOM JSON vulnerabilities and package inventory."""
    builder = _prepare("trivy", data, source, run_id, import_id, "trivy/json")
    document = builder.document
    if builder.result.status == "invalid":
        return builder.finish()
    if not isinstance(document, dict) or "Results" not in document:
        builder.diagnostic("Expected Trivy JSON object containing Results", invalid=True)
        return builder.finish()
    artifact = _text(document.get("ArtifactName")) or _text(document.get("ArtifactID"))
    if not artifact:
        artifact = f"unknown-artifact:{builder.result.import_id}"
        builder.diagnostic("Artifact identity absent; scan isolated by import ID", "ArtifactName")
    artifact_id = "container:image/" + _part(_text(document.get("ArtifactID")) or artifact)
    builder.result.source_schema = f"trivy/{document.get('SchemaVersion', 'unknown')}"
    image_relations = []
    if artifact_id != "container:image/" + _part(artifact):
        image_relations.append(_relation("identifies", "container:image/" + _part(artifact), direction="in"))
    builder.add("image", artifact_id, {key: value for key, value in document.items() if key != "Results"}, name=artifact,
                relations=image_relations,
                artifact_type=document.get("ArtifactType"), scanner="trivy")
    for result in sorted(builder.objects(document.get("Results"), "Results"), key=lambda item: _canonical(_raw(item))):
        target = _text(result.get("Target")) or artifact
        owner = artifact_id + "/target/" + _part(target)
        builder.add("scan_target", owner, {key: value for key, value in result.items() if key not in {"Packages", "Vulnerabilities", "Secrets"}},
                    name=target, relations=[_relation("contains", artifact_id, direction="in")],
                    target_type=result.get("Type"), target_class=result.get("Class"))
        packages = {}
        for package in sorted(builder.objects(result.get("Packages"), "Results/Packages"), key=lambda item: _canonical(_raw(item))):
            name, version = package.get("Name"), package.get("Version")
            identity = _package(builder, owner, package, name=name, version=version,
                                package_type=result.get("Type"), source_id=package.get("ID"))
            if identity:
                packages[(package.get("ID"), name, version)] = identity
        for vulnerability in sorted(builder.objects(result.get("Vulnerabilities"), "Results/Vulnerabilities"), key=lambda item: _canonical(_raw(item))):
            name, version, package_id = vulnerability.get("PkgName"), vulnerability.get("InstalledVersion"), vulnerability.get("PkgID")
            package = next((identity for (key, pkg_name, pkg_version), identity in packages.items()
                            if (package_id and key == package_id) or (pkg_name == name and pkg_version == version)), None)
            if package is None:
                package = _package(builder, owner, {"Name": name, "Version": version, "ID": package_id},
                                   name=name, version=version, source_id=package_id, package_type=result.get("Type"))
            fixed = vulnerability.get("FixedVersion")
            _finding(builder, owner, package, vulnerability,
                     vulnerability_id=vulnerability.get("VulnerabilityID"), severity=vulnerability.get("Severity"),
                     fixed_versions=[part.strip() for part in fixed.split(",") if part.strip()] if isinstance(fixed, str) else [],
                     title=vulnerability.get("Title"), description=vulnerability.get("Description"),
                     references=deepcopy(vulnerability.get("References", [])),
                     data_source=_raw(vulnerability.get("DataSource", {})), cvss=_raw(vulnerability.get("CVSS", {})))
        for field_name in ("Secrets", "Misconfigurations", "Licenses"):
            if result.get(field_name):
                builder.diagnostic(f"{field_name} records are outside the vulnerability/package adapter", "Results/" + field_name)
    return builder.finish()


@_guard("grype")
def import_grype_json(data, *, source=None, run_id=None, import_id=None) -> ContainerInventory:
    """Import Grype JSON matches, retaining scanner severity, aliases and fixes."""
    builder = _prepare("grype", data, source, run_id, import_id, "grype/json")
    document = builder.document
    if builder.result.status == "invalid":
        return builder.finish()
    if not isinstance(document, dict) or "matches" not in document:
        builder.diagnostic("Expected Grype JSON object containing matches", invalid=True)
        return builder.finish()
    origin = builder.mapping(document.get("source"), "source")
    target = builder.mapping(origin.get("target"), "source/target") if isinstance(origin.get("target"), dict) else {}
    artifact = _text(target.get("imageID")) or _text(target.get("userInput")) or _text(origin.get("target"))
    if not artifact:
        artifact = f"unknown-artifact:{builder.result.import_id}"
        builder.diagnostic("Artifact identity absent; scan isolated by import ID", "source/target")
    artifact_id = "container:image/" + _part(artifact)
    descriptor = builder.mapping(document.get("descriptor"), "descriptor")
    builder.result.source_schema = "grype/" + str(descriptor.get("version", "unknown"))
    builder.add("image", artifact_id, origin, name=artifact, scanner="grype", artifact_type=origin.get("type"))
    for match in sorted(builder.objects(document.get("matches"), "matches"), key=lambda item: _canonical(_raw(item))):
        artifact_record = builder.mapping(match.get("artifact"), "matches/artifact")
        vulnerability = builder.mapping(match.get("vulnerability"), "matches/vulnerability")
        package = _package(builder, artifact_id, artifact_record, name=artifact_record.get("name"),
                           version=artifact_record.get("version"), package_type=artifact_record.get("type"),
                           source_id=artifact_record.get("id"))
        aliases = [item.get("id") for item in builder.objects(match.get("relatedVulnerabilities"), "matches/relatedVulnerabilities") if _text(item.get("id"))]
        fixes = builder.mapping(vulnerability.get("fix"), "matches/vulnerability/fix")
        versions = fixes.get("versions", [])
        if not isinstance(versions, list):
            builder.diagnostic("Fix versions must be an array", "matches/vulnerability/fix")
            versions = []
        _finding(builder, artifact_id, package, match, vulnerability_id=vulnerability.get("id"),
                 severity=vulnerability.get("severity"), aliases=aliases,
                 fixed_versions=[item for item in versions if _text(item)],
                 description=vulnerability.get("description"),
                 fix_state=fixes.get("state"), data_source=vulnerability.get("dataSource"),
                 references=deepcopy(vulnerability.get("urls", [])), cvss=_raw(vulnerability.get("cvss", [])),
                 match_details=_raw(match.get("matchDetails", [])), purl=artifact_record.get("purl"))
    return builder.finish()


__all__ = [
    "CONTAINER_SCHEMA_VERSION", "ContainerInventory", "import_kubernetes_inventory",
    "import_container_inventory", "import_docker_inventory", "import_podman_inventory",
    "import_crictl_inventory", "import_trivy_json", "import_grype_json",
]
