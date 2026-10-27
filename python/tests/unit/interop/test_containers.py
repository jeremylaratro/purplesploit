"""Container capability contracts from recorded JSON, with no live collectors."""

from copy import deepcopy
import json
from pathlib import Path
import socket
import subprocess

import pytest

from purplesploit.core.attack_graph import AttackGraph, EdgeType, NodeType
from purplesploit.interop.containers import (
    CONTAINER_SCHEMA_VERSION,
    import_container_inventory,
    import_crictl_inventory,
    import_docker_inventory,
    import_grype_json,
    import_kubernetes_inventory,
    import_podman_inventory,
    import_trivy_json,
)


FIXTURES = Path(__file__).parents[2] / "fixtures" / "containers"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def of_type(result, record_type):
    return [observation for observation in result.observations
            if observation.attributes["record_type"] == record_type]


def named(result, record_type, name):
    return next(item for item in of_type(result, record_type) if item.attributes["name"] == name)


def relationships(observation, relationship):
    return [item for item in observation.attributes["relationships"] if item["type"] == relationship]


def test_kubernetes_full_inventory_and_workload_relationships():
    result = import_kubernetes_inventory(fixture("kubernetes.json"), cluster="dev", context="dev-context")
    assert result.status == "ok"
    assert set(result.inventory) >= {
        "context", "cluster", "namespace", "node", "pod", "deployment", "statefulset",
        "daemonset", "job", "cronjob", "container", "service", "ingress", "route", "role",
        "clusterrole", "rolebinding", "clusterrolebinding", "serviceaccount", "networkpolicy",
        "secret", "configmap", "image", "port",
    }
    pod = named(result, "pod", "web-1")
    node = named(result, "node", "node-a")
    assert relationships(pod, "runs_on")[0]["target"] == node.target
    assert any(item["target"] == named(result, "namespace", "apps").target for item in relationships(pod, "contains"))
    assert named(result, "image", "example.test/web:v1").target in {item["target"] for item in relationships(pod, "uses_image")}
    assert {item.attributes["container_type"] for item in of_type(result, "container")} >= {
        "containers", "initContainers", "ephemeralContainers",
    }
    service = named(result, "service", "web")
    assert relationships(service, "routes_to")[0]["target"] == pod.target
    assert relationships(named(result, "networkpolicy", "web-ingress"), "applies_to")[0]["target"] == pod.target
    assert len({item.observation_id for item in result.observations}) == len(result.observations)


def test_kubernetes_tcp_udp_nodeport_and_exposure_evidence():
    result = import_kubernetes_inventory(fixture("kubernetes.json"), cluster="dev")
    service = named(result, "service", "web")
    ports = [item for item in of_type(result, "port")
             if item.attributes["resource_owner"] == service.target and not item.attributes["published"]]
    assert {(item.port, item.protocol) for item in ports} == {(53, "tcp"), (53, "udp")}
    assert len({item.target for item in ports}) == 2
    node_ports = [item for item in of_type(result, "port") if item.port == 30053]
    assert {item.protocol for item in node_ports} == {"tcp", "udp"}
    assert all(relationships(item, "exposed_to") for item in node_ports)
    assert all(relationships(item, "routes_to") and item.attributes["resource_owner"] == service.target for item in node_ports)
    assert relationships(named(result, "service", "public"), "exposed_to")[0]["address"] == "198.51.100.5"
    assert not relationships(named(result, "service", "private-lb"), "exposed_to")
    # Declared ingress hosts are inventory exposure, never an assertion of internet reachability.
    ingress = named(result, "ingress", "web")
    assert relationships(ingress, "routes_to")[0]["target"] == service.target
    assert relationships(ingress, "routes_to")[0]["backend_port"] == 53
    assert relationships(ingress, "exposed_to")[0]["hostname"] == "web.example.test"
    assert "internet" not in json.dumps(result.to_dict())


def test_kubernetes_rbac_scopes_subjects_roles_and_rules():
    result = import_kubernetes_inventory(fixture("kubernetes.json"), cluster="dev")
    role = named(result, "role", "reader")
    cluster_role = named(result, "clusterrole", "viewer")
    binding = named(result, "rolebinding", "read")
    assert role.attributes["rules"][0]["verbs"] == ["get", "list"]
    assert relationships(binding, "references")[0]["target"] == role.target
    assert {item["target_kind"] for item in relationships(binding, "applies_to")} == {"identity", "user", "group"}
    account = named(result, "serviceaccount", "web")
    assert account.attributes["reference_only"] is False
    permissions = relationships(account, "has_permission")
    assert {(item["target"], item["scope"], item["namespace"]) for item in permissions} == {
        (role.target, "namespace", "apps"), (cluster_role.target, "cluster", ""),
    }
    assert named(result, "clusterrolebinding", "view").attributes["namespace"] == ""


def test_kubernetes_secret_references_are_metadata_only_and_do_not_mutate_input():
    document = fixture("kubernetes.json")
    original = deepcopy(document)
    result = import_kubernetes_inventory(document, cluster="dev")
    assert document == original
    secret = named(result, "secret", "db")
    assert secret.attributes["keys"] == ["extra", "password"]
    assert secret.attributes["secret_type"] == "Opaque"
    assert named(result, "configmap", "settings").attributes["keys"] == ["logo", "settings.json"]
    assert {item.attributes["name"] for item in of_type(result, "secret")} >= {
        "db", "shared", "tls", "projected-secret", "registry", "web-token",
    }
    pod = named(result, "pod", "web-1")
    assert any(item["target"] == named(result, "secret", "tls").target for item in relationships(pod, "references"))
    container = next(item for item in of_type(result, "container") if item.attributes["name"] == "web" and "pod" in item.target)
    assert any(item["target"] == secret.target for item in relationships(container, "references"))
    serialized = json.dumps(result.to_dict())
    for value in ("FIXTURE_CA_BYTES", "FIXTURE_LITERAL_ENV", "FIXTURE_ANNOTATION_SECRET", "FIXTURE_BASE64_SECRET",
                  "FIXTURE_SECRET_STRING", "FIXTURE_CONFIG_PAYLOAD", "FIXTURE_BINARY_PAYLOAD", "FIXTURE_ROUTE_KEY", "FIXTURE_ROUTE_CERT"):
        assert value not in serialized
    assert secret.attributes["raw"]["data_keys"] == ["password"]
    assert "data" not in secret.attributes["raw"]


def test_kubeconfig_contexts_multiple_clusters_and_credentials_omitted():
    document = {"kind": "Config", "current-context": "prod-context", "clusters": [
        {"name": "dev", "cluster": {"server": "https://dev.test", "certificate-authority-data": "FIXTURE_CA"}},
        {"name": "prod", "cluster": {"server": "https://prod.test"}},
    ], "contexts": [{"name": "prod-context", "context": {"cluster": "prod", "user": "operator"}}],
        "users": [{"name": "operator", "user": {"token": "FIXTURE_TOKEN", "exec": {"command": "never-run"}}}]}
    result = import_kubernetes_inventory(document)
    assert result.status == "ok"
    assert {item.target for item in of_type(result, "cluster")} == {"k8s:/dev/cluster//dev", "k8s:/prod/cluster//prod"}
    assert relationships(named(result, "context", "prod-context"), "references")[0]["target"] == "k8s:/prod/cluster//prod"
    assert "FIXTURE_TOKEN" not in json.dumps(result.to_dict())
    assert "never-run" not in json.dumps(result.to_dict())


@pytest.mark.parametrize("kind", ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job"])
def test_single_kubectl_and_typed_list_json(kind):
    spec = {"containers": [{"name": "main", "image": "example:v1"}]}
    if kind != "Pod":
        spec = {"template": {"spec": spec}}
    record = {"kind": kind, "metadata": {"name": "example"}, "spec": spec}
    single = import_kubernetes_inventory(record, cluster="fixture")
    listed = import_kubernetes_inventory({"kind": kind + "List", "items": [record]}, cluster="fixture")
    assert single.status == listed.status == "ok"
    assert named(single, kind.lower(), "example").target == named(listed, kind.lower(), "example").target
    assert named(single, kind.lower(), "example").attributes["namespace"] == "default"


def test_missing_inventories_reference_stubs_and_selector_namespace_boundaries():
    document = {"kind": "List", "items": [
        {"kind": "Pod", "metadata": {"name": "a", "namespace": "one", "labels": {"app": "x"}}, "spec": {"nodeName": "missing"}},
        {"kind": "Pod", "metadata": {"name": "b", "namespace": "two", "labels": {"app": "x"}}},
        {"kind": "Service", "metadata": {"name": "a", "namespace": "one"}, "spec": {"selector": {"app": "x"}}},
        {"kind": "Service", "metadata": {"name": "manual", "namespace": "one"}, "spec": {}},
    ]}
    result = import_kubernetes_inventory(document)
    assert result.status == "partial"
    assert named(result, "node", "missing").attributes["reference_only"] is True
    assert relationships(named(result, "service", "a"), "routes_to")[0]["target"] == named(result, "pod", "a").target
    assert not relationships(named(result, "service", "manual"), "routes_to")


@pytest.mark.parametrize("operator,values,expected", [
    ("In", ["frontend"], True), ("NotIn", ["frontend"], False),
    ("Exists", [], True), ("DoesNotExist", [], False), ("Bad", [], False),
])
def test_network_policy_expression_semantics(operator, values, expected):
    document = fixture("kubernetes.json")
    document["networkpolicies"][0]["spec"]["podSelector"] = {"matchExpressions": [{"key": "tier", "operator": operator, "values": values}]}
    result = import_kubernetes_inventory(document, cluster="dev")
    assert bool(relationships(named(result, "networkpolicy", "web-ingress"), "applies_to")) is expected
    assert result.status == ("partial" if operator == "Bad" else "ok")


def test_docker_inventory_images_networks_mounts_and_published_ports():
    document = fixture("docker.json")
    result = import_docker_inventory(document, runtime="host-a")
    assert result.status == "ok"
    assert len(of_type(result, "image")) == len(of_type(result, "container")) == len(of_type(result, "network")) == 1
    container = of_type(result, "container")[0]
    image = of_type(result, "image")[0]
    network = of_type(result, "network")[0]
    assert relationships(container, "uses_image")[0]["target"] == image.target
    assert image.attributes["tags"] == ["example.test/web:v1"]
    assert relationships(container, "member_of")[0]["target"] == network.target
    assert len(of_type(result, "mount")) == 2
    assert next(item for item in of_type(result, "mount") if item.attributes["destination"] == "/app").attributes["read_only"] is True
    ports = of_type(result, "port")
    assert {(item.port, item.protocol) for item in ports if "/published/" not in item.target} == {(53, "tcp"), (53, "udp"), (80, "tcp")}
    public = [item for item in ports if relationships(item, "exposed_to")]
    assert {(item.port, item.protocol, item.attributes["host"]) for item in public} == {(1053, "tcp", "0.0.0.0"), (1053, "udp", "127.0.0.1")}
    assert all(relationships(item, "routes_to") for item in public)
    assert "FIXTURE_ENV_SECRET" not in json.dumps(result.to_dict())


def test_podman_ports_and_docker_engine_ports_and_json_lines():
    record = {"Id": "podman-container", "Image": "image:v1", "Names": ["worker"],
              "Ports": [{"container_port": 53, "host_port": 1053, "host_ip": "::1", "protocol": "udp"}]}
    result = import_podman_inventory([record], runtime="host-a")
    assert result.status == "ok"
    assert {(item.port, item.protocol) for item in of_type(result, "port")} == {(53, "udp"), (1053, "udp")}
    record["Ports"] = [{"PrivatePort": 80, "PublicPort": 8080, "IP": "0.0.0.0", "Type": "tcp"}]
    docker = import_docker_inventory(json.dumps(record) + "\n" + json.dumps({**record, "Id": "second"}), runtime="host-a")
    assert docker.status == "ok"
    assert len(of_type(docker, "container")) == 2
    assert len([item for item in of_type(docker, "port") if item.port == 8080]) == 2


def test_crictl_inventory_and_inspect_status():
    result = import_crictl_inventory(fixture("crictl.json"), runtime="cri-host")
    assert result.status == "ok"
    assert len(of_type(result, "image")) == 1
    assert relationships(of_type(result, "container")[0], "uses_image")[0]["target"] == of_type(result, "image")[0].target
    assert of_type(result, "mount")[0].attributes["read_only"] is True
    record = fixture("crictl.json")["containers"][0]
    inspected = import_crictl_inventory({"status": record, "info": {"pid": 456}}, runtime="cri-host")
    assert inspected.status == "ok"
    assert of_type(inspected, "container")[0].attributes["raw"]["pid"] == 456
    inspected_image = import_crictl_inventory({"status": fixture("crictl.json")["images"][0]}, runtime="cri-host")
    assert inspected_image.status == "ok"
    assert len(of_type(inspected_image, "image")) == 1
    assert not of_type(inspected_image, "container")


def test_trivy_packages_vulnerability_metadata_and_graph_relationships():
    result = import_trivy_json(fixture("trivy.json"), source="trivy-fixture", run_id="scan-1")
    assert result.status == "ok"
    assert len(of_type(result, "package")) == 3
    assert len(of_type(result, "finding")) == 2
    finding = named(result, "finding", "Fixture vulnerability")
    assert finding.kind == "finding"
    assert finding.attributes["severity"] == "critical"
    assert finding.attributes["original_severity"] == "CRITICAL"
    assert finding.attributes["cve_ids"] == ["CVE-2026-12345"]
    assert finding.attributes["fixed_versions"] == ["3.0.1", "3.1.0"]
    assert finding.attributes["cvss"] == {"nvd": {"V3Score": 9.8}}
    package = named(result, "package", "openssl")
    assert relationships(finding, "has_vulnerability")[0]["target"] == package.target
    assert relationships(finding, "has_vulnerability")[0]["direction"] == "in"
    assert package.attributes["version"] == "3.0.0"
    assert all(item.attributes["source_schema"] == "trivy/2" for item in result.observations)


def test_grype_aliases_keep_primary_scanner_severity_and_fix_state():
    result = import_grype_json(fixture("grype.json"))
    assert result.status == "ok"
    assert len(of_type(result, "package")) == len(of_type(result, "finding")) == 2
    finding = named(result, "finding", "GHSA-fixture-test")
    assert finding.attributes["cve_ids"] == ["CVE-2026-12345"]
    assert finding.attributes["severity"] == "high"
    assert finding.attributes["fix_state"] == "fixed"
    assert finding.attributes["fixed_versions"] == ["3.0.1"]
    assert finding.attributes["purl"] == "pkg:deb/debian/openssl@3.0.0"
    assert named(result, "finding", "CVE-2026-54321").attributes["severity"] == "info"


def test_duplicate_scanner_verdicts_merge_evidence_severity_aliases_and_fix_versions():
    document = fixture("grype.json")
    duplicate = deepcopy(document["matches"][0])
    duplicate["vulnerability"]["severity"] = "Critical"
    duplicate["vulnerability"]["fix"]["versions"] = ["3.0.2"]
    duplicate["relatedVulnerabilities"] = [{"id": "CVE-2026-99999"}]
    document["matches"].append(duplicate)
    first = import_grype_json(document)
    document["matches"].reverse()
    second = import_grype_json(document)
    assert first.to_dict() == second.to_dict()
    finding = named(first, "finding", "GHSA-fixture-test")
    assert finding.attributes["severity"] == "critical"
    assert finding.attributes["fixed_versions"] == ["3.0.1", "3.0.2"]
    assert finding.attributes["cves"] == ["CVE-2026-12345", "CVE-2026-99999"]
    assert len(finding.attributes["source_records"]) == 2


def test_trivy_secret_results_never_retained():
    document = fixture("trivy.json")
    document["Results"][0]["Secrets"] = [{"RuleID": "generic", "Match": "FIXTURE_MATCH_SECRET",
                                            "Code": {"Lines": [{"Content": "FIXTURE_LINE_SECRET"}]}}]
    result = import_trivy_json(document)
    assert result.status == "partial"
    assert all("FIXTURE_" not in json.dumps(item.attributes["raw"]) for item in result.observations)
    assert any("Secrets" in item["message"] for item in result.diagnostics)


@pytest.mark.parametrize("importer,filename,kwargs", [
    (import_kubernetes_inventory, "kubernetes.json", {"cluster": "dev"}),
    (import_docker_inventory, "docker.json", {"runtime": "host"}),
    (import_crictl_inventory, "crictl.json", {"runtime": "host"}),
    (import_trivy_json, "trivy.json", {}), (import_grype_json, "grype.json", {}),
])
def test_determinism_provenance_path_inputs_merge_and_scope(importer, filename, kwargs):
    document = fixture(filename)
    first = importer(document, source=filename, run_id="run-1", **kwargs)
    second = importer(dict(reversed(list(document.items()))), source=filename, run_id="run-1", **kwargs)
    assert first.to_dict() == second.to_dict()
    assert first.schema_version == CONTAINER_SCHEMA_VERSION
    assert all(item.observed_at is None for item in first.observations)
    assert all(item.attributes["provider"] == first.provider and item.attributes["source"] == filename
               and item.attributes["run_id"] == "run-1" and item.attributes["import_id"] == first.import_id
               and item.attributes["source_id"] and item.attributes["source_schema"]
               and item.attributes["raw_redacted"] is True for item in first.observations)
    assert importer(json.dumps(document).encode(), source=filename, run_id="run-1", **kwargs).to_dict() == first.to_dict()
    assert importer(FIXTURES / filename, source=filename, run_id="run-1", **kwargs).to_dict() == first.to_dict()
    observations = []
    assert first.merge_into(observations) == len(first.observations)
    assert second.merge_into(observations) == 0
    assert importer(document, source=filename, run_id="run-2", **kwargs).import_id != first.import_id
    assert importer(document, source="different", run_id="run-1", **kwargs).import_id != first.import_id
    assert importer(document, import_id="explicit-import", **kwargs).import_id == "explicit-import"


def test_inventory_order_is_independent_and_duplicate_resources_merge():
    document = fixture("kubernetes.json")
    first = import_kubernetes_inventory(document, cluster="dev")
    for value in document.values():
        if isinstance(value, list):
            value.reverse()
    second = import_kubernetes_inventory(document, cluster="dev")
    assert first.to_dict() == second.to_dict()
    pod = deepcopy(document["pods"]["items"][0])
    document["pods"]["items"].append(pod)
    duplicate = import_kubernetes_inventory(document, cluster="dev", import_id=first.import_id)
    assert [item.target for item in duplicate.observations] == [item.target for item in first.observations]
    assert len(named(duplicate, "serviceaccount", "web").attributes["relationships"]) == len(named(first, "serviceaccount", "web").attributes["relationships"])


@pytest.mark.parametrize("importer", [import_kubernetes_inventory, import_docker_inventory, import_trivy_json, import_grype_json])
@pytest.mark.parametrize("document", [None, 42, "not-json", b"\xff", '{"x":1,"x":2}', {"x": float("nan")}, {4: "bad"}, {"x": object()}])
def test_malformed_json_is_rejected_with_diagnostics(importer, document):
    result = importer(document)
    assert result.status == "invalid"
    assert result.observations == []
    assert result.diagnostics
    json.dumps(result.to_dict(), allow_nan=False)


@pytest.mark.parametrize("document", [
    {"kind": []}, {"kind": "Pod", "metadata": []}, {"pods": "unsafe"},
    {"kind": "Pod", "metadata": {"name": "x"}, "spec": {"containers": [7]}},
    {"kind": "RoleBinding", "metadata": {"name": "x"}, "roleRef": {"kind": [], "name": "x"}},
    {"kind": "Service", "metadata": {"name": "x"}, "spec": {"ports": [{"port": True}, {"port": 65536}, {"port": "not-a-port"}, {"port": 80, "protocol": "bad"}]}},
    {"kind": "ClusterRoleBinding", "metadata": {"name": "x"}, "roleRef": {"kind": "Role", "name": "bad"}, "subjects": [{"kind": "ServiceAccount", "name": "missing-ns"}]},
])
def test_kubernetes_partial_or_unsafe_shapes_are_diagnosed(document):
    result = import_kubernetes_inventory(document, cluster="fixture")
    assert result.status in {"invalid", "partial"}
    assert result.diagnostics
    assert all(item.port is None or 1 <= item.port <= 65535 for item in result.observations)


@pytest.mark.parametrize("importer,document", [
    (import_trivy_json, {"Results": "bad"}),
    (import_trivy_json, {"Results": [None, {"Vulnerabilities": [{"PkgName": {}, "InstalledVersion": []}]}]}),
    (import_grype_json, {"matches": [{"artifact": [], "vulnerability": {"severity": "urgent"}}]}),
    (import_grype_json, {"matches": [7, {"artifact": {"name": "x", "version": {}}, "vulnerability": {"id": []}}]}),
    (import_docker_inventory, {"containers": [{"Id": [], "Image": "x"}, "bad"]}),
])
def test_partial_scanner_and_runtime_shapes_do_not_crash(importer, document):
    result = importer(document)
    assert result.status in {"invalid", "partial"}
    assert result.diagnostics
    json.dumps(result.to_dict())


def test_unknown_scanner_severity_missing_ids_and_empty_scan_results():
    result = import_grype_json({"matches": [{"artifact": {"name": "x", "version": "1"},
                                            "vulnerability": {"id": "TEST-1", "severity": "future"}}]})
    assert of_type(result, "finding")[0].attributes["severity"] == "unknown"
    assert of_type(result, "finding")[0].attributes["original_severity"] == "future"
    assert import_trivy_json({"Results": [], "ArtifactName": "empty-fixture"}).status == "ok"
    assert import_grype_json({"matches": [], "source": {"type": "directory", "target": "fixture"}}).status == "ok"
    unknown = import_trivy_json({"Results": []})
    assert unknown.status == "partial"
    assert "unknown-artifact" in of_type(unknown, "image")[0].target
    assert import_trivy_json({"unsupported": []}).status == "invalid"


def test_image_references_correlate_kubernetes_runtime_and_scanner_evidence():
    graph = AttackGraph()
    kube = import_kubernetes_inventory(fixture("kubernetes.json"), cluster="dev")
    runtime = import_docker_inventory(fixture("docker.json"), runtime="host")
    scanner = import_trivy_json(fixture("trivy.json"))
    for result in (kube, runtime, scanner):
        result.populate_graph(graph)
    image_id = of_type(runtime, "image")[0].target
    assert image_id == of_type(scanner, "image")[0].target
    runtime_image = graph.get_node_by_identifier(NodeType.RESOURCE, image_id)
    assert len(runtime_image.metadata["source_execution_ids"]) == 2
    image_ref = named(kube, "image", "example.test/web:v1").target
    alias_node = graph.get_node_by_identifier(NodeType.RESOURCE, image_ref)
    assert any(edge.source_id == alias_node.id and edge.target_id == runtime_image.id
               and edge.edge_type == EdgeType.IDENTIFIES for edge in graph.edges.values())


@pytest.mark.parametrize("importer,filename,kwargs", [
    (import_kubernetes_inventory, "kubernetes.json", {"cluster": "dev"}),
    (import_docker_inventory, "docker.json", {"runtime": "host"}),
    (import_trivy_json, "trivy.json", {}), (import_grype_json, "grype.json", {}),
])
def test_graph_population_is_idempotent_and_retains_edges(importer, filename, kwargs):
    result = importer(fixture(filename), **kwargs)
    graph = AttackGraph()
    assert result.populate_graph(graph) == len(result.observations)
    first = len(graph.nodes), len(graph.edges)
    assert first[0] and first[1]
    result.populate_graph(graph)
    graph.ingest_observations([item.to_dict() for item in result.observations])
    assert (len(graph.nodes), len(graph.edges)) == first
    assert all(node.metadata.get("source_observation_ids") for node in graph.nodes.values())
    if filename in {"trivy.json", "grype.json"}:
        assert len([node for node in graph.nodes.values() if node.node_type == NodeType.VULNERABILITY]) == 2
        assert any(edge.edge_type == EdgeType.HAS_VULNERABILITY for edge in graph.edges.values())
    if filename == "kubernetes.json":
        assert any(edge.edge_type == EdgeType.RUNS_ON for edge in graph.edges.values())
        assert any(edge.edge_type == EdgeType.ROUTES_TO for edge in graph.edges.values())
        assert any(edge.edge_type == EdgeType.HAS_PERMISSION for edge in graph.edges.values())
        owner = named(result, "service", "web").target
        services = [node for node in graph.nodes.values() if node.node_type == NodeType.SERVICE and node.properties.get("resource_owner") == owner]
        assert {node.properties["protocol"] for node in services} == {"tcp", "udp"}
        assert graph.get_node_by_identifier(NodeType.HOST, owner) is None


def test_importers_are_offline_and_never_run_commands_or_read_references(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Live collectors, network and referenced-file access are forbidden")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    document = fixture("kubernetes.json")
    document["clusters"][0]["cluster"]["certificate-authority"] = "/never/read/me"
    document["contexts"][0]["context"]["user"] = "exec-user"
    monkeypatch.setattr(Path, "read_text", forbidden)
    assert import_kubernetes_inventory(document, cluster="dev").status == "ok"
    assert import_container_inventory({"containers": [{"Id": "c", "Image": "never-pull"}]}, runtime="host").status == "ok"
