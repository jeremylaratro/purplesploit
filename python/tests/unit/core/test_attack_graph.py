"""
Tests for purplesploit.core.attack_graph module.
"""

import pytest
from unittest.mock import Mock
from datetime import datetime
import json

from purplesploit.core.attack_graph import (
    AttackGraph,
    GraphNode,
    GraphEdge,
    AttackPath,
    NodeType,
    EdgeType,
    NodeStatus,
    create_attack_graph,
)


class TestNodeType:
    """Tests for NodeType enum."""

    def test_all_types_exist(self):
        """Test all expected node types exist."""
        expected = ["host", "service", "credential", "vulnerability", "share", "user", "group", "domain", "session"]
        for t in expected:
            assert NodeType(t) is not None


class TestEdgeType:
    """Tests for EdgeType enum."""

    def test_all_types_exist(self):
        """Test all expected edge types exist."""
        expected = [
            "has_service", "has_vulnerability", "exploited_by",
            "authenticates_to", "member_of", "has_access",
            "lateral_move", "contains", "pivots_to", "discovered_via"
        ]
        for t in expected:
            assert EdgeType(t) is not None


class TestNodeStatus:
    """Tests for NodeStatus enum."""

    def test_all_statuses_exist(self):
        """Test all expected statuses exist."""
        expected = ["discovered", "scanned", "compromised", "pivot", "target", "domain_admin"]
        for s in expected:
            assert NodeStatus(s) is not None


class TestGraphNode:
    """Tests for GraphNode dataclass."""

    def test_basic_node(self):
        """Test creating a basic node."""
        node = GraphNode(
            id="host:abc123",
            node_type=NodeType.HOST,
            label="192.168.1.1",
        )

        assert node.id == "host:abc123"
        assert node.node_type == NodeType.HOST
        assert node.label == "192.168.1.1"
        assert node.status == NodeStatus.DISCOVERED

    def test_node_with_properties(self):
        """Test node with properties."""
        node = GraphNode(
            id="service:xyz789",
            node_type=NodeType.SERVICE,
            label="HTTP:80",
            properties={"port": 80, "service": "http"},
        )

        assert node.properties["port"] == 80
        assert node.properties["service"] == "http"

    def test_node_to_dict(self):
        """Test converting node to dict."""
        node = GraphNode(
            id="host:test",
            node_type=NodeType.HOST,
            label="test-host",
            status=NodeStatus.COMPROMISED,
            properties={"ip": "10.0.0.1"},
        )

        data = node.to_dict()

        assert data["id"] == "host:test"
        assert data["type"] == "host"
        assert data["status"] == "compromised"
        assert data["properties"]["ip"] == "10.0.0.1"

    def test_node_from_dict(self):
        """Test creating node from dict."""
        data = {
            "id": "cred:admin",
            "type": "credential",
            "label": "admin",
            "status": "discovered",
            "properties": {"username": "admin"},
            "metadata": {},
            "discovered_at": "2024-01-01T12:00:00",
        }

        node = GraphNode.from_dict(data)

        assert node.id == "cred:admin"
        assert node.node_type == NodeType.CREDENTIAL
        assert node.properties["username"] == "admin"


class TestGraphEdge:
    """Tests for GraphEdge dataclass."""

    def test_basic_edge(self):
        """Test creating a basic edge."""
        edge = GraphEdge(
            id="edge:abc",
            source_id="host:1",
            target_id="service:1",
            edge_type=EdgeType.HAS_SERVICE,
        )

        assert edge.source_id == "host:1"
        assert edge.target_id == "service:1"
        assert edge.edge_type == EdgeType.HAS_SERVICE
        assert edge.weight == 1.0

    def test_edge_to_dict(self):
        """Test converting edge to dict."""
        edge = GraphEdge(
            id="edge:test",
            source_id="cred:admin",
            target_id="host:dc01",
            edge_type=EdgeType.AUTHENTICATES_TO,
            label="SMB",
            weight=2.0,
        )

        data = edge.to_dict()

        assert data["source"] == "cred:admin"
        assert data["target"] == "host:dc01"
        assert data["type"] == "authenticates_to"
        assert data["weight"] == 2.0

    def test_edge_from_dict(self):
        """Test creating edge from dict."""
        data = {
            "id": "edge:lat",
            "source": "host:1",
            "target": "host:2",
            "type": "lateral_move",
            "label": "Pass-the-hash",
            "weight": 1.0,
            "properties": {},
            "created_at": "2024-01-01T12:00:00",
        }

        edge = GraphEdge.from_dict(data)

        assert edge.source_id == "host:1"
        assert edge.target_id == "host:2"
        assert edge.edge_type == EdgeType.LATERAL_MOVE


class TestAttackPath:
    """Tests for AttackPath dataclass."""

    def test_path_creation(self):
        """Test creating an attack path."""
        path = AttackPath(
            id="path:1",
            nodes=["host:1", "cred:admin", "host:2"],
            edges=["edge:1", "edge:2"],
            risk_score=7.5,
            description="Lateral movement via admin creds",
        )

        assert len(path.nodes) == 3
        assert len(path.edges) == 2
        assert path.risk_score == 7.5

    def test_path_to_dict(self):
        """Test converting path to dict."""
        path = AttackPath(
            id="path:test",
            nodes=["a", "b"],
            edges=["e1"],
            risk_score=5.0,
            techniques=["T1550"],
        )

        data = path.to_dict()

        assert data["nodes"] == ["a", "b"]
        assert data["techniques"] == ["T1550"]


class TestAttackGraphInit:
    """Tests for AttackGraph initialization."""

    def test_init_empty(self):
        """Test initializing empty graph."""
        graph = AttackGraph()

        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        assert len(graph.attack_paths) == 0

    def test_factory_function(self):
        """Test factory function."""
        graph = create_attack_graph()

        assert isinstance(graph, AttackGraph)


class TestAttackGraphNodes:
    """Tests for node operations."""

    def test_add_node(self):
        """Test adding a node."""
        graph = AttackGraph()

        node = graph.add_node(
            node_type=NodeType.HOST,
            label="192.168.1.1",
            identifier="192.168.1.1",
        )

        assert node.label == "192.168.1.1"
        assert len(graph.nodes) == 1
        assert node.id in graph.nodes

    def test_add_duplicate_node_updates(self):
        """Test adding duplicate node updates existing."""
        graph = AttackGraph()

        node1 = graph.add_node(
            node_type=NodeType.HOST,
            label="host1",
            identifier="10.0.0.1",
            properties={"os": "Linux"},
        )

        node2 = graph.add_node(
            node_type=NodeType.HOST,
            label="host1",
            identifier="10.0.0.1",
            properties={"hostname": "server1"},
        )

        # Should be same node
        assert node1.id == node2.id
        assert len(graph.nodes) == 1
        # Should have both properties
        assert graph.nodes[node1.id].properties["os"] == "Linux"
        assert graph.nodes[node1.id].properties["hostname"] == "server1"

    def test_add_host_convenience(self):
        """Test add_host convenience method."""
        graph = AttackGraph()

        host = graph.add_host(
            ip="192.168.1.100",
            hostname="webserver",
            os="Ubuntu 22.04",
        )

        assert host.node_type == NodeType.HOST
        assert host.properties["ip"] == "192.168.1.100"
        assert host.properties["hostname"] == "webserver"
        assert host.properties["os"] == "Ubuntu 22.04"

    def test_add_service_creates_host_and_edge(self):
        """Test add_service creates host if needed and links."""
        graph = AttackGraph()

        service = graph.add_service(
            host_ip="10.0.0.1",
            port=443,
            service="https",
            version="nginx/1.18",
        )

        # Should have created host and service
        assert len(graph.nodes) == 2
        # Should have edge
        assert len(graph.edges) == 1

        # Verify service properties
        assert service.properties["port"] == 443
        assert service.properties["version"] == "nginx/1.18"

    def test_add_credential(self):
        """Test add_credential method."""
        graph = AttackGraph()

        cred = graph.add_credential(
            username="administrator",
            password="P@ssw0rd",
            domain="CORP",
        )

        assert cred.node_type == NodeType.CREDENTIAL
        assert cred.label == "CORP\\administrator"
        assert cred.properties["has_password"] is True

    def test_add_vulnerability(self):
        """Test add_vulnerability linked to service."""
        graph = AttackGraph()

        service = graph.add_service("10.0.0.1", 80, "http")
        vuln = graph.add_vulnerability(
            service_id=service.id,
            name="CVE-2021-44228",
            severity="critical",
            cve="CVE-2021-44228",
        )

        assert vuln.node_type == NodeType.VULNERABILITY
        assert vuln.properties["severity"] == "critical"
        # Should have edge from service to vuln
        edges = graph.get_edges_from(service.id)
        assert len(edges) == 1
        assert edges[0].edge_type == EdgeType.HAS_VULNERABILITY

    def test_get_nodes_by_type(self):
        """Test getting nodes by type."""
        graph = AttackGraph()

        graph.add_host("10.0.0.1")
        graph.add_host("10.0.0.2")
        graph.add_credential("admin")

        hosts = graph.get_nodes_by_type(NodeType.HOST)
        creds = graph.get_nodes_by_type(NodeType.CREDENTIAL)

        assert len(hosts) == 2
        assert len(creds) == 1


class TestAttackGraphEdges:
    """Tests for edge operations."""

    def test_add_edge(self):
        """Test adding an edge."""
        graph = AttackGraph()

        host = graph.add_host("10.0.0.1")
        cred = graph.add_credential("admin")

        edge = graph.add_edge(
            cred.id,
            host.id,
            EdgeType.AUTHENTICATES_TO,
            label="SMB",
        )

        assert edge is not None
        assert edge.source_id == cred.id
        assert edge.target_id == host.id

    def test_add_edge_missing_node(self):
        """Test adding edge with missing node returns None."""
        graph = AttackGraph()
        host = graph.add_host("10.0.0.1")

        edge = graph.add_edge(
            "nonexistent",
            host.id,
            EdgeType.AUTHENTICATES_TO,
        )

        assert edge is None

    def test_add_duplicate_edge(self):
        """Test adding duplicate edge returns existing."""
        graph = AttackGraph()
        host = graph.add_host("10.0.0.1")
        cred = graph.add_credential("admin")

        edge1 = graph.add_edge(cred.id, host.id, EdgeType.AUTHENTICATES_TO)
        edge2 = graph.add_edge(cred.id, host.id, EdgeType.AUTHENTICATES_TO)

        assert edge1.id == edge2.id
        assert len(graph.edges) == 1

    def test_get_edges_from(self):
        """Test getting outgoing edges."""
        graph = AttackGraph()
        host = graph.add_host("10.0.0.1")
        graph.add_service("10.0.0.1", 80, "http")
        graph.add_service("10.0.0.1", 443, "https")

        edges = graph.get_edges_from(host.id)
        assert len(edges) == 2

    def test_get_edges_to(self):
        """Test getting incoming edges."""
        graph = AttackGraph()
        host = graph.add_host("10.0.0.1")
        cred1 = graph.add_credential("admin")
        cred2 = graph.add_credential("user")

        graph.link_credential_to_host(cred1.id, host.id)
        graph.link_credential_to_host(cred2.id, host.id)

        edges = graph.get_edges_to(host.id)
        assert len(edges) == 2

    def test_get_neighbors(self):
        """Test getting neighboring nodes."""
        graph = AttackGraph()
        host = graph.add_host("10.0.0.1")
        service = graph.add_service("10.0.0.1", 80, "http")
        cred = graph.add_credential("admin")
        graph.link_credential_to_host(cred.id, host.id)

        neighbors = graph.get_neighbors(host.id)
        neighbor_ids = {n.id for n in neighbors}

        assert service.id in neighbor_ids
        assert cred.id in neighbor_ids


class TestAttackGraphStatus:
    """Tests for node status operations."""

    def test_mark_compromised(self):
        """Test marking node as compromised."""
        graph = AttackGraph()
        host = graph.add_host("10.0.0.1")

        assert host.status == NodeStatus.DISCOVERED

        result = graph.mark_compromised(host.id)

        assert result is True
        assert graph.nodes[host.id].status == NodeStatus.COMPROMISED

    def test_mark_compromised_nonexistent(self):
        """Test marking nonexistent node."""
        graph = AttackGraph()

        result = graph.mark_compromised("fake:id")

        assert result is False

    def test_callback_on_node_updated(self):
        """Test callback fired on node update."""
        graph = AttackGraph()
        callback = Mock()
        graph.on_node_updated = callback

        host = graph.add_host("10.0.0.1")
        graph.mark_compromised(host.id)

        callback.assert_called_once()


class TestAttackGraphCallbacks:
    """Tests for callback functionality."""

    def test_on_node_added_callback(self):
        """Test node added callback."""
        graph = AttackGraph()
        callback = Mock()
        graph.on_node_added = callback

        host = graph.add_host("10.0.0.1")

        callback.assert_called_once_with(host)

    def test_on_edge_added_callback(self):
        """Test edge added callback."""
        graph = AttackGraph()
        callback = Mock()
        graph.on_edge_added = callback

        graph.add_service("10.0.0.1", 80, "http")

        # Should be called for the host->service edge
        assert callback.called


class TestAttackGraphPaths:
    """Tests for path finding."""

    def test_find_attack_paths_simple(self):
        """Test finding simple attack paths."""
        graph = AttackGraph()

        host1 = graph.add_host("10.0.0.1")
        service = graph.add_service("10.0.0.1", 445, "smb")
        cred = graph.add_credential("admin")
        host2 = graph.add_host("10.0.0.2")

        # Create path: service -> vuln -> cred -> host2
        vuln = graph.add_vulnerability(service.id, "MS17-010", "critical")
        graph.add_edge(vuln.id, cred.id, EdgeType.EXPLOITED_BY)
        graph.link_credential_to_host(cred.id, host2.id)

        paths = graph.find_attack_paths(service.id, host2.id)

        assert len(paths) >= 1
        # Path should go through vuln and cred
        for path in paths:
            assert cred.id in path.nodes

    def test_find_attack_paths_no_path(self):
        """Test when no path exists."""
        graph = AttackGraph()

        host1 = graph.add_host("10.0.0.1")
        host2 = graph.add_host("10.0.0.2")  # Not connected

        paths = graph.find_attack_paths(host1.id, host2.id)

        assert len(paths) == 0

    def test_find_lateral_paths(self):
        """Test finding lateral movement paths."""
        graph = AttackGraph()

        host1 = graph.add_host("10.0.0.1")
        host2 = graph.add_host("10.0.0.2")
        cred = graph.add_credential("admin")

        # Credential authenticates to both hosts
        graph.link_credential_to_host(cred.id, host1.id)
        graph.link_credential_to_host(cred.id, host2.id)

        paths = graph.find_lateral_paths(host1.id)

        assert len(paths) >= 1
        assert any(host2.id in p.nodes for p in paths)


class TestAttackGraphStatistics:
    """Tests for statistics."""

    def test_get_statistics(self):
        """Test getting graph statistics."""
        graph = AttackGraph()

        graph.add_host("10.0.0.1")
        graph.add_host("10.0.0.2")
        graph.add_service("10.0.0.1", 80, "http")
        graph.add_credential("admin")
        vuln_service = graph.add_service("10.0.0.1", 445, "smb")
        graph.add_vulnerability(vuln_service.id, "MS17-010")

        stats = graph.get_statistics()

        assert stats["hosts"] == 2
        assert stats["services"] == 2
        assert stats["credentials"] == 1
        assert stats["vulnerabilities"] == 1
        assert stats["total_nodes"] == 6  # 2 hosts + 2 services + 1 cred + 1 vuln


class TestAttackGraphExport:
    """Tests for export functionality."""

    def test_to_dict(self):
        """Test exporting to dict."""
        graph = AttackGraph()
        graph.add_host("10.0.0.1")
        graph.add_service("10.0.0.1", 80, "http")

        data = graph.to_dict()

        assert "nodes" in data
        assert "edges" in data
        assert "statistics" in data
        assert len(data["nodes"]) == 2

    def test_from_dict(self):
        """Test importing from dict."""
        graph = AttackGraph()
        graph.add_host("10.0.0.1")
        graph.add_service("10.0.0.1", 80, "http")

        data = graph.to_dict()
        restored = AttackGraph.from_dict(data)

        assert len(restored.nodes) == len(graph.nodes)
        assert len(restored.edges) == len(graph.edges)

    def test_to_json(self):
        """Test exporting to JSON."""
        graph = AttackGraph()
        graph.add_host("10.0.0.1")

        json_str = graph.to_json()
        data = json.loads(json_str)

        assert "nodes" in data
        assert len(data["nodes"]) == 1

    def test_from_json(self):
        """Test importing from JSON."""
        graph = AttackGraph()
        graph.add_host("10.0.0.1")

        json_str = graph.to_json()
        restored = AttackGraph.from_json(json_str)

        assert len(restored.nodes) == 1

    def test_to_cytoscape(self):
        """Test exporting to Cytoscape format."""
        graph = AttackGraph()
        host = graph.add_host("10.0.0.1")
        graph.add_service("10.0.0.1", 80, "http")

        cyto = graph.to_cytoscape()

        assert "nodes" in cyto
        assert "edges" in cyto
        assert len(cyto["nodes"]) == 2
        assert len(cyto["edges"]) == 1

        # Check node format
        node_data = cyto["nodes"][0]["data"]
        assert "id" in node_data
        assert "label" in node_data
        assert "color" in node_data

    def test_to_graphviz(self):
        """Test exporting to GraphViz DOT format."""
        graph = AttackGraph()
        graph.add_host("10.0.0.1")
        graph.add_service("10.0.0.1", 80, "http")

        dot = graph.to_graphviz()

        assert "digraph AttackGraph" in dot
        assert "rankdir=LR" in dot
        assert "->" in dot  # Edge notation


class TestAttackGraphClear:
    """Tests for clear functionality."""

    def test_clear(self):
        """Test clearing the graph."""
        graph = AttackGraph()
        graph.add_host("10.0.0.1")
        graph.add_service("10.0.0.1", 80, "http")
        graph.add_credential("admin")

        assert len(graph.nodes) > 0
        assert len(graph.edges) > 0

        graph.clear()

        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        assert len(graph.attack_paths) == 0
