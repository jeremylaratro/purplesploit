"""
Attack Graph Visualization Module.

Provides live visualization of attack paths, showing relationships between
hosts, services, credentials, and vulnerabilities in a penetration test.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
from datetime import datetime
import json
import hashlib


class NodeType(Enum):
    """Types of nodes in the attack graph."""
    HOST = "host"
    SERVICE = "service"
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"
    SHARE = "share"
    USER = "user"
    GROUP = "group"
    DOMAIN = "domain"
    SESSION = "session"


class EdgeType(Enum):
    """Types of edges connecting nodes."""
    HAS_SERVICE = "has_service"          # Host → Service
    HAS_VULNERABILITY = "has_vulnerability"  # Service → Vulnerability
    EXPLOITED_BY = "exploited_by"        # Vulnerability → Credential
    AUTHENTICATES_TO = "authenticates_to"  # Credential → Host/Service
    MEMBER_OF = "member_of"              # User → Group
    HAS_ACCESS = "has_access"            # Credential → Share
    LATERAL_MOVE = "lateral_move"        # Host → Host
    CONTAINS = "contains"                # Domain → Host/User
    PIVOTS_TO = "pivots_to"              # Session → Host
    DISCOVERED_VIA = "discovered_via"    # Node → Node (discovery path)


class NodeStatus(Enum):
    """Status of nodes in the graph."""
    DISCOVERED = "discovered"
    SCANNED = "scanned"
    COMPROMISED = "compromised"
    PIVOT = "pivot"
    TARGET = "target"
    DOMAIN_ADMIN = "domain_admin"


@dataclass
class GraphNode:
    """A node in the attack graph."""
    id: str
    node_type: NodeType
    label: str
    status: NodeStatus = NodeStatus.DISCOVERED
    properties: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.node_type.value,
            "label": self.label,
            "status": self.status.value,
            "properties": self.properties,
            "metadata": self.metadata,
            "discovered_at": self.discovered_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GraphNode":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            node_type=NodeType(data["type"]),
            label=data["label"],
            status=NodeStatus(data.get("status", "discovered")),
            properties=data.get("properties", {}),
            metadata=data.get("metadata", {}),
            discovered_at=datetime.fromisoformat(data["discovered_at"]) if "discovered_at" in data else datetime.now(),
        )


@dataclass
class GraphEdge:
    """An edge connecting nodes in the attack graph."""
    id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""
    weight: float = 1.0
    properties: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "label": self.label,
            "weight": self.weight,
            "properties": self.properties,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GraphEdge":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            source_id=data["source"],
            target_id=data["target"],
            edge_type=EdgeType(data["type"]),
            label=data.get("label", ""),
            weight=data.get("weight", 1.0),
            properties=data.get("properties", {}),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
        )


@dataclass
class AttackPath:
    """Represents a complete attack path through the graph."""
    id: str
    nodes: list[str] = field(default_factory=list)
    edges: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    description: str = ""
    techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "nodes": self.nodes,
            "edges": self.edges,
            "risk_score": self.risk_score,
            "description": self.description,
            "techniques": self.techniques,
        }


class AttackGraph:
    """
    Live attack graph for visualizing penetration test progress.

    Maintains a graph of hosts, services, credentials, and vulnerabilities,
    tracking how they relate and showing potential attack paths.
    """

    def __init__(self):
        """Initialize empty attack graph."""
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        self.attack_paths: list[AttackPath] = []

        # Indexes for fast lookups
        self._nodes_by_type: dict[NodeType, set[str]] = {t: set() for t in NodeType}
        self._edges_by_source: dict[str, set[str]] = {}
        self._edges_by_target: dict[str, set[str]] = {}
        self._edges_by_type: dict[EdgeType, set[str]] = {t: set() for t in EdgeType}

        # Callbacks for live updates
        self.on_node_added: Callable[[GraphNode], None] | None = None
        self.on_edge_added: Callable[[GraphEdge], None] | None = None
        self.on_node_updated: Callable[[GraphNode], None] | None = None
        self.on_path_found: Callable[[AttackPath], None] | None = None

        # Track changes for undo/redo
        self._history: list[dict] = []
        self._history_index: int = -1

    def _generate_node_id(self, node_type: NodeType, identifier: str) -> str:
        """Generate a unique node ID."""
        return f"{node_type.value}:{hashlib.md5(identifier.encode()).hexdigest()[:12]}"

    def _generate_edge_id(self, source_id: str, target_id: str, edge_type: EdgeType) -> str:
        """Generate a unique edge ID."""
        combined = f"{source_id}-{edge_type.value}-{target_id}"
        return f"edge:{hashlib.md5(combined.encode()).hexdigest()[:12]}"

    def add_node(
        self,
        node_type: NodeType,
        label: str,
        identifier: str | None = None,
        status: NodeStatus = NodeStatus.DISCOVERED,
        properties: dict | None = None,
        metadata: dict | None = None,
    ) -> GraphNode:
        """
        Add a node to the graph.

        Args:
            node_type: Type of node (HOST, SERVICE, etc.)
            label: Display label for the node
            identifier: Unique identifier (defaults to label)
            status: Node status
            properties: Additional properties
            metadata: Metadata about discovery

        Returns:
            The created or existing node
        """
        identifier = identifier or label
        node_id = self._generate_node_id(node_type, identifier)

        if node_id in self.nodes:
            # Update existing node if needed
            existing = self.nodes[node_id]
            if properties:
                existing.properties.update(properties)
            if metadata:
                existing.metadata.update(metadata)
            if status.value > existing.status.value:  # Upgrade status
                existing.status = status
            if self.on_node_updated:
                self.on_node_updated(existing)
            return existing

        node = GraphNode(
            id=node_id,
            node_type=node_type,
            label=label,
            status=status,
            properties=properties or {},
            metadata=metadata or {},
        )

        self.nodes[node_id] = node
        self._nodes_by_type[node_type].add(node_id)

        if self.on_node_added:
            self.on_node_added(node)

        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        label: str = "",
        weight: float = 1.0,
        properties: dict | None = None,
    ) -> GraphEdge | None:
        """
        Add an edge between nodes.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: Type of relationship
            label: Display label
            weight: Edge weight (for path calculations)
            properties: Additional properties

        Returns:
            The created edge, or None if nodes don't exist
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        edge_id = self._generate_edge_id(source_id, target_id, edge_type)

        if edge_id in self.edges:
            return self.edges[edge_id]

        edge = GraphEdge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            label=label,
            weight=weight,
            properties=properties or {},
        )

        self.edges[edge_id] = edge

        # Update indexes
        if source_id not in self._edges_by_source:
            self._edges_by_source[source_id] = set()
        self._edges_by_source[source_id].add(edge_id)

        if target_id not in self._edges_by_target:
            self._edges_by_target[target_id] = set()
        self._edges_by_target[target_id].add(edge_id)

        self._edges_by_type[edge_type].add(edge_id)

        if self.on_edge_added:
            self.on_edge_added(edge)

        return edge

    def add_host(
        self,
        ip: str,
        hostname: str | None = None,
        os: str | None = None,
        status: NodeStatus = NodeStatus.DISCOVERED,
    ) -> GraphNode:
        """Convenience method to add a host node."""
        label = hostname or ip
        props = {"ip": ip}
        if hostname:
            props["hostname"] = hostname
        if os:
            props["os"] = os

        return self.add_node(
            node_type=NodeType.HOST,
            label=label,
            identifier=ip,
            status=status,
            properties=props,
        )

    def add_service(
        self,
        host_ip: str,
        port: int,
        service: str,
        version: str | None = None,
    ) -> GraphNode:
        """Convenience method to add a service and link to host."""
        host = self.get_node_by_identifier(NodeType.HOST, host_ip)
        if not host:
            host = self.add_host(host_ip)

        identifier = f"{host_ip}:{port}"
        label = f"{service}:{port}"

        props = {"port": port, "service": service}
        if version:
            props["version"] = version

        service_node = self.add_node(
            node_type=NodeType.SERVICE,
            label=label,
            identifier=identifier,
            properties=props,
        )

        self.add_edge(host.id, service_node.id, EdgeType.HAS_SERVICE)

        return service_node

    def add_credential(
        self,
        username: str,
        password: str | None = None,
        hash_value: str | None = None,
        domain: str | None = None,
        cred_type: str = "password",
    ) -> GraphNode:
        """Convenience method to add a credential node."""
        identifier = f"{domain}\\{username}" if domain else username
        label = identifier

        props = {
            "username": username,
            "type": cred_type,
        }
        if password:
            props["has_password"] = True
        if hash_value:
            props["has_hash"] = True
        if domain:
            props["domain"] = domain

        return self.add_node(
            node_type=NodeType.CREDENTIAL,
            label=label,
            identifier=identifier,
            properties=props,
        )

    def add_vulnerability(
        self,
        service_id: str,
        name: str,
        severity: str = "medium",
        cve: str | None = None,
        description: str | None = None,
    ) -> GraphNode:
        """Convenience method to add a vulnerability linked to a service."""
        identifier = f"{service_id}:{name}"

        props = {
            "name": name,
            "severity": severity,
        }
        if cve:
            props["cve"] = cve
        if description:
            props["description"] = description

        vuln = self.add_node(
            node_type=NodeType.VULNERABILITY,
            label=name,
            identifier=identifier,
            properties=props,
        )

        self.add_edge(service_id, vuln.id, EdgeType.HAS_VULNERABILITY)

        return vuln

    def link_credential_to_host(
        self,
        credential_id: str,
        host_id: str,
        service: str | None = None,
    ) -> GraphEdge | None:
        """Link a credential to a host it can authenticate to."""
        props = {}
        if service:
            props["service"] = service

        return self.add_edge(
            credential_id,
            host_id,
            EdgeType.AUTHENTICATES_TO,
            properties=props,
        )

    def mark_compromised(self, node_id: str) -> bool:
        """Mark a node as compromised."""
        if node_id in self.nodes:
            self.nodes[node_id].status = NodeStatus.COMPROMISED
            if self.on_node_updated:
                self.on_node_updated(self.nodes[node_id])
            return True
        return False

    def get_node_by_identifier(self, node_type: NodeType, identifier: str) -> GraphNode | None:
        """Get a node by its type and identifier."""
        node_id = self._generate_node_id(node_type, identifier)
        return self.nodes.get(node_id)

    def get_nodes_by_type(self, node_type: NodeType) -> list[GraphNode]:
        """Get all nodes of a specific type."""
        return [self.nodes[nid] for nid in self._nodes_by_type[node_type]]

    def get_edges_from(self, node_id: str) -> list[GraphEdge]:
        """Get all edges originating from a node."""
        edge_ids = self._edges_by_source.get(node_id, set())
        return [self.edges[eid] for eid in edge_ids]

    def get_edges_to(self, node_id: str) -> list[GraphEdge]:
        """Get all edges pointing to a node."""
        edge_ids = self._edges_by_target.get(node_id, set())
        return [self.edges[eid] for eid in edge_ids]

    def get_neighbors(self, node_id: str) -> list[GraphNode]:
        """Get all nodes connected to a given node."""
        neighbors = set()

        for edge in self.get_edges_from(node_id):
            neighbors.add(edge.target_id)
        for edge in self.get_edges_to(node_id):
            neighbors.add(edge.source_id)

        return [self.nodes[nid] for nid in neighbors if nid in self.nodes]

    def find_attack_paths(
        self,
        start_node_id: str,
        target_node_id: str,
        max_depth: int = 10,
    ) -> list[AttackPath]:
        """
        Find all attack paths between two nodes.

        Uses DFS to find all paths, tracking edges used.
        """
        paths = []

        def dfs(current: str, target: str, visited: set, path_nodes: list, path_edges: list, depth: int):
            if depth > max_depth:
                return

            if current == target:
                path_id = f"path:{hashlib.md5(':'.join(path_nodes).encode()).hexdigest()[:12]}"
                paths.append(AttackPath(
                    id=path_id,
                    nodes=path_nodes.copy(),
                    edges=path_edges.copy(),
                    risk_score=self._calculate_path_risk(path_nodes),
                ))
                return

            for edge in self.get_edges_from(current):
                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    path_nodes.append(edge.target_id)
                    path_edges.append(edge.id)

                    dfs(edge.target_id, target, visited, path_nodes, path_edges, depth + 1)

                    path_nodes.pop()
                    path_edges.pop()
                    visited.remove(edge.target_id)

        visited = {start_node_id}
        dfs(start_node_id, target_node_id, visited, [start_node_id], [], 0)

        # Sort by risk score (highest first)
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        return paths

    def _calculate_path_risk(self, node_ids: list[str]) -> float:
        """Calculate risk score for a path."""
        score = 0.0

        for node_id in node_ids:
            node = self.nodes.get(node_id)
            if not node:
                continue

            # Higher score for certain node types
            if node.node_type == NodeType.VULNERABILITY:
                severity = node.properties.get("severity", "medium").lower()
                severity_scores = {"critical": 10, "high": 7, "medium": 4, "low": 1}
                score += severity_scores.get(severity, 4)
            elif node.node_type == NodeType.CREDENTIAL:
                score += 5
            elif node.node_type == NodeType.HOST:
                if node.status == NodeStatus.COMPROMISED:
                    score += 3

        return score

    def find_lateral_paths(self, start_host_id: str) -> list[AttackPath]:
        """Find all possible lateral movement paths from a compromised host."""
        paths = []

        # Get credentials that can authenticate from this host
        for edge in self.get_edges_to(start_host_id):
            if edge.edge_type == EdgeType.AUTHENTICATES_TO:
                cred_node = self.nodes.get(edge.source_id)
                if not cred_node:
                    continue

                # Find other hosts this credential can access
                for cred_edge in self.get_edges_from(cred_node.id):
                    if cred_edge.edge_type == EdgeType.AUTHENTICATES_TO:
                        target_host = cred_edge.target_id
                        if target_host != start_host_id:
                            path_id = f"lateral:{start_host_id}-{target_host}"
                            paths.append(AttackPath(
                                id=path_id,
                                nodes=[start_host_id, cred_node.id, target_host],
                                edges=[edge.id, cred_edge.id],
                                risk_score=5.0,
                                description=f"Lateral move via {cred_node.label}",
                            ))

        return paths

    def get_statistics(self) -> dict:
        """Get graph statistics."""
        compromised_hosts = sum(
            1 for nid in self._nodes_by_type[NodeType.HOST]
            if self.nodes[nid].status == NodeStatus.COMPROMISED
        )

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "hosts": len(self._nodes_by_type[NodeType.HOST]),
            "services": len(self._nodes_by_type[NodeType.SERVICE]),
            "credentials": len(self._nodes_by_type[NodeType.CREDENTIAL]),
            "vulnerabilities": len(self._nodes_by_type[NodeType.VULNERABILITY]),
            "compromised_hosts": compromised_hosts,
            "attack_paths": len(self.attack_paths),
        }

    def to_dict(self) -> dict:
        """Export graph to dictionary."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "statistics": self.get_statistics(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackGraph":
        """Import graph from dictionary."""
        graph = cls()

        for node_data in data.get("nodes", []):
            node = GraphNode.from_dict(node_data)
            graph.nodes[node.id] = node
            graph._nodes_by_type[node.node_type].add(node.id)

        for edge_data in data.get("edges", []):
            edge = GraphEdge.from_dict(edge_data)
            graph.edges[edge.id] = edge

            if edge.source_id not in graph._edges_by_source:
                graph._edges_by_source[edge.source_id] = set()
            graph._edges_by_source[edge.source_id].add(edge.id)

            if edge.target_id not in graph._edges_by_target:
                graph._edges_by_target[edge.target_id] = set()
            graph._edges_by_target[edge.target_id].add(edge.id)

            graph._edges_by_type[edge.edge_type].add(edge.id)

        return graph

    def to_json(self, indent: int | None = 2) -> str:
        """Export graph to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_json(cls, json_str: str) -> "AttackGraph":
        """Import graph from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def to_cytoscape(self) -> dict:
        """
        Export graph in Cytoscape.js format for web visualization.

        Returns a dict with 'nodes' and 'edges' arrays in Cytoscape format.
        """
        cyto_nodes = []
        cyto_edges = []

        # Color mapping for node types
        type_colors = {
            NodeType.HOST: "#4A90D9",
            NodeType.SERVICE: "#50C878",
            NodeType.CREDENTIAL: "#FFD700",
            NodeType.VULNERABILITY: "#FF6B6B",
            NodeType.SHARE: "#9B59B6",
            NodeType.USER: "#3498DB",
            NodeType.GROUP: "#1ABC9C",
            NodeType.DOMAIN: "#E74C3C",
            NodeType.SESSION: "#F39C12",
        }

        status_shapes = {
            NodeStatus.DISCOVERED: "ellipse",
            NodeStatus.SCANNED: "ellipse",
            NodeStatus.COMPROMISED: "star",
            NodeStatus.PIVOT: "diamond",
            NodeStatus.TARGET: "triangle",
            NodeStatus.DOMAIN_ADMIN: "hexagon",
        }

        for node in self.nodes.values():
            cyto_nodes.append({
                "data": {
                    "id": node.id,
                    "label": node.label,
                    "type": node.node_type.value,
                    "status": node.status.value,
                    "color": type_colors.get(node.node_type, "#888888"),
                    "shape": status_shapes.get(node.status, "ellipse"),
                    **node.properties,
                },
            })

        for edge in self.edges.values():
            cyto_edges.append({
                "data": {
                    "id": edge.id,
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "label": edge.label or edge.edge_type.value,
                    "type": edge.edge_type.value,
                    "weight": edge.weight,
                },
            })

        return {
            "nodes": cyto_nodes,
            "edges": cyto_edges,
        }

    def to_graphviz(self) -> str:
        """
        Export graph in GraphViz DOT format.

        Returns a DOT string for rendering with graphviz.
        """
        lines = ["digraph AttackGraph {"]
        lines.append("  rankdir=LR;")
        lines.append("  node [fontname=\"Arial\"];")
        lines.append("  edge [fontname=\"Arial\", fontsize=10];")
        lines.append("")

        # Node styles by type
        type_styles = {
            NodeType.HOST: 'shape=box, style=filled, fillcolor="#4A90D9"',
            NodeType.SERVICE: 'shape=ellipse, style=filled, fillcolor="#50C878"',
            NodeType.CREDENTIAL: 'shape=diamond, style=filled, fillcolor="#FFD700"',
            NodeType.VULNERABILITY: 'shape=octagon, style=filled, fillcolor="#FF6B6B"',
            NodeType.SHARE: 'shape=folder, style=filled, fillcolor="#9B59B6"',
            NodeType.USER: 'shape=ellipse, style=filled, fillcolor="#3498DB"',
            NodeType.GROUP: 'shape=ellipse, style=filled, fillcolor="#1ABC9C"',
            NodeType.DOMAIN: 'shape=house, style=filled, fillcolor="#E74C3C"',
            NodeType.SESSION: 'shape=parallelogram, style=filled, fillcolor="#F39C12"',
        }

        # Add nodes
        for node in self.nodes.values():
            style = type_styles.get(node.node_type, "")
            label = node.label.replace('"', '\\"')
            compromised = ', penwidth=3, color=red' if node.status == NodeStatus.COMPROMISED else ''
            lines.append(f'  "{node.id}" [label="{label}", {style}{compromised}];')

        lines.append("")

        # Add edges
        for edge in self.edges.values():
            label = edge.label or edge.edge_type.value.replace("_", " ")
            lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [label="{label}"];')

        lines.append("}")

        return "\n".join(lines)

    def clear(self):
        """Clear the graph."""
        self.nodes.clear()
        self.edges.clear()
        self.attack_paths.clear()

        for type_set in self._nodes_by_type.values():
            type_set.clear()
        self._edges_by_source.clear()
        self._edges_by_target.clear()
        for type_set in self._edges_by_type.values():
            type_set.clear()


def create_attack_graph() -> AttackGraph:
    """Factory function to create a new attack graph."""
    return AttackGraph()
