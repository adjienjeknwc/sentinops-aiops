"""
SentinOps Graph Knowledge Engine
Implements Directed Graph Topology, Neo4j Cypher export/query generation,
Cascading Blast Radius computation, and Graph-based Root Cause Analysis (RCA).
"""
import collections
import heapq
import json
from typing import Dict, List, Set, Tuple, Optional, Any
from .models import TopologyNode, TopologyEdge, NodeType, NodeStatus, EdgeType


class GraphKnowledgeEngine:
    """
    Enterprise-grade Graph Knowledge Engine for Hybrid-Cloud Topology.
    Supports Neo4j Cypher syntax generation, cascading failure propagation,
    and dependency-aware Root Cause Analysis (RCA).
    """

    def __init__(self):
        self.nodes: Dict[str, TopologyNode] = {}
        self.edges: List[TopologyEdge] = []
        # Adjacency lists
        self.adj_out: Dict[str, List[Tuple[str, TopologyEdge]]] = collections.defaultdict(list)
        self.adj_in: Dict[str, List[Tuple[str, TopologyEdge]]] = collections.defaultdict(list)

    def add_node(self, node: TopologyNode) -> None:
        """Register a node in the graph topology."""
        self.nodes[node.id] = node

    def add_edge(self, edge: TopologyEdge) -> None:
        """Register a directed relationship between two nodes."""
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            raise ValueError(f"Source {edge.source_id} or Target {edge.target_id} not registered in graph.")
        self.edges.append(edge)
        self.adj_out[edge.source_id].append((edge.target_id, edge))
        self.adj_in[edge.target_id].append((edge.source_id, edge))

    def get_node(self, node_id: str) -> Optional[TopologyNode]:
        return self.nodes.get(node_id)

    def update_node_status(self, node_id: str, status: NodeStatus) -> None:
        if node_id in self.nodes:
            self.nodes[node_id].status = status

    def get_downstream_dependencies(self, node_id: str, max_depth: int = 5) -> List[str]:
        """
        Find all downstream nodes that depend on this node (impacted if this node fails).
        Traverses outbound edges.
        """
        visited: Set[str] = set()
        queue: collections.deque = collections.deque([(node_id, 0)])
        result: List[str] = []

        while queue:
            curr, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor, _ in self.adj_out.get(curr, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    result.append(neighbor)
                    queue.append((neighbor, depth + 1))
        return result

    def get_upstream_dependencies(self, node_id: str, max_depth: int = 5) -> List[str]:
        """
        Find all upstream infrastructure/services that this node relies on.
        Traverses inbound edges.
        """
        visited: Set[str] = set()
        queue: collections.deque = collections.deque([(node_id, 0)])
        result: List[str] = []

        while queue:
            curr, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for parent, _ in self.adj_in.get(curr, []):
                if parent not in visited:
                    visited.add(parent)
                    result.append(parent)
                    queue.append((parent, depth + 1))
        return result

    def calculate_blast_radius(self, failed_node_id: str) -> Dict[str, Any]:
        """
        Calculates the quantitative blast radius when a node experiences failure.
        Weight decays with graph hop distance and edge latency.
        """
        if failed_node_id not in self.nodes:
            return {"blast_score": 0.0, "impacted_nodes": [], "impacted_count": 0}

        impacted: Dict[str, float] = {}
        queue: collections.deque = collections.deque([(failed_node_id, 1.0, 0)])
        visited: Set[str] = {failed_node_id}

        while queue:
            curr_id, current_impact, hops = queue.popleft()
            for neighbor_id, edge in self.adj_out.get(curr_id, []):
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    # Decay impact by hop distance and node criticality
                    neighbor_node = self.nodes[neighbor_id]
                    crit_mult = 1.5 if neighbor_node.type in [NodeType.DATABASE_RDBMS, NodeType.GATEWAY] else 1.0
                    decayed_impact = (current_impact * 0.75 * crit_mult) / (1.0 + (edge.latency_ms / 100.0))
                    impacted[neighbor_id] = round(decayed_impact, 3)
                    queue.append((neighbor_id, decayed_impact, hops + 1))

        total_nodes = max(len(self.nodes) - 1, 1)
        raw_score = sum(impacted.values())
        normalized_blast_score = round(min(100.0, (raw_score / total_nodes) * 100.0), 2)

        return {
            "root_node_id": failed_node_id,
            "blast_score": normalized_blast_score,
            "impacted_count": len(impacted),
            "impacted_nodes": [
                {
                    "node_id": nid,
                    "node_name": self.nodes[nid].name,
                    "type": self.nodes[nid].type.value if isinstance(self.nodes[nid].type, NodeType) else self.nodes[nid].type,
                    "estimated_impact_pct": round(impact * 100, 1)
                }
                for nid, impact in impacted.items()
            ]
        }

    def perform_graph_rca(self, anomalous_node_ids: List[str]) -> Dict[str, Any]:
        """
        Graph-based Root Cause Analysis (RCA).
        Given multiple anomalous nodes across the stack, traces the dependency DAG
        to find the common upstream root cause vertex (Lowest Common Ancestor / Origin Node).
        """
        if not anomalous_node_ids:
            return {"root_cause": None, "confidence": 0.0, "reasoning": "No anomalous nodes provided."}

        # Count how many anomalous nodes trace back to each candidate ancestor
        candidate_scores: Dict[str, int] = collections.defaultdict(int)
        
        for node_id in anomalous_node_ids:
            if node_id not in self.nodes:
                continue
            # Self vote
            candidate_scores[node_id] += 1
            # Upstream ancestors vote
            upstreams = self.get_upstream_dependencies(node_id, max_depth=6)
            for anc in upstreams:
                candidate_scores[anc] += 2  # upstream causes get higher weight

        if not candidate_scores:
            return {"root_cause": None, "confidence": 0.0, "reasoning": "No graph path found."}

        # Filter candidates by their health or anomalous status
        sorted_candidates = sorted(candidate_scores.items(), key=lambda x: x[1], reverse=True)
        primary_candidate_id, highest_score = sorted_candidates[0]
        primary_node = self.nodes[primary_candidate_id]

        confidence = round(min(0.98, 0.5 + (highest_score / (len(anomalous_node_ids) * 3))), 2)

        downstream_symptoms = [
            self.nodes[nid].name for nid in anomalous_node_ids if nid != primary_candidate_id and nid in self.nodes
        ]

        reasoning = (
            f"Graph topological traversal identified '{primary_node.name}' ({primary_node.type.value if isinstance(primary_node.type, NodeType) else primary_node.type}) "
            f"as the primary root cause ancestor propagating cascading degradation to {len(downstream_symptoms)} downstream components: "
            f"[{', '.join(downstream_symptoms) if downstream_symptoms else 'isolated component'}]."
        )

        return {
            "root_cause_node_id": primary_candidate_id,
            "root_cause_node_name": primary_node.name,
            "root_cause_type": primary_node.type.value if isinstance(primary_node.type, NodeType) else primary_node.type,
            "confidence": confidence,
            "score": highest_score,
            "reasoning": reasoning,
            "downstream_symptoms": downstream_symptoms
        }

    def export_neo4j_cypher(self) -> str:
        """
        Generates Neo4j Cypher statements to replicate the full topology into a Neo4j Graph DB.
        """
        cypher_lines = ["// --- SENTINOPS HYBRID CLOUD TOPOLOGY CYPHER SCRIPT ---"]
        cypher_lines.append("// Clear existing topology constraints / nodes")
        cypher_lines.append("MATCH (n:SentinOpsNode) DETACH DELETE n;\n")

        # Create Nodes
        for node in self.nodes.values():
            node_type = node.type.value if isinstance(node.type, NodeType) else node.type
            node_status = node.status.value if isinstance(node.status, NodeStatus) else node.status
            props = {
                "id": node.id,
                "name": node.name,
                "type": node_type,
                "status": node_status,
                "ip_address": node.ip_address or "N/A",
                "subnet": node.subnet or "N/A",
                "os_info": node.os_info or "Linux"
            }
            prop_str = ", ".join([f"{k}: '{v}'" for k, v in props.items()])
            cypher_lines.append(f"CREATE (:{node_type}:SentinOpsNode {{{prop_str}}});")

        cypher_lines.append("\n// Create Directed Relationships")
        # Create Edges
        for edge in self.edges:
            rel_type = edge.relation.value if isinstance(edge.relation, EdgeType) else edge.relation
            cypher_lines.append(
                f"MATCH (s:SentinOpsNode {{id: '{edge.source_id}'}}), (t:SentinOpsNode {{id: '{edge.target_id}'}}) "
                f"CREATE (s)-[:{rel_type} {{latency_ms: {edge.latency_ms}, bandwidth_mbps: {edge.bandwidth_mbps}}}]->(t);"
            )

        return "\n".join(cypher_lines)

    def to_json_dict(self) -> Dict[str, Any]:
        """Serializes the graph topology into a web-ready format."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges]
        }
