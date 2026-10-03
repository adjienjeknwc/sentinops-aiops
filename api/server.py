"""
SentinOps REST API & Web Dashboard Server
Provides high-performance RESTful endpoints for topology graph inspection, live telemetry,
AIOps incident correlation, automated Ansible self-healing, and DevSecOps compliance audits.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import sys
import threading
import time
import urllib.parse
from typing import Dict, Any

from core.models import (
    TopologyNode,
    TopologyEdge,
    NodeType,
    NodeStatus,
    EdgeType,
    IncidentReport,
    IncidentStatus
)
from core.graph_engine import GraphKnowledgeEngine
from core.aiops_detector import AIOpsDetector
from core.telemetry_collector import TelemetryCollector
from core.remediation_orchestrator import RemediationOrchestrator
from core.devsecops_scanner import DevSecOpsScanner
from core.database import MultiModelDatabase


# Global Platform State Singletons
graph_engine = GraphKnowledgeEngine()
aiops_detector = AIOpsDetector(z_score_threshold=2.2)
telemetry_collector = TelemetryCollector()
orchestrator = RemediationOrchestrator()
db = MultiModelDatabase()

# Chaos simulation overrides: {node_id: failure_mode}
chaos_overrides: Dict[str, str] = {}
active_incident: IncidentReport = None


def initialize_hybrid_cloud_topology():
    """Initializes the multi-tier enterprise hybrid cloud topology."""
    # 1. Edge & Networking Tier
    gw = TopologyNode(id="gw-edge-ingress-01", name="Edge Ingress Gateway (Nginx/BGP)", type=NodeType.GATEWAY, ip_address="10.0.1.10", subnet="10.0.1.0/24")
    lb = TopologyNode(id="lb-app-internal", name="Internal Load Balancer", type=NodeType.LOAD_BALANCER, ip_address="10.0.2.15", subnet="10.0.2.0/24")
    
    # 2. Linux App Nodes Tier
    app1 = TopologyNode(id="host-linux-app-01", name="Linux App Worker 01 (Ubuntu 22.04)", type=NodeType.LINUX_HOST, ip_address="10.0.4.11", subnet="10.0.4.0/24")
    app2 = TopologyNode(id="host-linux-app-02", name="Linux App Worker 02 (Ubuntu 22.04)", type=NodeType.LINUX_HOST, ip_address="10.0.4.12", subnet="10.0.4.0/24")
    svc1 = TopologyNode(id="svc-order-processing", name="Order Processing Microservice", type=NodeType.MICROSERVICE, ip_address="10.0.4.110", subnet="10.0.4.0/24")
    svc2 = TopologyNode(id="svc-telemetry-ingest", name="Telemetry Ingestion Microservice", type=NodeType.MICROSERVICE, ip_address="10.0.4.120", subnet="10.0.4.0/24")

    # 3. Multi-Model Database Tier (RDBMS, NoSQL, Graph DB)
    db_rdbms = TopologyNode(id="db-primary-rdbms", name="PostgreSQL Cluster (RDBMS)", type=NodeType.DATABASE_RDBMS, ip_address="10.0.5.20", subnet="10.0.5.0/24")
    db_nosql = TopologyNode(id="db-nosql-telemetry", name="MongoDB Timeseries (NoSQL)", type=NodeType.DATABASE_NOSQL, ip_address="10.0.5.21", subnet="10.0.5.0/24")
    db_graph = TopologyNode(id="db-graph-topology", name="Neo4j Knowledge Graph (Graph DB)", type=NodeType.DATABASE_GRAPH, ip_address="10.0.5.22", subnet="10.0.5.0/24")

    # Register Nodes
    for n in [gw, lb, app1, app2, svc1, svc2, db_rdbms, db_nosql, db_graph]:
        graph_engine.add_node(n)

    # Register Directed Edges / Dependencies
    edges = [
        TopologyEdge(source_id="gw-edge-ingress-01", target_id="lb-app-internal", relation=EdgeType.ROUTES_TO, latency_ms=1.2),
        TopologyEdge(source_id="lb-app-internal", target_id="host-linux-app-01", relation=EdgeType.ROUTES_TO, latency_ms=2.1),
        TopologyEdge(source_id="lb-app-internal", target_id="host-linux-app-02", relation=EdgeType.ROUTES_TO, latency_ms=2.0),
        TopologyEdge(source_id="svc-order-processing", target_id="host-linux-app-01", relation=EdgeType.RUNS_ON, latency_ms=0.2),
        TopologyEdge(source_id="svc-telemetry-ingest", target_id="host-linux-app-02", relation=EdgeType.RUNS_ON, latency_ms=0.2),
        TopologyEdge(source_id="svc-order-processing", target_id="db-primary-rdbms", relation=EdgeType.DEPENDS_ON, latency_ms=3.4),
        TopologyEdge(source_id="svc-telemetry-ingest", target_id="db-nosql-telemetry", relation=EdgeType.DEPENDS_ON, latency_ms=2.8),
        TopologyEdge(source_id="svc-telemetry-ingest", target_id="db-graph-topology", relation=EdgeType.DEPENDS_ON, latency_ms=4.1),
    ]
    for e in edges:
        graph_engine.add_edge(e)


# Initialize topology immediately
initialize_hybrid_cloud_topology()


class SentinOpsRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for REST API and Static UI."""

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ["/", "/index.html"]:
            html_file = os.path.join(os.path.dirname(__file__), "..", "dashboard", "index.html")
            if os.path.exists(html_file):
                with open(html_file, "rb") as f:
                    content = f.read()
                self._set_headers(200, "text/html")
                self.wfile.write(content)
            else:
                self._set_headers(404, "text/plain")
                self.wfile.write(b"Dashboard HTML not found.")
            return

        if path == "/api/health":
            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "ONLINE", "version": "2.4.0", "timestamp": time.time()}).encode())
            return

        if path == "/api/topology":
            self._set_headers(200)
            self.wfile.write(json.dumps(graph_engine.to_json_dict()).encode())
            return

        if path == "/api/telemetry":
            telemetry_data = {}
            for nid in graph_engine.nodes.keys():
                is_failing = (nid in chaos_overrides)
                failure_mode = chaos_overrides.get(nid)
                linux_t, net_t = telemetry_collector.generate_synthetic_node_telemetry(nid, is_failing, failure_mode)
                
                # Record to NoSQL store
                db.insert_nosql_telemetry({"node_id": nid, "linux": linux_t.to_dict(), "network": net_t.to_dict(), "timestamp": time.time()})
                telemetry_data[nid] = {"linux": linux_t.to_dict(), "network": net_t.to_dict()}

            self._set_headers(200)
            self.wfile.write(json.dumps(telemetry_data).encode())
            return

        if path == "/api/graph/cypher":
            cypher = graph_engine.export_neo4j_cypher()
            self._set_headers(200, "text/plain")
            self.wfile.write(cypher.encode())
            return

        if path == "/api/security/audit":
            audit_result = DevSecOpsScanner.run_full_security_audit()
            self._set_headers(200)
            self.wfile.write(json.dumps(audit_result).encode())
            return

        if path == "/api/incidents/history":
            incidents = db.get_recent_incidents()
            self._set_headers(200)
            self.wfile.write(json.dumps(incidents).encode())
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())

    def do_POST(self):
        global active_incident
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}

        if path == "/api/chaos/inject":
            node_id = query.get("node_id", [payload.get("node_id", "host-linux-app-01")])[0]
            mode = query.get("mode", [payload.get("mode", "MEMORY_LEAK")])[0]
            chaos_overrides[node_id] = mode
            graph_engine.update_node_status(node_id, NodeStatus.CRITICAL)

            # Generate failing metrics to populate AIOps detector immediately
            linux_t, net_t = telemetry_collector.generate_synthetic_node_telemetry(node_id, is_failing=True, failure_mode=mode)
            aiops_detector.analyze_linux_telemetry(linux_t)
            aiops_detector.analyze_network_telemetry(net_t)

            self._set_headers(200)
            self.wfile.write(json.dumps({
                "status": "CHAOS_INJECTED",
                "node_id": node_id,
                "failure_mode": mode
            }).encode())
            return

        if path == "/api/chaos/reset":
            chaos_overrides.clear()
            for nid in graph_engine.nodes.keys():
                graph_engine.update_node_status(nid, NodeStatus.HEALTHY)
            aiops_detector.active_alerts.clear()
            active_incident = None

            self._set_headers(200)
            self.wfile.write(json.dumps({"status": "CHAOS_CLEARED", "message": "All nodes restored to HEALTHY."}).encode())
            return

        if path == "/api/incidents/analyze":
            # Run AIOps anomaly correlation and Graph RCA
            incident = aiops_detector.correlate_and_diagnose(graph_engine)
            if incident:
                active_incident = incident
                db.save_incident(incident)
                self._set_headers(200)
                self.wfile.write(json.dumps(incident.to_dict()).encode())
            else:
                # If no active anomaly, return clean status
                self._set_headers(200)
                self.wfile.write(json.dumps({"status": "NOMINAL", "message": "All infrastructure nodes operating within nominal thresholds."}).encode())
            return

        if path == "/api/remediate":
            if not active_incident:
                # Create a sample incident to demonstrate remediation if none is active
                target_node = payload.get("node_id", "host-linux-app-01")
                blast = graph_engine.calculate_blast_radius(target_node)
                active_incident = IncidentReport(
                    title=f"AIOps Self-Healing for {target_node}",
                    root_cause_node_id=target_node,
                    root_cause_hypothesis=f"High memory saturation and thread starvation detected on {target_node}.",
                    confidence_score=0.96,
                    blast_radius_score=blast["blast_score"],
                    recommended_playbook="ansible/playbooks/auto_heal.yml"
                )

            # Execute Ansible Playbook
            resolved_incident = orchestrator.remediate_incident(active_incident)
            db.save_incident(resolved_incident)
            
            # Reset chaos override for the fixed node
            if resolved_incident.root_cause_node_id in chaos_overrides:
                del chaos_overrides[resolved_incident.root_cause_node_id]
            graph_engine.update_node_status(resolved_incident.root_cause_node_id, NodeStatus.HEALTHY)
            aiops_detector.active_alerts.clear()

            self._set_headers(200)
            self.wfile.write(json.dumps(resolved_incident.to_dict()).encode())
            return

        self._set_headers(404)
        self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())


def run_server(port: int = 8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, SentinOpsRequestHandler)
    print(f"[*] SentinOps AIOps Server listening on http://0.0.0.0:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
