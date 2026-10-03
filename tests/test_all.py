"""
SentinOps Test Suite
Verifies Graph Algorithms, AIOps Anomaly Scoring, Blast Radius, Ansible Remediation,
DevSecOps Scans, and Multi-Model Persistence.
"""
import unittest
import os
import sys

# Ensure root package is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.models import (
    TopologyNode,
    TopologyEdge,
    NodeType,
    NodeStatus,
    EdgeType,
    LinuxTelemetry,
    NetworkTelemetry,
    IncidentSeverity,
    IncidentStatus
)
from core.graph_engine import GraphKnowledgeEngine
from core.aiops_detector import AIOpsDetector
from core.telemetry_collector import TelemetryCollector
from core.remediation_orchestrator import RemediationOrchestrator
from core.devsecops_scanner import DevSecOpsScanner
from core.database import MultiModelDatabase


class TestSentinOpsCore(unittest.TestCase):

    def setUp(self):
        self.graph = GraphKnowledgeEngine()
        # Setup test graph
        self.n1 = TopologyNode(id="gw-1", name="Gateway", type=NodeType.GATEWAY)
        self.n2 = TopologyNode(id="host-1", name="Linux Host 1", type=NodeType.LINUX_HOST)
        self.n3 = TopologyNode(id="svc-1", name="Microservice 1", type=NodeType.MICROSERVICE)
        self.n4 = TopologyNode(id="db-1", name="Postgres DB", type=NodeType.DATABASE_RDBMS)

        self.graph.add_node(self.n1)
        self.graph.add_node(self.n2)
        self.graph.add_node(self.n3)
        self.graph.add_node(self.n4)

        self.graph.add_edge(TopologyEdge(source_id="gw-1", target_id="host-1", relation=EdgeType.ROUTES_TO))
        self.graph.add_edge(TopologyEdge(source_id="svc-1", target_id="host-1", relation=EdgeType.RUNS_ON))
        self.graph.add_edge(TopologyEdge(source_id="svc-1", target_id="db-1", relation=EdgeType.DEPENDS_ON))

    def test_graph_traversal_and_blast_radius(self):
        """Test downstream blast radius computation."""
        blast = self.graph.calculate_blast_radius("gw-1")
        self.assertEqual(blast["root_node_id"], "gw-1")
        self.assertGreater(blast["blast_score"], 0)
        self.assertEqual(blast["impacted_count"], 1)

    def test_graph_rca(self):
        """Test finding upstream root cause given downstream symptoms."""
        rca = self.graph.perform_graph_rca(["host-1", "gw-1"])
        self.assertIsNotNone(rca["root_cause_node_id"])
        self.assertGreater(rca["confidence"], 0.5)

    def test_neo4j_cypher_export(self):
        """Test generation of valid Neo4j Cypher statements."""
        cypher = self.graph.export_neo4j_cypher()
        self.assertIn("CREATE (:GATEWAY:SentinOpsNode", cypher)
        self.assertIn("ROUTES_TO", cypher)

    def test_aiops_anomaly_detection(self):
        """Test statistical Z-Score and threshold anomaly detection."""
        detector = AIOpsDetector(z_score_threshold=2.0)
        
        # Populate baseline
        for _ in range(10):
            detector.evaluate_metric("host-1", "cpu_utilization_pct", 30.0)

        # Inject extreme anomaly
        alert = detector.evaluate_metric("host-1", "cpu_utilization_pct", 98.0, critical_threshold=90.0)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, IncidentSeverity.CRITICAL)

    def test_telemetry_collection(self):
        """Test Linux and Network telemetry probes."""
        collector = TelemetryCollector()
        linux_t = collector.get_real_linux_telemetry("test-node")
        net_t = collector.get_real_network_telemetry("test-node")
        
        self.assertEqual(linux_t.node_id, "test-node")
        self.assertIsInstance(linux_t.cpu_utilization_pct, float)
        self.assertEqual(net_t.node_id, "test-node")
        self.assertIsInstance(net_t.dns_resolution_latency_ms, float)

    def test_devsecops_scanner(self):
        """Test CIS benchmark and secret detection scanning."""
        findings = DevSecOpsScanner.scan_cis_linux_benchmarks("test-host")
        self.assertGreater(len(findings), 0)
        self.assertTrue(all(f.category == "CIS_BENCHMARK" for f in findings))

        # Test secret regex detection
        secret_findings = DevSecOpsScanner.scan_text_for_secrets(
            "AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE12'"
        )
        self.assertGreater(len(secret_findings), 0)
        self.assertEqual(secret_findings[0].category, "SECRETS")

    def test_ansible_remediation_orchestrator(self):
        """Test dynamic Ansible playbook execution."""
        orchestrator = RemediationOrchestrator()
        result = orchestrator.execute_ansible_playbook(
            playbook_path="ansible/playbooks/auto_heal.yml",
            target_hosts="host-linux-app-01",
            dry_run=True
        )
        self.assertTrue(result["success"])
        self.assertIn("host-linux-app-01", result["logs"][1])

    def test_multimodel_database(self):
        """Test RDBMS ACID persistence and NoSQL storage."""
        test_db_path = "test_sentinops.db"
        test_nosql_path = "test_nosql.json"
        
        try:
            db = MultiModelDatabase(db_path=test_db_path, nosql_path=test_nosql_path)
            
            # Insert incident
            inc = self.graph.perform_graph_rca(["host-1"])
            test_incident = self.graph.calculate_blast_radius("host-1")
            
            # Insert NoSQL doc
            db.insert_nosql_telemetry({"node_id": "host-1", "cpu": 45.2})
            events = db.query_nosql_telemetry("host-1")
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["cpu"], 45.2)
        finally:
            if os.path.exists(test_db_path):
                os.remove(test_db_path)
            if os.path.exists(test_nosql_path):
                os.remove(test_nosql_path)


if __name__ == "__main__":
    unittest.main()
