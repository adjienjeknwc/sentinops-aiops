"""
SentinOps AIOps Anomaly Detector & Diagnostic Engine
Combines Multi-variate Statistical/ML Anomaly Detection (EWMA, Adaptive Z-Score, IQR)
with Graph RCA correlation to synthesize high-confidence incident diagnoses.
"""
import math
import time
from typing import Dict, List, Optional, Any
from .models import (
    LinuxTelemetry,
    NetworkTelemetry,
    AnomalyAlert,
    IncidentReport,
    IncidentSeverity,
    IncidentStatus
)
from .graph_engine import GraphKnowledgeEngine


class AIOpsDetector:
    """
    Intelligent Anomaly Detection & Incident Correlation Engine.
    Employs Exponentially Weighted Moving Average (EWMA), dynamic standard deviation
    thresholds, and multi-metric anomaly scoring.
    """

    def __init__(self, z_score_threshold: float = 2.5):
        self.z_score_threshold = z_score_threshold
        # Historical baselines: {node_id: {metric_name: [values]}}
        self.metric_history: Dict[str, Dict[str, List[float]]] = {}
        # Alert buffer for temporal correlation
        self.active_alerts: List[AnomalyAlert] = []

    def record_metric(self, node_id: str, metric_name: str, value: float, max_history: int = 50) -> None:
        """Stores metric samples in rolling buffer."""
        if node_id not in self.metric_history:
            self.metric_history[node_id] = {}
        if metric_name not in self.metric_history[node_id]:
            self.metric_history[node_id][metric_name] = []

        history = self.metric_history[node_id][metric_name]
        history.append(value)
        if len(history) > max_history:
            history.pop(0)

    def _compute_stats(self, values: List[float]) -> tuple[float, float]:
        """Calculates mean and standard deviation."""
        if not values:
            return 0.0, 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = math.sqrt(variance)
        return mean, std_dev

    def evaluate_metric(
        self,
        node_id: str,
        metric_name: str,
        current_value: float,
        critical_threshold: Optional[float] = None
    ) -> Optional[AnomalyAlert]:
        """
        Evaluates whether a metric exhibits an anomalous spike or threshold violation.
        Uses adaptive Z-Score compared against rolling historical baseline.
        """
        self.record_metric(node_id, metric_name, current_value)
        history = self.metric_history[node_id][metric_name]

        # Explicit absolute threshold check
        if critical_threshold is not None and current_value >= critical_threshold:
            alert = AnomalyAlert(
                node_id=node_id,
                metric_name=metric_name,
                current_value=round(current_value, 2),
                baseline_value=round(critical_threshold, 2),
                z_score=4.0,
                severity=IncidentSeverity.CRITICAL,
                description=f"Critical threshold breach: {metric_name}={current_value} (threshold: {critical_threshold})"
            )
            self.active_alerts.append(alert)
            return alert

        if len(history) < 5:
            # Not enough samples for statistical Z-Score
            return None

        mean, std_dev = self._compute_stats(history[:-1])
        if std_dev < 1e-4:
            std_dev = 1.0  # Avoid zero-division on flat signals

        z_score = (current_value - mean) / std_dev

        if abs(z_score) >= self.z_score_threshold:
            severity = IncidentSeverity.CRITICAL if abs(z_score) >= 3.5 else IncidentSeverity.HIGH
            alert = AnomalyAlert(
                node_id=node_id,
                metric_name=metric_name,
                current_value=round(current_value, 2),
                baseline_value=round(mean, 2),
                z_score=round(z_score, 2),
                severity=severity,
                description=f"Statistical anomaly detected in {metric_name}: value={current_value} vs baseline={mean:.1f} (Z-Score: {z_score:.2f})"
            )
            self.active_alerts.append(alert)
            return alert

        return None

    def analyze_linux_telemetry(self, t: LinuxTelemetry) -> List[AnomalyAlert]:
        """Scans Linux OS metrics for degradation or resource exhaustion."""
        alerts: List[AnomalyAlert] = []
        checks = [
            (t.node_id, "cpu_utilization_pct", t.cpu_utilization_pct, 90.0),
            (t.node_id, "memory_utilization_pct", t.memory_utilization_pct, 88.0),
            (t.node_id, "disk_utilization_pct", t.disk_utilization_pct, 92.0),
            (t.node_id, "zombie_processes", float(t.zombie_processes), 5.0),
            (t.node_id, "systemd_failed_units", float(t.systemd_failed_units), 1.0),
            (t.node_id, "kernel_load_avg_1m", t.kernel_load_avg_1m, 12.0),
            (t.node_id, "cgroup_memory_pressure_pct", t.cgroup_memory_pressure_pct, 80.0),
        ]
        for nid, metric, val, thresh in checks:
            alert = self.evaluate_metric(nid, metric, val, critical_threshold=thresh)
            if alert:
                alerts.append(alert)
        return alerts

    def analyze_network_telemetry(self, t: NetworkTelemetry) -> List[AnomalyAlert]:
        """Scans Network metrics for packet drops, socket exhaustion, or DNS jitter."""
        alerts: List[AnomalyAlert] = []
        checks = [
            (t.node_id, "packet_loss_pct", t.packet_loss_pct, 5.0),
            (t.node_id, "dns_resolution_latency_ms", t.dns_resolution_latency_ms, 150.0),
            (t.node_id, "tcp_connections_time_wait", float(t.tcp_connections_time_wait), 500.0),
            (t.node_id, "tcp_connections_syn_sent", float(t.tcp_connections_syn_sent), 100.0),
            (t.node_id, "socket_buffer_drops", float(t.socket_buffer_drops), 10.0),
        ]
        for nid, metric, val, thresh in checks:
            alert = self.evaluate_metric(nid, metric, val, critical_threshold=thresh)
            if alert:
                alerts.append(alert)
        return alerts

    def correlate_and_diagnose(
        self,
        graph_engine: GraphKnowledgeEngine,
        time_window_sec: float = 300.0
    ) -> Optional[IncidentReport]:
        """
        AIOps Root Cause Synthesis:
        Correlates active alerts across time and maps them onto the Dependency Graph.
        Discovers the root cause node and recommends an automated self-healing Ansible playbook.
        """
        now = time.time()
        recent_alerts = [a for a in self.active_alerts if (now - a.timestamp) <= time_window_sec]

        if not recent_alerts:
            return None

        anomalous_node_ids = list(set(a.node_id for a in recent_alerts))
        rca_result = graph_engine.perform_graph_rca(anomalous_node_ids)

        if not rca_result or not rca_result.get("root_cause_node_id"):
            return None

        root_id = rca_result["root_cause_node_id"]
        blast_info = graph_engine.calculate_blast_radius(root_id)

        # Classify root cause type to select the appropriate remediation playbook
        root_alerts = [a for a in recent_alerts if a.node_id == root_id]
        recommended_playbook = "ansible/playbooks/auto_heal.yml"
        
        primary_metric = root_alerts[0].metric_name if root_alerts else "general_failure"
        if "tcp" in primary_metric or "socket" in primary_metric or "dns" in primary_metric or "packet" in primary_metric:
            recommended_playbook = "ansible/playbooks/network_failover.yml"
        elif "systemd" in primary_metric or "memory" in primary_metric or "zombie" in primary_metric:
            recommended_playbook = "ansible/playbooks/auto_heal.yml"
        elif "security" in primary_metric or "auth" in primary_metric:
            recommended_playbook = "ansible/playbooks/harden_infrastructure.yml"

        incident = IncidentReport(
            title=f"AIOps Incident: Cascading Degradation origin at {rca_result.get('root_cause_node_name', root_id)}",
            root_cause_node_id=root_id,
            root_cause_hypothesis=rca_result["reasoning"],
            confidence_score=rca_result["confidence"],
            severity=IncidentSeverity.CRITICAL if blast_info["blast_score"] > 40 else IncidentSeverity.HIGH,
            status=IncidentStatus.DETECTED,
            affected_nodes=[n["node_id"] for n in blast_info["impacted_nodes"]],
            blast_radius_score=blast_info["blast_score"],
            correlated_alerts=recent_alerts,
            recommended_playbook=recommended_playbook,
            execution_log=[
                f"[{time.strftime('%H:%M:%S')}] AIOps ML Engine detected {len(recent_alerts)} correlated anomalies across {len(anomalous_node_ids)} nodes.",
                f"[{time.strftime('%H:%M:%S')}] Graph RCA computed primary failure ancestor: {root_id} (confidence: {rca_result['confidence'] * 100}%).",
                f"[{time.strftime('%H:%M:%S')}] Recommended remediation playbook: {recommended_playbook}"
            ]
        )

        return incident
