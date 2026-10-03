"""
SentinOps Domain Models
Defines data structures for Topology Nodes, Edges, Metrics, Incidents, and DevSecOps Findings.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid


class NodeType(str, Enum):
    LINUX_HOST = "LINUX_HOST"
    SUBNET = "SUBNET"
    GATEWAY = "GATEWAY"
    MICROSERVICE = "MICROSERVICE"
    DATABASE_RDBMS = "DATABASE_RDBMS"
    DATABASE_NOSQL = "DATABASE_NOSQL"
    DATABASE_GRAPH = "DATABASE_GRAPH"
    CONTAINER = "CONTAINER"
    LOAD_BALANCER = "LOAD_BALANCER"


class NodeStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    UNREACHABLE = "UNREACHABLE"
    MAINTENANCE = "MAINTENANCE"


class EdgeType(str, Enum):
    DEPENDS_ON = "DEPENDS_ON"
    RUNS_ON = "RUNS_ON"
    ROUTES_TO = "ROUTES_TO"
    CONNECTS_TO = "CONNECTS_TO"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    DETECTED = "DETECTED"
    ANALYZING = "ANALYZING"
    REMEDIATING = "REMEDIATING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"


@dataclass
class TopologyNode:
    id: str
    name: str
    type: NodeType
    status: NodeStatus = NodeStatus.HEALTHY
    ip_address: Optional[str] = None
    subnet: Optional[str] = None
    os_info: Optional[str] = "Ubuntu 22.04 LTS (Linux 5.15)"
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['type'] = self.type.value if isinstance(self.type, NodeType) else self.type
        data['status'] = self.status.value if isinstance(self.status, NodeStatus) else self.status
        return data


@dataclass
class TopologyEdge:
    source_id: str
    target_id: str
    relation: EdgeType
    latency_ms: float = 1.0
    bandwidth_mbps: float = 1000.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['relation'] = self.relation.value if isinstance(self.relation, EdgeType) else self.relation
        return data


@dataclass
class LinuxTelemetry:
    node_id: str
    timestamp: float = field(default_factory=time.time)
    cpu_utilization_pct: float = 0.0
    memory_utilization_pct: float = 0.0
    memory_cached_mb: float = 0.0
    disk_utilization_pct: float = 0.0
    disk_iops: int = 0
    open_file_descriptors: int = 0
    zombie_processes: int = 0
    systemd_failed_units: int = 0
    kernel_load_avg_1m: float = 0.0
    cgroup_memory_pressure_pct: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkTelemetry:
    node_id: str
    timestamp: float = field(default_factory=time.time)
    tcp_connections_established: int = 0
    tcp_connections_time_wait: int = 0
    tcp_connections_syn_sent: int = 0
    packet_loss_pct: float = 0.0
    dns_resolution_latency_ms: float = 0.0
    rtt_latency_ms: float = 0.0
    interface_rx_kbps: float = 0.0
    interface_tx_kbps: float = 0.0
    socket_buffer_drops: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnomalyAlert:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    node_id: str = ""
    metric_name: str = ""
    current_value: float = 0.0
    baseline_value: float = 0.0
    z_score: float = 0.0
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    description: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['severity'] = self.severity.value if isinstance(self.severity, IncidentSeverity) else self.severity
        return data


@dataclass
class IncidentReport:
    id: str = field(default_factory=lambda: f"INC-{str(uuid.uuid4())[:8].upper()}")
    title: str = ""
    root_cause_node_id: str = ""
    root_cause_hypothesis: str = ""
    confidence_score: float = 0.0
    severity: IncidentSeverity = IncidentSeverity.HIGH
    status: IncidentStatus = IncidentStatus.DETECTED
    affected_nodes: List[str] = field(default_factory=list)
    blast_radius_score: float = 0.0
    correlated_alerts: List[AnomalyAlert] = field(default_factory=list)
    recommended_playbook: str = ""
    execution_log: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['severity'] = self.severity.value if isinstance(self.severity, IncidentSeverity) else self.severity
        data['status'] = self.status.value if isinstance(self.status, IncidentStatus) else self.status
        data['correlated_alerts'] = [a.to_dict() if hasattr(a, 'to_dict') else a for a in self.correlated_alerts]
        return data


@dataclass
class DevSecOpsFinding:
    id: str = field(default_factory=lambda: f"SEC-{str(uuid.uuid4())[:8].upper()}")
    check_name: str = ""
    category: str = ""  # CIS_BENCHMARK, SAST, SECRETS, PORT_EXPOSURE, CVE
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    target_node_or_file: str = ""
    description: str = ""
    remediation_playbook: str = ""
    compliance_standard: str = "CIS Linux 2.0 / OWASP Top 10"
    passed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['severity'] = self.severity.value if isinstance(self.severity, IncidentSeverity) else self.severity
        return data
