"""
SentinOps Hybrid Database Engine
Integrates RDBMS (SQLite/PostgreSQL schema), NoSQL Document Store, and Graph DB Export.
"""
import json
import os
import sqlite3
import time
from typing import Dict, List, Optional, Any
from .models import IncidentReport, LinuxTelemetry, NetworkTelemetry


class MultiModelDatabase:
    """
    Manages hybrid data storage:
    - RDBMS: Relational tables for Incidents, Remediations, and Audit Logs (ACID compliant).
    - NoSQL: Document-oriented collection store for fast, schemaless telemetry timeseries.
    - Graph: Export & sync utilities for Neo4j.
    """

    def __init__(self, db_path: str = "sentinops.db", nosql_path: str = "nosql_store.json"):
        self.db_path = db_path
        self.nosql_path = nosql_path
        self._init_rdbms()
        self._init_nosql()

    def _init_rdbms(self) -> None:
        """Initializes RDBMS relational schema with constraints and foreign keys."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Incidents Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            root_cause_node_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            blast_radius_score REAL NOT NULL,
            recommended_playbook TEXT,
            raw_payload TEXT,
            created_at REAL NOT NULL,
            resolved_at REAL
        )
        """)

        # Audit Logs Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            action TEXT NOT NULL,
            actor TEXT DEFAULT 'AIOPS_AUTOREMEDIATE_ENGINE',
            details TEXT,
            timestamp REAL NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE CASCADE
        )
        """)

        conn.commit()
        conn.close()

    def _init_nosql(self) -> None:
        """Initializes JSON-based NoSQL Document Store."""
        if not os.path.exists(self.nosql_path):
            with open(self.nosql_path, "w") as f:
                json.dump({"telemetry_events": [], "raw_alerts": []}, f)

    # --- RDBMS Operations ---
    def save_incident(self, incident: IncidentReport) -> None:
        """Persists an incident and writes an audit log in RDBMS."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO incidents 
        (id, title, root_cause_node_id, severity, status, confidence_score, blast_radius_score, recommended_playbook, raw_payload, created_at, resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident.id,
            incident.title,
            incident.root_cause_node_id,
            incident.severity.value if hasattr(incident.severity, 'value') else incident.severity,
            incident.status.value if hasattr(incident.status, 'value') else incident.status,
            incident.confidence_score,
            incident.blast_radius_score,
            incident.recommended_playbook,
            json.dumps(incident.to_dict()),
            incident.created_at,
            incident.resolved_at
        ))

        cursor.execute("""
        INSERT INTO audit_logs (incident_id, action, actor, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """, (
            incident.id,
            f"INCIDENT_STATUS_{incident.status.value if hasattr(incident.status, 'value') else incident.status}",
            "AIOps_Self_Healer",
            f"Confidence: {incident.confidence_score * 100}% | Root: {incident.root_cause_node_id}",
            time.time()
        ))

        conn.commit()
        conn.close()

    def get_recent_incidents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Queries recent incidents from RDBMS."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result

    # --- NoSQL Document Store Operations ---
    def insert_nosql_telemetry(self, doc: Dict[str, Any]) -> None:
        """Appends telemetry document into NoSQL collection."""
        try:
            with open(self.nosql_path, "r") as f:
                data = json.load(f)
            data["telemetry_events"].append(doc)
            # Keep rolling window of last 200 documents
            if len(data["telemetry_events"]) > 200:
                data["telemetry_events"] = data["telemetry_events"][-200:]
            with open(self.nosql_path, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    def query_nosql_telemetry(self, node_id: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """Filters documents in NoSQL collection."""
        try:
            with open(self.nosql_path, "r") as f:
                data = json.load(f)
            events = data.get("telemetry_events", [])
            if node_id:
                events = [e for e in events if e.get("node_id") == node_id]
            return events[-limit:]
        except Exception:
            return []
