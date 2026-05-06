import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "elastic_client"))
from client import ElasticClient


SCHEMA_FIELDS = {
    "alert.id": "Alert unique identifier",
    "alert.rule.name": "Detection rule name",
    "alert.severity": "critical|high|medium|low",
    "alert.status": "active|acknowledged|closed",
    "kibana.alert.reason": "Human-readable alert reason",
    "signal.original_time": "Original event timestamp",
    "event.kind": "event|signal|alert",
    "user.name": "Affected username",
    "host.name": "Affected host",
    "source.ip": "Source IP address",
    "destination.ip": "Destination IP address",
    "@timestamp": "Alert timestamp",
}

INDEX_PATTERNS = [".alerts-security.alerts-*", ".siem-signals-default-*"]


class ElasticAlertsSearch:
    """Search security alerts from Elastic."""

    def __init__(self):
        self.client = ElasticClient()
        self.index_patterns = INDEX_PATTERNS
        self.schema = SCHEMA_FIELDS

    def _nl_to_esql(self, question: str) -> str:
        """Convert natural language to ES|QL for alerts."""
        q = question.lower()

        # Time range
        time_filter = ""
        if "last hour" in q or "última hora" in q:
            time_filter = "WHERE @timestamp >= NOW() - 1h"
        elif "last 24" in q or "últimas 24" in q or "último día" in q:
            time_filter = "WHERE @timestamp >= NOW() - 1d"
        elif "last 7" in q or "última semana" in q or "últimos 7" in q:
            time_filter = "WHERE @timestamp >= NOW() - 7d"
        elif "today" in q or "hoy" in q:
            time_filter = "WHERE @timestamp >= NOW() - 1d"

        # Severity filter
        severity_filter = ""
        if "critical" in q:
            severity_filter = "alert.severity == 'critical'"
        elif "high" in q and "critical" not in q:
            severity_filter = "alert.severity == 'high'"
        elif "medium" in q or "medium" in q:
            severity_filter = "alert.severity == 'medium'"
        elif "low" in q:
            severity_filter = "alert.severity == 'low'"

        # Status filter
        status_filter = ""
        if "open" in q or "active" in q:
            status_filter = "alert.status == 'active'"
        elif "closed" in q or "cerrada" in q:
            status_filter = "alert.status == 'closed'"
        elif "acknowledged" in q or "acknow" in q:
            status_filter = "alert.status == 'acknowledged'"

        # False positive detection
        fp_filter = ""
        if "false positive" in q or "falso positivo" in q:
            fp_filter = "alert.status == 'closed'"

        base_select = "alert.id, alert.rule.name, alert.severity, alert.status, kibana.alert.reason, @timestamp"

        # Combine WHERE parts
        where_parts = [p for p in [time_filter, severity_filter, status_filter, fp_filter] if p]
        where_clause = ""
        if where_parts:
            where_clause = " | WHERE " + " AND ".join(where_parts)

        query = f"FROM {','.join(self.index_patterns)} | {base_select}{where_clause} | LIMIT 50"
        return query

    def search(self, question: str) -> dict:
        """Execute alert search based on natural language question."""
        query = self._nl_to_esql(question)
        return self.client.execute(query=query)