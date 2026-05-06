import sys
import os
from typing import Optional

# Add shared client to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "elastic_client"))
from client import ElasticClient


# Schema context for NL → ES|QL conversion
SCHEMA_FIELDS = {
    "agent.id": "Agent unique identifier",
    "agent.name": "Agent display name",
    "agent.status": "online|offline|unknown",
    "agent.type": "endpoint|fleet-server",
    "host.name": "Hostname",
    "host.os.name": "Operating system name",
    "host.os.full": "Full OS name (e.g. macOS 14.4)",
    "host.ip": "Host IP addresses (array)",
    "host.cpu_usage": "CPU usage percentage",
    "host.memory_usage": "Memory usage percentage",
    "@timestamp": "Event timestamp",
    "last_checkin": "Last time agent checked in",
}

INDEX_PATTERNS = ["fleet-agents-*", "metrics-fleet.agent-default-*"]


class ElasticFleetSearch:
    """Search Fleet agent metadata from Elastic."""

    def __init__(self):
        self.client = ElasticClient()
        self.index_patterns = INDEX_PATTERNS
        self.schema = SCHEMA_FIELDS

    def _nl_to_esql(self, question: str) -> str:
        """
        Convert natural language question to ES|QL query.
        Uses keyword matching to infer query intent.
        """
        q = question.lower()

        # Determine time range
        time_filter = ""
        if "last hour" in q or "última hora" in q:
            time_filter = "WHERE @timestamp >= NOW() - 1h"
        elif "last 24" in q or "últimas 24" in q or "último día" in q:
            time_filter = "WHERE @timestamp >= NOW() - 1d"
        elif "last 7" in q or "última semana" in q or "últimos 7" in q:
            time_filter = "WHERE @timestamp >= NOW() - 7d"
        elif "today" in q or "hoy" in q:
            time_filter = "WHERE @timestamp >= NOW() - 1d"

        # Determine status filter
        status_filter = ""
        if "online" in q and "offline" not in q:
            status_filter = "agent.status == 'online'"
        elif "offline" in q:
            status_filter = "agent.status == 'offline'"

        # Determine what to select
        base_select = "agent.id, agent.name, agent.status, host.name, host.os.name, @timestamp"

        # Build WHERE clause
        where_parts = [p for p in [time_filter, status_filter] if p]
        where_clause = ""
        if where_parts:
            where_clause = " | WHERE " + " AND ".join(where_parts)

        # Build query
        query = f"FROM {','.join(self.index_patterns)} | {base_select}{where_clause} | LIMIT 50"
        return query

    def search(self, question: str) -> dict:
        """
        Execute fleet agent search based on natural language question.

        Args:
            question: Natural language question about fleet agents

        Returns:
            dict with success, query, columns, rows, total, took_ms
        """
        query = self._nl_to_esql(question)
        return self.client.execute(query=query)
