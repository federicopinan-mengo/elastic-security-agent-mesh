import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "elastic_client"))
from client import ElasticClient


INDEX_PATTERNS = ["logs-*", "*-logs-*", "logs-generic-default-*"]


class ElasticLogsSearch:
    """Search generic logs from Elastic."""

    def __init__(self):
        self.client = ElasticClient()
        self.index_patterns = INDEX_PATTERNS

    def _nl_to_esql(self, question: str) -> str:
        """Convert natural language to ES|QL for logs."""
        q = question.lower()

        # Time range
        time_filter = ""
        if "last hour" in q or "última hora" in q:
            time_filter = "@timestamp >= NOW() - 1h"
        elif "last 24" in q or "últimas 24" in q or "último día" in q:
            time_filter = "@timestamp >= NOW() - 1d"
        elif "last 7" in q or "última semana" in q or "últimos 7" in q:
            time_filter = "@timestamp >= NOW() - 7d"
        elif "today" in q or "hoy" in q:
            time_filter = "@timestamp >= NOW() - 1d"

        # Keyword search - look for error, warning, etc in message field
        keyword_filter = ""
        if "error" in q or "error" in q:
            keyword_filter = "MATCH(message, 'error')"
        elif "warning" in q or "warn" in q:
            keyword_filter = "MATCH(message, 'warning')"
        elif "fail" in q:
            keyword_filter = "MATCH(message, 'fail')"
        elif "timeout" in q:
            keyword_filter = "MATCH(message, 'timeout')"

        base_select = "@timestamp, message, log.level, host.name"

        where_parts = [p for p in [time_filter, keyword_filter] if p]
        where_clause = ""
        if where_parts:
            where_clause = " | WHERE " + " AND ".join(where_parts)

        query = f"FROM {','.join(self.index_patterns)} | {base_select}{where_clause} | LIMIT 100"
        return query

    def search(self, question: str) -> dict:
        """Execute log search based on natural language question."""
        query = self._nl_to_esql(question)
        return self.client.execute(query=query)
