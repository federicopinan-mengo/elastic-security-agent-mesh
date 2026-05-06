import os
import requests
from typing import Optional


class ElasticClient:
    """Executes ES|QL queries against Elastic Cloud."""

    def __init__(self):
        self.cloud_url = os.environ.get("ELASTIC_CLOUD_URL")
        self.api_key = os.environ.get("ES_API_KEY")
        if not self.cloud_url or not self.api_key:
            raise ValueError("ELASTIC_CLOUD_URL and ES_API_KEY must be set")

    def execute(self, query: str, index_pattern: Optional[str] = None, limit: int = 100) -> dict:
        """
        Execute an ES|QL query and return structured results.

        Args:
            query: ES|QL query string (should include LIMIT)
            index_pattern: Optional index pattern override
            limit: Default row limit if not in query

        Returns:
            dict with keys: success, query, columns, rows, total, took_ms
        """
        # Build the full query with limit if not present
        if "LIMIT" not in query.upper():
            query = f"{query} | LIMIT {limit}"

        url = f"{self.cloud_url}/_query?format=json"
        headers = {
            "Authorization": f"ApiKey {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {"query": query}

        if index_pattern:
            payload["index"] = index_pattern

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()

            # Extract column names from values if present
            columns = data.get("columns", [])
            if columns and isinstance(columns[0], dict):
                column_names = [c.get("name", c.get("id", str(i))) for i, c in enumerate(columns)]
            else:
                column_names = columns if columns else []

            rows = data.get("values", [])
            total = data.get("total", len(rows))
            took_ms = data.get("took", 0)

            return {
                "success": True,
                "query": query,
                "columns": column_names,
                "rows": [dict(zip(column_names, row)) for row in rows],
                "total": total,
                "took_ms": took_ms,
            }

        except requests.RequestException as e:
            return {
                "success": False,
                "query": query,
                "error": type(e).__name__,
                "message": str(e),
            }