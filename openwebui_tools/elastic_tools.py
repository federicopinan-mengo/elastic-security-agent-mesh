"""
title: Elastic Security Data Tools
author: federico
version: 0.1.0
license: MIT
required_open_webui_version: 0.7.0
description: Query Elastic Security data (Fleet agents, alerts, logs, observability) via natural language.
              Includes automatic index discovery to detect the correct index names for your deployment.
              Each tool accepts a natural language question and returns structured JSON results.
"""

import json
import re
import requests
from typing import Optional, Callable, Any, Dict, List

from fastapi import Request
from pydantic import BaseModel, Field


# ============================================================================
# Shared Elastic Client
# ============================================================================


class ElasticClient:
    """Executes ES|QL queries and discovers indices in Elastic Cloud."""

    def __init__(self, cloud_url: str, api_key: str):
        self.cloud_url = cloud_url
        self.api_key = api_key
        if not self.cloud_url or not self.api_key:
            raise ValueError("ELASTIC_CLOUD_URL and ES_API_KEY must be set via Valves")

        self._headers = {
            "Authorization": f"ApiKey {self.api_key}",
            "Content-Type": "application/json",
        }

    def list_indices(self, pattern: str = "*") -> List[str]:
        """List all indices matching a pattern."""
        url = f"{self.cloud_url}/_cat/indices/{pattern}?format=json"
        try:
            response = requests.get(url, headers=self._headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            return [idx.get("index", idx.get("uuid", "")) for idx in data if idx.get("index")]
        except Exception:
            return []

    def discover_indices(self) -> Dict[str, List[str]]:
        """Discover all relevant indices grouped by category."""
        categories = {
            "fleet": [],
            "alerts": [],
            "logs": [],
            "observability": [],
        }

        # Fleet patterns
        fleet_patterns = ["fleet-agents*", "metrics-fleet*", "fleet*"]
        for pattern in fleet_patterns:
            categories["fleet"].extend(self.list_indices(pattern))

        # Alert patterns
        alert_patterns = [".alerts*", "*signals*", "*alerts*", "security*"]
        for pattern in alert_patterns:
            categories["alerts"].extend(self.list_indices(pattern))

        # Log patterns
        log_patterns = ["logs-*", "*-logs-*", "logstash*"]
        for pattern in log_patterns:
            categories["logs"].extend(self.list_indices(pattern))

        # Observability patterns
        obs_patterns = ["metrics-*", "traces-*", "apm-*", "logs-apm*", "observability*"]
        for pattern in obs_patterns:
            categories["observability"].extend(self.list_indices(pattern))

        # Deduplicate
        for key in categories:
            categories[key] = sorted(set(categories[key]))

        return categories

    def execute(self, query: str, limit: int = 100) -> dict:
        """Execute an ES|QL query and return structured results."""
        # Remove existing LIMIT if present, add our own
        query_clean = re.sub(r'\s*\|\s*LIMIT\s+\d+', '', query, flags=re.IGNORECASE)
        if "LIMIT" not in query_clean.upper():
            query_clean = f"{query_clean} | LIMIT {limit}"

        url = f"{self.cloud_url}/_query?format=json"
        payload = {"query": query_clean}

        try:
            response = requests.post(url, headers=self._headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()

            columns = data.get("columns", [])
            if columns and isinstance(columns[0], dict):
                column_names = [c.get("name", str(i)) for i, c in enumerate(columns)]
            else:
                column_names = columns if columns else []

            rows = data.get("values", [])
            total = data.get("total", len(rows))
            took_ms = data.get("took", 0)

            return {
                "success": True,
                "query": query_clean,
                "columns": column_names,
                "rows": [dict(zip(column_names, row)) for row in rows],
                "total": total,
                "took_ms": took_ms,
            }
        except requests.HTTPError as e:
            error_detail = ""
            try:
                error_data = e.response.json()
                error_detail = error_data.get("error", {}).get("reason", str(error_data))
            except Exception:
                error_detail = str(e)
            return {
                "success": False,
                "query": query_clean,
                "error": type(e).__name__,
                "message": error_detail,
                "status_code": e.response.status_code if hasattr(e, 'response') else None,
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "query": query_clean,
                "error": type(e).__name__,
                "message": str(e),
            }


# ============================================================================
# Index Discovery & NL → ES|QL
# ============================================================================


def _time_filter(q: str) -> str:
    """Extract time range filter from natural language."""
    if "last hour" in q or "última hora" in q:
        return "@timestamp >= NOW() - 1h"
    elif "last 24" in q or "últimas 24" in q or "último día" in q:
        return "@timestamp >= NOW() - 1d"
    elif "last 7" in q or "última semana" in q or "últimos 7" in q:
        return "@timestamp >= NOW() - 7d"
    elif "today" in q or "hoy" in q:
        return "@timestamp >= NOW() - 1d"
    return ""


def _build_where_clause(parts: List[str]) -> str:
    """Build WHERE clause from list of conditions."""
    return f" | WHERE {' AND '.join(parts)}" if parts else ""


def _fleet_nl_to_esql(question: str, indices: List[str]) -> str:
    """Convert natural language to ES|QL for Fleet agents."""
    q = question.lower()

    time_part = _time_filter(q)
    status_filter = ""
    if "online" in q and "offline" not in q:
        status_filter = "agent.status == 'online'"
    elif "offline" in q:
        status_filter = "agent.status == 'offline'"

    parts = [p for p in [time_part, status_filter] if p]
    where_clause = _build_where_clause(parts)

    index_str = ",".join(indices) if indices else "fleet-agents-*,metrics-fleet*"
    return (
        f"FROM {index_str} "
        f"| SELECT agent.id, agent.name, agent.status, host.name, host.os.name, @timestamp"
        f"{where_clause}"
        f" | LIMIT 50"
    )


def _alerts_nl_to_esql(question: str, indices: List[str]) -> str:
    """Convert natural language to ES|QL for security alerts."""
    q = question.lower()

    time_part = _time_filter(q)

    severity_filter = ""
    if "critical" in q:
        severity_filter = "alert.severity == 'critical'"
    elif "high" in q and "critical" not in q:
        severity_filter = "alert.severity == 'high'"
    elif "medium" in q:
        severity_filter = "alert.severity == 'medium'"
    elif "low" in q:
        severity_filter = "alert.severity == 'low'"

    status_filter = ""
    if "open" in q or "active" in q:
        status_filter = "alert.status == 'active'"
    elif "closed" in q or "cerrada" in q:
        status_filter = "alert.status == 'closed'"
    elif "acknowledged" in q or "acknow" in q:
        status_filter = "alert.status == 'acknowledged'"

    if "false positive" in q or "falso positivo" in q:
        status_filter = "alert.status == 'closed'"

    parts = [p for p in [time_part, severity_filter, status_filter] if p]
    where_clause = _build_where_clause(parts)

    index_str = ",".join(indices) if indices else ".alerts-*,.siem-signals-*"
    return (
        f"FROM {index_str} "
        f"| SELECT alert.id, alert.rule.name, alert.severity, alert.status, kibana.alert.reason, @timestamp"
        f"{where_clause}"
        f" | LIMIT 50"
    )


def _logs_nl_to_esql(question: str, indices: List[str]) -> str:
    """Convert natural language to ES|QL for generic logs."""
    q = question.lower()

    time_part = _time_filter(q)

    keyword_filter = ""
    if "error" in q:
        keyword_filter = "MATCH(message, 'error')"
    elif "warning" in q or "warn" in q:
        keyword_filter = "MATCH(message, 'warning')"
    elif "fail" in q:
        keyword_filter = "MATCH(message, 'fail')"
    elif "timeout" in q:
        keyword_filter = "MATCH(message, 'timeout')"

    parts = [p for p in [time_part, keyword_filter] if p]
    where_clause = _build_where_clause(parts)

    index_str = ",".join(indices) if indices else "logs-*,*-logs-*"
    return (
        f"FROM {index_str} "
        f"| SELECT @timestamp, message, log.level, host.name"
        f"{where_clause}"
        f" | LIMIT 100"
    )


def _observability_nl_to_esql(question: str, indices: List[str]) -> str:
    """Convert natural language to ES|QL for APM/metrics/traces."""
    q = question.lower()

    time_part = _time_filter(q)

    apm_filter = ""
    if "error" in q:
        apm_filter = "event.outcome == 'failure'"
    elif "slow" in q or "lento" in q:
        apm_filter = "event.duration >= 1000"

    parts = [p for p in [time_part, apm_filter] if p]
    where_clause = _build_where_clause(parts)

    index_str = ",".join(indices) if indices else "metrics-*,traces-*,apm-*"
    return (
        f"FROM {index_str} "
        f"| SELECT @timestamp, service.name, service.environment, event.duration, event.outcome"
        f"{where_clause}"
        f" | LIMIT 50"
    )


# ============================================================================
# Tools Class
# ============================================================================


class Tools:
    """Elastic Security Data Tools for OpenWebUI."""

    class Valves(BaseModel):
        ELASTIC_CLOUD_URL: str = Field(
            default="",
            description="Elastic Cloud URL (e.g. https://your-deployment.es.region.cloud.es.io)"
        )
        ES_API_KEY: str = Field(
            default="",
            description="Elastic API key with read permissions"
        )

    def __init__(self):
        self.valves = self.Valves()

    def _get_client(self) -> ElasticClient:
        """Create ElasticClient from valves configuration."""
        return ElasticClient(
            cloud_url=self.valves.ELASTIC_CLOUD_URL,
            api_key=self.valves.ES_API_KEY,
        )

    async def elastic_index_discovery(
        self,
        __user__: Optional[dict] = None,
        __request__: Optional[Request] = None,
        __model__: Optional[dict] = None,
        __metadata__: Optional[dict] = None,
        __id__: Optional[str] = None,
        __event_emitter__: Optional[Callable[[dict], Any]] = None,
        __event_call__: Optional[Callable[[dict], Any]] = None,
        __chat_id__: Optional[str] = None,
        __message_id__: Optional[str] = None,
        __oauth_token__: Optional[dict] = None,
        __messages__: Optional[list] = None,
    ) -> str:
        """
        Discover available Elastic indices grouped by category (fleet, alerts, logs, observability).
        Use this to find out what indices are available in your Elastic deployment before running searches.
        Returns a list of indices for each category.
        Example: 'What indices do I have?' / 'Show me available Elastic indices'
        """
        if not __event_emitter__:
            return '{"error": "Tool context not available"}'

        try:
            await __event_emitter__({
                "type": "status",
                "data": {"description": "Discovering Elastic indices...", "done": False},
            })

            client = self._get_client()
            indices = client.discover_indices()

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Found {sum(len(v) for v in indices.values())} indices", "done": True},
            })

            return json.dumps({
                "success": True,
                "indices": indices,
                "summary": {
                    "fleet_count": len(indices.get("fleet", [])),
                    "alerts_count": len(indices.get("alerts", [])),
                    "logs_count": len(indices.get("logs", [])),
                    "observability_count": len(indices.get("observability", [])),
                }
            }, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({"success": False, "error": type(e).__name__, "message": str(e)})

    async def elastic_fleet_search(
        self,
        question: str,
        __user__: Optional[dict] = None,
        __request__: Optional[Request] = None,
        __model__: Optional[dict] = None,
        __metadata__: Optional[dict] = None,
        __id__: Optional[str] = None,
        __event_emitter__: Optional[Callable[[dict], Any]] = None,
        __event_call__: Optional[Callable[[dict], Any]] = None,
        __chat_id__: Optional[str] = None,
        __message_id__: Optional[str] = None,
        __oauth_token__: Optional[dict] = None,
        __messages__: Optional[list] = None,
    ) -> str:
        """
        Search Fleet agent metadata (status, health, enrolled agents).
        Use this when the user asks about fleet agents, endpoint status,
        agent health, or enrolled devices.
        Example: 'What fleet agents are online?' / 'Show me offline agents'
        """
        if not __event_emitter__:
            return '{"error": "Tool context not available"}'

        try:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Searching Fleet agents: {question[:50]}...", "done": False},
            })

            client = self._get_client()

            # Discover fleet indices first
            all_indices = client.discover_indices()
            fleet_indices = all_indices.get("fleet", [])

            if not fleet_indices:
                return json.dumps({
                    "success": False,
                    "error": "No fleet indices found",
                    "message": "No fleet-agents or metrics-fleet indices found in your deployment. Try elastic_index_discovery to see available indices."
                }, ensure_ascii=False, default=str)

            query = _fleet_nl_to_esql(question, fleet_indices)
            result = client.execute(query)

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Fleet search complete: {result.get('total', 0)} results", "done": True},
            })

            result["indices_used"] = fleet_indices
            return json.dumps(result, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({"success": False, "error": type(e).__name__, "message": str(e)})

    async def elastic_alerts_search(
        self,
        question: str,
        __user__: Optional[dict] = None,
        __request__: Optional[Request] = None,
        __model__: Optional[dict] = None,
        __metadata__: Optional[dict] = None,
        __id__: Optional[str] = None,
        __event_emitter__: Optional[Callable[[dict], Any]] = None,
        __event_call__: Optional[Callable[[dict], Any]] = None,
        __chat_id__: Optional[str] = None,
        __message_id__: Optional[str] = None,
        __oauth_token__: Optional[dict] = None,
        __messages__: Optional[list] = None,
    ) -> str:
        """
        Search security alerts and cases (severity, status, rule names, triage).
        Use this when the user asks about alerts, detections, security cases,
        true/false positives, or SIEM signals.
        Example: 'Show critical alerts from last 24h' / 'List open security cases'
        """
        if not __event_emitter__:
            return '{"error": "Tool context not available"}'

        try:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Searching security alerts: {question[:50]}...", "done": False},
            })

            client = self._get_client()

            # Discover alert indices first
            all_indices = client.discover_indices()
            alert_indices = all_indices.get("alerts", [])

            if not alert_indices:
                return json.dumps({
                    "success": False,
                    "error": "No alert indices found",
                    "message": "No alert indices (.alerts-*, *signals-*) found in your deployment. Try elastic_index_discovery to see available indices."
                }, ensure_ascii=False, default=str)

            query = _alerts_nl_to_esql(question, alert_indices)
            result = client.execute(query)

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Alerts search complete: {result.get('total', 0)} results", "done": True},
            })

            result["indices_used"] = alert_indices
            return json.dumps(result, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({"success": False, "error": type(e).__name__, "message": str(e)})

    async def elastic_logs_search(
        self,
        question: str,
        __user__: Optional[dict] = None,
        __request__: Optional[Request] = None,
        __model__: Optional[dict] = None,
        __metadata__: Optional[dict] = None,
        __id__: Optional[str] = None,
        __event_emitter__: Optional[Callable[[dict], Any]] = None,
        __event_call__: Optional[Callable[[dict], Any]] = None,
        __chat_id__: Optional[str] = None,
        __message_id__: Optional[str] = None,
        __oauth_token__: Optional[dict] = None,
        __messages__: Optional[list] = None,
    ) -> str:
        """
        Search generic logs (errors, warnings, authentication failures).
        Use this when the user asks about logs, error messages, authentication
        failures, or any textual log data.
        Example: 'Search for error messages in the last hour' / 'Show authentication failures'
        """
        if not __event_emitter__:
            return '{"error": "Tool context not available"}'

        try:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Searching logs: {question[:50]}...", "done": False},
            })

            client = self._get_client()

            # Discover log indices first
            all_indices = client.discover_indices()
            log_indices = all_indices.get("logs", [])

            if not log_indices:
                return json.dumps({
                    "success": False,
                    "error": "No log indices found",
                    "message": "No log indices (logs-*, *-logs-*) found in your deployment. Try elastic_index_discovery to see available indices."
                }, ensure_ascii=False, default=str)

            query = _logs_nl_to_esql(question, log_indices)
            result = client.execute(query)

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Logs search complete: {result.get('total', 0)} results", "done": True},
            })

            result["indices_used"] = log_indices
            return json.dumps(result, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({"success": False, "error": type(e).__name__, "message": str(e)})

    async def elastic_observability_search(
        self,
        question: str,
        __user__: Optional[dict] = None,
        __request__: Optional[Request] = None,
        __model__: Optional[dict] = None,
        __metadata__: Optional[dict] = None,
        __id__: Optional[str] = None,
        __event_emitter__: Optional[Callable[[dict], Any]] = None,
        __event_call__: Optional[Callable[[dict], Any]] = None,
        __chat_id__: Optional[str] = None,
        __message_id__: Optional[str] = None,
        __oauth_token__: Optional[dict] = None,
        __messages__: Optional[list] = None,
    ) -> str:
        """
        Search APM metrics, traces, and observability data.
        Use this when the user asks about APM, service performance, error rates,
        slow transactions, or metrics.
        Example: 'Show APM error rates by service' / 'What are the slowest transactions today?'
        """
        if not __event_emitter__:
            return '{"error": "Tool context not available"}'

        try:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Searching observability data: {question[:50]}...", "done": False},
            })

            client = self._get_client()

            # Discover observability indices first
            all_indices = client.discover_indices()
            obs_indices = all_indices.get("observability", [])

            if not obs_indices:
                return json.dumps({
                    "success": False,
                    "error": "No observability indices found",
                    "message": "No observability indices (metrics-*, traces-*, apm-*) found in your deployment. Try elastic_index_discovery to see available indices."
                }, ensure_ascii=False, default=str)

            query = _observability_nl_to_esql(question, obs_indices)
            result = client.execute(query)

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Observability search complete: {result.get('total', 0)} results", "done": True},
            })

            result["indices_used"] = obs_indices
            return json.dumps(result, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({"success": False, "error": type(e).__name__, "message": str(e)})