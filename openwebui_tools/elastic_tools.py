"""
title: Elastic Security Data Tools
author: federico
version: 0.1.0
license: MIT
required_open_webui_version: 0.7.0
description: Query Elastic Security data (Fleet agents, alerts, logs, observability) via natural language.
              Uses ES|QL to search .alerts-*, fleet-agents-*, logs-*, metrics-*, traces-*, apm-* indices.
              Each tool accepts a natural language question and returns structured JSON results.
"""

import json
import requests
from typing import Optional, Callable, Any

from fastapi import Request
from pydantic import BaseModel, Field


# ============================================================================
# Shared Elastic Client
# ============================================================================


class ElasticClient:
    """Executes ES|QL queries against Elastic Cloud."""

    def __init__(self, cloud_url: str, api_key: str):
        self.cloud_url = cloud_url
        self.api_key = api_key
        if not self.cloud_url or not self.api_key:
            raise ValueError("ELASTIC_CLOUD_URL and ES_API_KEY must be set via Valves")

    def execute(self, query: str, index_pattern: Optional[str] = None, limit: int = 100) -> dict:
        """Execute an ES|QL query and return structured results."""
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


# ============================================================================
# NL → ES|QL Converters
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


def _fleet_nl_to_esql(question: str) -> str:
    """Convert natural language to ES|QL for Fleet agents."""
    q = question.lower()

    time_part = _time_filter(q)
    status_filter = ""
    if "online" in q and "offline" not in q:
        status_filter = "agent.status == 'online'"
    elif "offline" in q:
        status_filter = "agent.status == 'offline'"

    parts = [p for p in [time_part, status_filter] if p]
    where_clause = f" | WHERE {' AND '.join(parts)}" if parts else ""

    return (
        f"FROM fleet-agents-*,metrics-fleet.agent-default-* "
        f"| SELECT agent.id, agent.name, agent.status, host.name, host.os.name, @timestamp"
        f"{where_clause}"
        f" | LIMIT 50"
    )


def _alerts_nl_to_esql(question: str) -> str:
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
    where_clause = f" | WHERE {' AND '.join(parts)}" if parts else ""

    return (
        f"FROM .alerts-security.alerts-*,.siem-signals-default-* "
        f"| SELECT alert.id, alert.rule.name, alert.severity, alert.status, kibana.alert.reason, @timestamp"
        f"{where_clause}"
        f" | LIMIT 50"
    )


def _logs_nl_to_esql(question: str) -> str:
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
    where_clause = f" | WHERE {' AND '.join(parts)}" if parts else ""

    return (
        f"FROM logs-*,*-logs-*,logs-generic-default-* "
        f"| SELECT @timestamp, message, log.level, host.name"
        f"{where_clause}"
        f" | LIMIT 100"
    )


def _observability_nl_to_esql(question: str) -> str:
    """Convert natural language to ES|QL for APM/metrics/traces."""
    q = question.lower()

    time_part = _time_filter(q)

    apm_filter = ""
    if "error" in q:
        apm_filter = "event.outcome == 'failure'"
    elif "slow" in q or "lento" in q:
        apm_filter = "event.duration >= 1000"

    parts = [p for p in [time_part, apm_filter] if p]
    where_clause = f" | WHERE {' AND '.join(parts)}" if parts else ""

    return (
        f"FROM metrics-*,traces-*,apm-*,logs-apm-* "
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
            query = _fleet_nl_to_esql(question)
            result = client.execute(query)

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Fleet search complete: {result.get('total', 0)} results", "done": True},
            })

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
            query = _alerts_nl_to_esql(question)
            result = client.execute(query)

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Alerts search complete: {result.get('total', 0)} results", "done": True},
            })

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
            query = _logs_nl_to_esql(question)
            result = client.execute(query)

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Logs search complete: {result.get('total', 0)} results", "done": True},
            })

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
            query = _observability_nl_to_esql(question)
            result = client.execute(query)

            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Observability search complete: {result.get('total', 0)} results", "done": True},
            })

            return json.dumps(result, ensure_ascii=False, default=str)

        except Exception as e:
            return json.dumps({"success": False, "error": type(e).__name__, "message": str(e)})