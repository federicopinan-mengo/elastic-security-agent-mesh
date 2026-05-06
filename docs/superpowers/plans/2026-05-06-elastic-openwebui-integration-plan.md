# Elastic + OpenWebUI Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create Python tools that allow OpenWebUI to query Elastic data (Fleet, alerts, logs, observability) via natural language using ES|QL.

**Architecture:** Domain-specific tools (fleet, alerts, logs, observability) share a common `ElasticClient` that handles ES|QL generation and execution. Each tool receives a natural language question, builds an ES|QL query using its schema context, and returns structured JSON.

**Tech Stack:** Python 3.11+, `requests` library, `python-dotenv` for env vars, ES|QL for query execution.

---

## File Structure

```
.agents/skills/openwebui/
├── elastic_client/
│   └── client.py              # Shared ES|QL execution
├── elastic_fleet_search/
│   └── fleet_search.py       # Fleet agent queries
├── elastic_alerts_search/
│   └── alerts_search.py      # Security alert queries
├── elastic_logs_search/
│   └── logs_search.py         # Generic log queries
└── elastic_observability_search/
    └── observability_search.py # APM/metrics/traces queries
```

Each tool is a standalone Python module with a `search(question: str) -> dict` function that OpenWebUI can call.

---

## Task 1: Create `elastic_client` Module

**Files:**
- Create: `.agents/skills/openwebui/elastic_client/__init__.py`
- Create: `.agents/skills/openwebui/elastic_client/client.py`
- Create: `.agents/skills/openwebui/elastic_client/pyproject.toml`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p .agents/skills/openwebui/elastic_client
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "elastic-client"
version = "0.1.0"
description = "Shared Elastic ES|QL client for OpenWebUI tools"
requires-python = ">=3.11"
dependencies = [
    "requests>=2.31.0",
    "python-dotenv>=1.0.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0.0", "pytest-asyncio>=0.23.0"]
```

- [ ] **Step 3: Write `__init__.py`**

```python
from .client import ElasticClient

__all__ = ["ElasticClient"]
```

- [ ] **Step 4: Write `client.py`**

```python
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
```

- [ ] **Step 5: Commit**

```bash
git add .agents/skills/openwebui/elastic_client/
git commit -m "feat(openwebui): add elastic_client module for ES|QL execution"
```

---

## Task 2: Create `elastic_fleet_search` Tool

**Files:**
- Create: `.agents/skills/openwebui/elastic_fleet_search/__init__.py`
- Create: `.agents/skills/openwebui/elastic_fleet_search/fleet_search.py`
- Create: `.agents/skills/openwebui/elastic_fleet_search/pyproject.toml`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p .agents/skills/openwebui/elastic_fleet_search
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "elastic-fleet-search"
version = "0.1.0"
description = "Fleet agent search tool for OpenWebUI"
requires-python = ">=3.11"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8.0.0"]
```

- [ ] **Step 3: Write `__init__.py`**

```python
from .fleet_search import ElasticFleetSearch

__all__ = ["ElasticFleetSearch"]
```

- [ ] **Step 4: Write `fleet_search.py`**

```python
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
```

- [ ] **Step 5: Commit**

```bash
git add .agents/skills/openwebui/elastic_fleet_search/
git commit -m "feat(openwebui): add elastic_fleet_search tool"
```

---

## Task 3: Create `elastic_alerts_search` Tool

**Files:**
- Create: `.agents/skills/openwebui/elastic_alerts_search/__init__.py`
- Create: `.agents/skills/openwebui/elastic_alerts_search/alerts_search.py`
- Create: `.agents/skills/openwebui/elastic_alerts_search/pyproject.toml`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p .agents/skills/openwebui/elastic_alerts_search
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "elastic-alerts-search"
version = "0.1.0"
description = "Security alerts search tool for OpenWebUI"
requires-python = ">=3.11"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8.0.0"]
```

- [ ] **Step 3: Write `__init__.py`**

```python
from .alerts_search import ElasticAlertsSearch

__all__ = ["ElasticAlertsSearch"]
```

- [ ] **Step 4: Write `alerts_search.py`**

```python
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
```

- [ ] **Step 5: Commit**

```bash
git add .agents/skills/openwebui/elastic_alerts_search/
git commit -m "feat(openwebui): add elastic_alerts_search tool"
```

---

## Task 4: Create `elastic_logs_search` Tool

**Files:**
- Create: `.agents/skills/openwebui/elastic_logs_search/__init__.py`
- Create: `.agents/skills/openwebui/elastic_logs_search/logs_search.py`
- Create: `.agents/skills/openwebui/elastic_logs_search/pyproject.toml`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p .agents/skills/openwebui/elastic_logs_search
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "elastic-logs-search"
version = "0.1.0"
description = "Generic log search tool for OpenWebUI"
requires-python = ">=3.11"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8.0.0"]
```

- [ ] **Step 3: Write `__init__.py`**

```python
from .logs_search import ElasticLogsSearch

__all__ = ["ElasticLogsSearch"]
```

- [ ] **Step 4: Write `logs_search.py`**

```python
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
            time_filter = "WHERE @timestamp >= NOW() - 1h"
        elif "last 24" in q or "últimas 24" in q or "último día" in q:
            time_filter = "WHERE @timestamp >= NOW() - 1d"
        elif "last 7" in q or "última semana" in q or "últimos 7" in q:
            time_filter = "WHERE @timestamp >= NOW() - 7d"
        elif "today" in q or "hoy" in q:
            time_filter = "WHERE @timestamp >= NOW() - 1d"

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
```

- [ ] **Step 5: Commit**

```bash
git add .agents/skills/openwebui/elastic_logs_search/
git commit -m "feat(openwebui): add elastic_logs_search tool"
```

---

## Task 5: Create `elastic_observability_search` Tool

**Files:**
- Create: `.agents/skills/openwebui/elastic_observability_search/__init__.py`
- Create: `.agents/skills/openwebui/elastic_observability_search/observability_search.py`
- Create: `.agents/skills/openwebui/elastic_observability_search/pyproject.toml`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p .agents/skills/openwebui/elastic_observability_search
```

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "elastic-observability-search"
version = "0.1.0"
description = "Observability metrics and APM search for OpenWebUI"
requires-python = ">=3.11"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8.0.0"]
```

- [ ] **Step 3: Write `__init__.py`**

```python
from .observability_search import ElasticObservabilitySearch

__all__ = ["ElasticObservabilitySearch"]
```

- [ ] **Step 4: Write `observability_search.py`**

```python
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "elastic_client"))
from client import ElasticClient


INDEX_PATTERNS = ["metrics-*", "traces-*", "apm-*", "logs-apm-*"]


class ElasticObservabilitySearch:
    """Search APM, metrics, and traces from Elastic."""

    def __init__(self):
        self.client = ElasticClient()
        self.index_patterns = INDEX_PATTERNS

    def _nl_to_esql(self, question: str) -> str:
        """Convert natural language to ES|QL for observability data."""
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

        # APM-specific filters
        apm_filter = ""
        if "error" in q:
            apm_filter = "event.outcome == 'failure'"
        elif "slow" in q or "lento" in q:
            apm_filter = "event.duration >= 1000"

        base_select = "@timestamp, service.name, service.environment, event.duration, event.outcome"

        where_parts = [p for p in [time_filter, apm_filter] if p]
        where_clause = ""
        if where_parts:
            where_clause = " | WHERE " + " AND ".join(where_parts)

        query = f"FROM {','.join(self.index_patterns)} | {base_select}{where_clause} | LIMIT 50"
        return query

    def search(self, question: str) -> dict:
        """Execute observability search based on natural language question."""
        query = self._nl_to_esql(question)
        return self.client.execute(query=query)
```

- [ ] **Step 5: Commit**

```bash
git add .agents/skills/openwebui/elastic_observability_search/
git commit -m "feat(openwebui): add elastic_observability_search tool"
```

---

## Task 6: Register Tools in OpenWebUI

**Files:**
- Create: `.agents/skills/openwebui/README.md` (setup instructions)

- [ ] **Step 1: Write OpenWebUI README with registration instructions**

```markdown
# OpenWebUI Elastic Tools

Tools to query Elastic data from OpenWebUI chat interface.

## Available Tools

- `elastic_fleet_search` — Fleet agent metadata and health
- `elastic_alerts_search` — Security alerts and cases
- `elastic_logs_search` — Generic log search
- `elastic_observability_search` — APM, metrics, traces

## Setup

1. Set environment variables:
```bash
export ELASTIC_CLOUD_URL=https://your-deployment.es.region.cloud.es.io
export ES_API_KEY=your_read_only_api_key
```

2. Register each tool in OpenWebUI Admin Panel → Tools

3. Each tool exposes a `search(question: str)` function

## Testing

```python
from elastic_fleet_search import ElasticFleetSearch

tool = ElasticFleetSearch()
result = tool.search("What fleet agents are online?")
print(result)
```
```

- [ ] **Step 2: Commit**

```bash
git add .agents/skills/openwebui/README.md
git commit -m "docs(openwebui): add setup instructions for OpenWebUI tools"
```

---

## Spec Coverage Check

| Spec Section | Task |
|-------------|------|
| Architecture (folder structure) | Task 1-5 |
| elastic_client module | Task 1 |
| elastic_fleet_search tool | Task 2 |
| elastic_alerts_search tool | Task 3 |
| elastic_logs_search tool | Task 4 |
| elastic_observability_search tool | Task 5 |
| Output JSON format | All tasks (client.py returns this format) |
| OpenWebUI registration | Task 6 |

---

## Self-Review

- All tasks have complete code — no placeholders
- File paths are exact
- Each task has commit message
- Spec coverage is complete
- No TODO/TBD in plan