# Elastic + OpenWebUI Integration Design

## Context

User wants to use OpenWebUI as a unified chat interface to query Elastic data (Fleet agents, security alerts, logs, observability metrics) in natural language. The LLM decides which tool to invoke and constructs the ES|QL query dynamically based on the user's question.

## Architecture

```
OpenWebUI (chat interface)
    │
    ├── elastic_fleet_search/         # Fleet agents metadata
    │   └── fleet_search.py
    ├── elastic_alerts_search/        # Security alerts & cases
    │   └── alerts_search.py
    ├── elastic_logs_search/         # Generic log search
    │   └── logs_search.py
    ├── elastic_observability_search/ # APM, metrics, traces
    │   └── observability_search.py
    └── elastic_client/               # Shared ES|QL execution
        └── client.py
```

## Tool Specification

### Shared: `elastic_client`

**Purpose:** Centralized ES|QL execution for all domain tools.

**Capabilities:**
- Accept natural language question + index context
- Infer ES|QL query from question
- Execute against Elastic Cloud
- Return structured JSON results

**Environment Variables Required:**
- `ELASTIC_CLOUD_URL` — Elasticsearch endpoint
- `ES_API_KEY` — API key with read permissions

### Domain Tool: `elastic_fleet_search`

**Index patterns:** `fleet-agents-*`, `metrics-fleet*`

**Schema context:**
- `agent.id` — Agent ID
- `agent.name` — Agent name
- `agent.status` — online/offline/unknown
- `agent.type` — endpoint/fleet-server
- `host.name` — Hostname
- `host.os.name` — OS name
- `host.ip` — Host IP addresses
- `@timestamp` — Event timestamp

**Example queries it should handle:**
- "What fleet agents are online?"
- "Show me agents with high CPU usage"
- "List all endpoint agents last seen in the last hour"

### Domain Tool: `elastic_alerts_search`

**Index patterns:** `.alerts-*`, `.siem-signals-*`, `security-case-*`

**Schema context:**
- `alert.id` — Alert ID
- `alert.rule.name` — Rule name
- `alert.severity` — critical/high/medium/low
- `alert.status` — active/acknowledged/closed
- `kibana.alert.reason` — Alert reason
- `signal.original_time` — Original event time
- `cases.id` — Case ID
- `cases.status` — Case status

**Example queries:**
- "Show me critical alerts from the last 24 hours"
- "What false positives have been flagged this week?"
- "List open security cases"

### Domain Tool: `elastic_logs_search`

**Index patterns:** `logs-*`, `*-logs-*`

**Schema context:** Dynamic — logs vary by source. Tool should use `FROM <index> | LIMIT 100` and allow flexibility.

**Example queries:**
- "Search for error messages in the last hour"
- "Show me authentication failures"
- "Find logs containing 'connection timeout'"

### Domain Tool: `elastic_observability_search`

**Index patterns:** `metrics-*`, `traces-*`, `apm-*`, `logs-apm-*`

**Schema context:**
- `service.name` — Service name
- `service.environment` — Environment (production/staging)
- `metric.samples.*.value` — Metric values
- `trace.id` — Trace ID
- `transaction.name` — Transaction name
- `event.duration` — Duration in ms

**Example queries:**
- "Show APM error rates by service"
- "What are the slowest transactions today?"
- "Display CPU metrics for the last 6 hours"

## Output Format

All tools return JSON:

```json
{
  "success": true,
  "query": "FROM fleet-agents-* | WHERE agent.status == 'online' | LIMIT 50",
  "columns": ["agent.id", "agent.name", "host.name"],
  "rows": [
    {"agent.id": "abc123", "agent.name": "workstation-1", "host.name": "John's MacBook"},
    ...
  ],
  "total": 150,
  "took_ms": 45
}
```

On error:
```json
{
  "success": false,
  "error": "IndexNotFoundException",
  "message": "No matching index found for pattern 'fake-*'"
}
```

## Tool Implementation Pattern

Each domain tool follows this pattern:

```python
from elatic_client import ElasticClient

class ElasticFleetSearch:
    def __init__(self):
        self.client = ElasticClient()
        self.index_patterns = ["fleet-agents-*", "metrics-fleet*"]
        self.schema_fields = {
            "agent.id": "Agent unique identifier",
            "agent.name": "Agent display name",
            "agent.status": "online|offline|unknown",
            "host.name": "Hostname",
            "host.os.name": "Operating system name",
            "host.ip": "Host IP addresses (array)",
            "@timestamp": "Event timestamp"
        }

    def search(self, question: str) -> dict:
        # 1. Build ES|QL from question + schema context
        query = self._nl_to_esql(question)

        # 2. Execute
        result = self.client.execute(
            index=",".join(self.index_patterns),
            query=query
        )

        # 3. Return structured JSON
        return result
```

## Testing Strategy

- Unit test: `_nl_to_esql()` parsing for each domain
- Integration test: Execute against live Elastic Cloud
- Edge cases: Empty results, index not found, query timeout

## Next Steps

1. Create `elastic_client.py` shared module
2. Implement `elastic_fleet_search.py` as first domain tool
3. Implement remaining domain tools
4. Register tools in OpenWebUI
5. Test with sample questions

## Files to Create

```
.agents/skills/openwebui/
├── elastic_client/
│   └── client.py
├── elastic_fleet_search/
│   └── fleet_search.py
├── elastic_alerts_search/
│   └── alerts_search.py
├── elastic_logs_search/
│   └── logs_search.py
└── elastic_observability_search/
    └── observability_search.py
```