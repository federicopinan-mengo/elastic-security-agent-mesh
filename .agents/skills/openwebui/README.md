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