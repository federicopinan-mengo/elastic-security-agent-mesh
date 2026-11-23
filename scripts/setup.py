#!/usr/bin/env python3
"""
Elastic Security Agent Mesh — Setup Script

Automates the deployment of indices, workflows, and agent registrations
to an Elastic Cloud deployment. Reads configuration from environment variables.

Set required variables before running (see README.md for full instructions):
    export ELASTIC_CLOUD_URL=https://your-deployment.es.region.gcp.cloud.es.io
    export KIBANA_URL=https://your-deployment.kb.region.gcp.cloud.es.io
    export ES_API_KEY=your-es-api-key
    export KIBANA_API_KEY=your-kibana-api-key

Or authenticate with a user and a password instead of an API key:
    export ES_USERNAME=your-es-user
    export ES_PASSWORD=your-es-password
    export KIBANA_USERNAME=your-kibana-user
    export KIBANA_PASSWORD=your-kibana-password

Usage:
    python scripts/setup.py                    # Run full setup (indices → policies → workflows → tools → agents → registry)
    python scripts/setup.py --indices-only     # Only create indices
    python scripts/setup.py --workflows-only   # Only import workflows
    python scripts/setup.py --seed-policies    # Only seed action policies
    python scripts/setup.py --tools-only       # Only create tools (requires workflows already imported)
    python scripts/setup.py --agents-only      # Only create agents (requires tools already created)
    python scripts/setup.py --delete-workflows # delete the workflows this repo owns (add --yes to act)
    python scripts/setup.py --delete-all       # Delete agents + tools + workflows, then full re-deploy
    python scripts/setup.py --validate         # Validate env vars without deploying

Workflow YAML is imported verbatim without credential substitution. Credentials
come from the Elasticsearch/Kibana execution context for native
elasticsearch.request and kibana.request steps, or from Kibana connectors.
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print(
        "ERROR: 'requests' package required. Install with: pip install requests pyyaml python-dotenv"
    )
    sys.exit(1)

try:
    import yaml
except ImportError:
    print(
        "ERROR: 'pyyaml' package required. Install with: pip install requests pyyaml python-dotenv"
    )
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    print(
        "ERROR: 'python-dotenv' package required. Install with: pip install requests pyyaml python-dotenv"
    )
    sys.exit(1)

from auth import auth_header, auth_mode

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_ENV_VARS = ["ELASTIC_CLOUD_URL", "KIBANA_URL"]

# Each target authenticates with an API key or with a user and a password.
AUTH_TARGETS = [
    ("Elasticsearch", "ES_API_KEY", "ES_USERNAME", "ES_PASSWORD"),
    ("Kibana", "KIBANA_API_KEY", "KIBANA_USERNAME", "KIBANA_PASSWORD"),
]

ALERT_CONTEXT_PROFILE = "bounded-alert-context-v1"
ALERT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
ALERT_CONTEXT_FIELDS = (
    "_id",
    "@timestamp",
    "kibana.alert.workflow_status",
    "kibana.alert.rule.name",
    "kibana.alert.severity",
    "kibana.alert.risk_score",
    "kibana.alert.reason",
    "agent.id",
    "host.name",
    "user.name",
)
ALERT_CONTEXT_QUERY = "\n".join(
    (
        "FROM .alerts-security.alerts-* METADATA _id",
        '| WHERE _id == ?alert_id AND ?alert_id RLIKE "^[A-Za-z0-9_-]{1,512}$"',
        "| WHERE @timestamp >= NOW() - 7 days AND @timestamp <= NOW()",
        f"| KEEP {', '.join(ALERT_CONTEXT_FIELDS)}",
        "| LIMIT 1",
    )
)


AlertContextConfigurationError = ValueError


def load_project_env():
    """Load repository configuration without overriding shell or CI values."""
    return load_dotenv(dotenv_path=REPO_ROOT / ".env", override=False)


def validate_alert_context_params(params):
    alert_id = (
        params.get("alert_id") if isinstance(params, dict) and set(params) == {"alert_id"} else None
    )
    if not isinstance(alert_id, str) or not ALERT_ID_PATTERN.fullmatch(alert_id):
        raise AlertContextConfigurationError("alert_id must match ^[A-Za-z0-9_-]{1,512}$")
    return alert_id


def build_alert_context_tool(tool_definition):
    """Build the sole immutable Agent Builder ES|QL tool payload."""
    if tool_definition != {"name": "Bounded Alert Context", "profile": ALERT_CONTEXT_PROFILE}:
        raise AlertContextConfigurationError("bounded alert context profile must not be overridden")
    return {
        "id": slugify(tool_definition["name"]),
        "type": "esql",
        "description": "Read one alert by alert_id matching ^[A-Za-z0-9_-]{1,512}$.",
        "tags": ["security-mesh"],
        "configuration": {
            "query": ALERT_CONTEXT_QUERY,
            "params": {"alert_id": {"type": "string", "description": "Bounded alert ID."}},
        },
    }


def validate_alert_context_schema():
    """Fail closed unless the complete fixed ES|QL profile is schema-compatible."""
    es_url, headers = os.environ["ELASTIC_CLOUD_URL"].rstrip("/"), es_headers()
    resolved = requests.get(
        f"{es_url}/_resolve/index/.alerts-security.alerts-*",
        headers=headers,
        params={"expand_wildcards": "all"},
        timeout=30,
    )
    if not resolved.ok or not any(
        resolved.json().get(key) for key in ("indices", "aliases", "data_streams")
    ):
        raise AlertContextConfigurationError("alert-context index scope is absent or unresolved")
    field_caps = requests.get(
        f"{es_url}/.alerts-security.alerts-*/_field_caps",
        headers=headers,
        params={"fields": ",".join(ALERT_CONTEXT_FIELDS[1:]), "include_unmapped": "true"},
        timeout=30,
    )
    fields = field_caps.json().get("fields", {}) if field_caps.ok else {}
    for field in ALERT_CONTEXT_FIELDS[1:]:
        capabilities = fields.get(field)
        if not isinstance(capabilities, dict) or len(capabilities) != 1:
            raise AlertContextConfigurationError(
                f"alert-context field is missing or ambiguous: {field}"
            )
        capability = next(iter(capabilities.values()))
        if (
            not isinstance(capability, dict)
            or not capability.get("searchable")
            or capability.get("non_searchable_indices")
        ):
            raise AlertContextConfigurationError(f"alert-context field is incompatible: {field}")
    compiled = requests.post(
        f"{es_url}/_query",
        headers=headers,
        json={"query": ALERT_CONTEXT_QUERY, "params": [{"alert_id": "schema-gate"}]},
        timeout=30,
    )
    if not compiled.ok:
        raise AlertContextConfigurationError("immutable alert-context ES|QL query did not compile")


# kb-compliance excluded — uses compliance_mapping() (nested controls) instead of generic KB mapping
KNOWLEDGE_BASE_INDICES = [
    "kb-detection-rules",
    "kb-ecs-schema",
    "kb-mitre-attack",
    "kb-threat-intel",
    "kb-ioc-history",
    "kb-incidents",
    "kb-playbooks",
    "kb-forensics",
    "kb-soc-ops",
    "kb-runbooks",
]

WORKFLOW_DIRS = [
    "agents/setup",
    "workflows/ai-agents",
    "workflows/compliance",
    "workflows/feedback",
    "workflows/governance",
    "workflows/investigation",
    "workflows/knowledge",
    "workflows/mesh",
    "workflows/observability",
    "workflows/search",
    "workflows/security/detection",
    "workflows/security/enrichment",
    "workflows/security/response",
    "workflows/utilities",
]

MESH_TAG = "oputils-mesh"

# Third-party enrichment connectors referenced by the workflows (connector-id).
# The API key lives in Kibana (connector secret), never in the workflow YAML.
CONNECTOR_SPECS = (
    {
        "id": "oputils-virustotal",
        "name": "VirusTotal",
        "url": "https://www.virustotal.com/api/v3",
        "secret_header": "x-apikey",
        "env_var": "VIRUSTOTAL_API_KEY",
    },
    {
        "id": "oputils-abuseipdb",
        "name": "AbuseIPDB",
        "url": "https://api.abuseipdb.com/api/v2",
        "secret_header": "Key",
        "env_var": "ABUSEIPDB_API_KEY",
    },
)


def validate_env():
    """Check that all required environment variables are set."""
    missing = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v)]
    for _label, api_key_var, user_var, password_var in AUTH_TARGETS:
        if auth_mode(api_key_var, user_var, password_var) == "not configured":
            missing.append(f"{api_key_var} or {user_var} and {password_var}")
    if missing:
        print("ERROR: Missing required environment variables:")
        for v in missing:
            print(f"  - {v}")
        print()
        print("Set these variables before running setup. See README.md for instructions.")
        sys.exit(1)

    print("Environment validated:")
    print(f"  Elasticsearch: {os.environ['ELASTIC_CLOUD_URL']}")
    print(f"  Kibana:        {os.environ['KIBANA_URL']}")
    for label, api_key_var, user_var, password_var in AUTH_TARGETS:
        print(f"  {label} auth: {auth_mode(api_key_var, user_var, password_var)}")
    print("  Space:         default (hardcoded)")
    print()


def es_headers():
    return {
        "Content-Type": "application/json",
        "Authorization": auth_header("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD"),
    }


def kibana_headers():
    return {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "x-elastic-internal-origin": "Kibana",
        "Authorization": auth_header("KIBANA_API_KEY", "KIBANA_USERNAME", "KIBANA_PASSWORD"),
    }


def kibana_base_url():
    return os.environ["KIBANA_URL"].rstrip("/")


def _connector_manual_hint(spec):
    """One-line manual instruction for a connector setup.py could not create."""
    return (
        "create it manually in Kibana "
        f"(Stack Management > Connectors > Create connector > HTTP, "
        f"base url {spec['url']}, secret header {spec['secret_header']})"
    )


def _provision_connector(spec, base_url, headers, existing):
    """Create or update one connector. Returns True when Kibana accepted it."""
    key = os.environ.get(spec["env_var"], "").strip()
    if not key:
        print(f"  [WARN] {spec['env_var']} is not set — skipping connector '{spec['id']}'")
        return False

    body = {
        "name": spec["name"],
        "connector_type_id": ".http",
        "config": {"url": spec["url"]},
        "secrets": {"secretHeaders": {spec["secret_header"]: key}},
    }
    url = f"{base_url}/api/actions/connector/{spec['id']}"
    already_there = any(
        c.get("id") == spec["id"] or c.get("name") == spec["name"] for c in existing
    )

    try:
        if already_there:
            resp = requests.put(url, headers=headers, json=body, timeout=30)
        else:
            resp = requests.post(url, headers=headers, json=body, timeout=30)
    except requests.RequestException as exc:
        print(f"  [WARN] Connector '{spec['id']}' request failed ({exc})")
        print(f"         {_connector_manual_hint(spec)}")
        return False

    if not resp.ok:
        print(f"  [WARN] Connector '{spec['id']}' failed: HTTP {resp.status_code}")
        print(f"         {_connector_manual_hint(spec)}")
        return False

    action = "updated" if already_there else "created"
    print(f"  [{action}] connector {spec['id']}")
    return True


def ensure_connectors():
    """Provision the third-party enrichment connectors the workflows reference.

    Best-effort by design: a missing API key or a failing Kibana call only
    warns, so a connector problem never aborts the deploy of indices,
    workflows, tools or agents. The API key is never printed.
    """
    if not os.environ.get("KIBANA_URL"):
        print("  [WARN] KIBANA_URL is not set — skipping connector provisioning")
        return []

    try:
        base_url = kibana_base_url()
        headers = kibana_headers()
    except KeyError as exc:
        print(f"  [WARN] {exc.args[0]} is not set — skipping connector provisioning")
        return []
    except RuntimeError as exc:
        print(f"  [WARN] {exc} — skipping connector provisioning")
        return []

    try:
        listing = requests.get(f"{base_url}/api/actions/connectors", headers=headers, timeout=30)
        if not listing.ok:
            raise RuntimeError(f"HTTP {listing.status_code}")
        payload = listing.json()
    except (requests.RequestException, RuntimeError, ValueError) as exc:
        print(f"  [WARN] Could not list Kibana connectors ({exc}); skipping connector provisioning")
        for spec in CONNECTOR_SPECS:
            print(f"         {spec['id']}: {_connector_manual_hint(spec)}")
        return []

    if isinstance(payload, dict):
        payload = payload.get("data", payload.get("connectors", []))
    existing = [c for c in payload if isinstance(c, dict)] if isinstance(payload, list) else []

    ensured = []
    for spec in CONNECTOR_SPECS:
        if _provision_connector(spec, base_url, headers, existing):
            ensured.append(spec["id"])

    return ensured


def index_exists(index_name):
    url = f"{os.environ['ELASTIC_CLOUD_URL']}/{index_name}"
    resp = requests.head(url, headers=es_headers(), timeout=15)
    return resp.status_code == 200


def create_index(index_name, mapping_body):
    if index_exists(index_name):
        print(f"  [skip] {index_name} already exists")
        return True

    url = f"{os.environ['ELASTIC_CLOUD_URL']}/{index_name}"
    resp = requests.put(url, headers=es_headers(), json=mapping_body, timeout=30)
    if resp.ok:
        print(f"  [created] {index_name}")
        return True
    else:
        print(f"  [FAILED] {index_name}: {resp.status_code} — {resp.text[:200]}")
        return False


def knowledge_base_mapping():
    inference_id = os.environ.get("INFERENCE_ENDPOINT_ID", ".multilingual-e5-small-elasticsearch")
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "title": {"type": "text"},
                "content": {"type": "text"},
                "semantic_summary": {
                    "type": "semantic_text",
                    "inference_id": inference_id,
                },
                "category": {"type": "keyword"},
                "source": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"},
                "expires_at": {"type": "date"},
                "metadata": {"type": "object", "dynamic": True},
            }
        },
    }


def agent_registry_mapping():
    inference_id = os.environ.get("INFERENCE_ENDPOINT_ID", ".multilingual-e5-small-elasticsearch")
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "agent_id": {"type": "keyword"},
                "agent_name": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword"}},
                },
                "domain": {"type": "keyword"},
                "capabilities": {"type": "keyword"},
                "description": {"type": "text"},
                "semantic_description": {
                    "type": "semantic_text",
                    "inference_id": inference_id,
                },
                "keywords": {"type": "keyword"},
                "status": {"type": "keyword"},
                "version": {"type": "keyword"},
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"},
            }
        },
    }


def investigation_contexts_mapping():
    inference_id = os.environ.get("INFERENCE_ENDPOINT_ID", ".multilingual-e5-small-elasticsearch")
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "investigation_id": {"type": "keyword"},
                "trigger_type": {"type": "keyword"},
                "trigger_ref": {"type": "keyword"},
                "status": {"type": "keyword"},
                "risk_tier": {"type": "keyword"},
                "assigned_agent": {"type": "keyword"},
                "title": {"type": "text"},
                "summary": {"type": "text"},
                "semantic_summary": {
                    "type": "semantic_text",
                    "inference_id": inference_id,
                },
                "evidence": {
                    "type": "nested",
                    "properties": {
                        "agent_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "evidence_type": {"type": "keyword"},
                        "content": {"type": "text"},
                        "confidence": {"type": "float"},
                        "references": {"type": "keyword"},
                    },
                },
                "actions_taken": {
                    "type": "nested",
                    "properties": {
                        "agent_id": {"type": "keyword"},
                        "action_type": {"type": "keyword"},
                        "target": {"type": "text"},
                        "timestamp": {"type": "date"},
                        "approved_by": {"type": "keyword"},
                        "result": {"type": "text"},
                        "risk_tier": {"type": "keyword"},
                    },
                },
                "pending_actions": {
                    "type": "nested",
                    "properties": {
                        "recommending_agent": {"type": "keyword"},
                        "action_type": {"type": "keyword"},
                        "risk_tier": {"type": "keyword"},
                        "justification": {"type": "text"},
                        "evidence_refs": {"type": "keyword"},
                    },
                },
                "l1_result": {
                    "type": "object",
                    "dynamic": "strict",
                    "properties": {
                        "schema_version": {"type": "keyword"},
                        "investigation_id": {"type": "keyword"},
                        "decision": {"type": "keyword"},
                        "summary": {"type": "text"},
                        "evidence_refs": {"type": "keyword"},
                        "observed_at": {"type": "date"},
                        "recorded_at": {"type": "date"},
                        "source_agent": {"type": "keyword"},
                        "target_agent": {"type": "keyword"},
                        "escalation": {
                            "type": "object",
                            "dynamic": "strict",
                            "properties": {
                                "requested": {"type": "boolean"},
                                "reason": {"type": "text"},
                                "requested_at": {"type": "date"},
                            },
                        },
                    },
                },
                "created_at": {"type": "date"},
                "updated_at": {"type": "date"},
                "resolved_at": {"type": "date"},
                "tags": {"type": "keyword"},
            }
        },
    }


def ensure_l1_result_mapping():
    """Apply the additive L1 result mapping to existing investigation indices."""
    result = investigation_contexts_mapping()["mappings"]["properties"]["l1_result"]
    response = requests.put(
        f"{os.environ['ELASTIC_CLOUD_URL'].rstrip('/')}/investigation-contexts/_mapping",
        headers=es_headers(),
        json={"properties": {"l1_result": result}},
        timeout=30,
    )
    return response.ok


def action_policies_mapping():
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "action_type": {"type": "keyword"},
                "risk_tier": {"type": "keyword"},
                "allowed_callers": {"type": "keyword"},
                "auto_approve": {
                    "type": "object",
                    "properties": {
                        "min_confidence": {"type": "float"},
                        "max_blast_radius": {"type": "integer"},
                        "required_evidence_count": {"type": "integer"},
                    },
                },
                "requires_approval": {"type": "boolean"},
                "approval_channel": {"type": "keyword"},
                "rollback_workflow": {"type": "keyword"},
                "ttl_minutes": {"type": "integer"},
                "description": {"type": "text"},
            }
        },
    }


def dispatch_requests_mapping():
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "dispatch_id": {"type": "keyword"},
                "target_agent": {"type": "keyword"},
                "requesting_agent": {"type": "keyword"},
                "case_id": {"type": "keyword"},
                "investigation_id": {"type": "keyword"},
                "context": {"type": "text"},
                "priority": {"type": "keyword"},
                "status": {"type": "keyword"},
                "idempotency_key": {"type": "keyword"},
                "retry_count": {"type": "integer"},
                "created_at": {"type": "date"},
                "dispatched_at": {"type": "date"},
                "completed_at": {"type": "date"},
                "result_summary": {"type": "text"},
            }
        },
    }


def ensure_dispatch_requests_mapping():
    """Apply additive idempotency fields to existing dispatch indices."""
    properties = dispatch_requests_mapping()["mappings"]["properties"]
    response = requests.put(
        f"{os.environ['ELASTIC_CLOUD_URL'].rstrip('/')}/dispatch-requests/_mapping",
        headers=es_headers(),
        json={
            "properties": {
                "idempotency_key": properties["idempotency_key"],
                "retry_count": properties["retry_count"],
            }
        },
        timeout=30,
    )
    return response.ok


def approval_requests_mapping():
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "approval_id": {"type": "keyword"},
                "case_id": {"type": "keyword"},
                "investigation_id": {"type": "keyword"},
                "requesting_agent": {"type": "keyword"},
                "target_agent": {"type": "keyword"},
                "action_type": {"type": "keyword"},
                "action_details": {"type": "text"},
                "context": {"type": "text"},
                "target": {"type": "keyword"},
                "status": {"type": "keyword"},
                "risk_tier": {"type": "keyword"},
                "justification": {"type": "text"},
                "created_at": {"type": "date"},
                "resolved_at": {"type": "date"},
                "resolved_by": {"type": "keyword"},
                "execution_result": {"type": "text"},
            }
        },
    }


def compliance_mapping():
    """Mapping for kb-compliance — compliance evidence documents per framework."""
    inference_id = os.environ.get("INFERENCE_ENDPOINT_ID", ".multilingual-e5-small-elasticsearch")
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "title": {"type": "text"},
                "framework": {"type": "keyword"},
                "period_start": {"type": "date"},
                "period_end": {"type": "date"},
                "overall_status": {"type": "keyword"},
                "controls": {
                    "type": "nested",
                    "properties": {
                        "control_id": {"type": "keyword"},
                        "control_name": {"type": "text"},
                        "status": {"type": "keyword"},
                        "evidence": {
                            "type": "object",
                            "properties": {
                                "active_rules": {"type": "integer"},
                                "mitre_techniques_covered": {"type": "keyword"},
                                "tp_alerts_30d": {"type": "integer"},
                                "avg_response_time_hours": {"type": "float"},
                            },
                        },
                        "gaps": {"type": "text"},
                    },
                },
                "summary": {"type": "text"},
                "semantic_summary": {
                    "type": "semantic_text",
                    "inference_id": inference_id,
                },
                "category": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "created_at": {"type": "date"},
            }
        },
    }


def agent_metrics_mapping():
    """Mapping for agent-metrics — time-series per-agent operational metrics."""
    return {
        "settings": {"number_of_shards": 1, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "agent_id": {"type": "keyword"},
                "agent_name": {"type": "text"},
                "domain": {"type": "keyword"},
                "period_start": {"type": "date"},
                "period_end": {"type": "date"},
                "decisions_total": {"type": "integer"},
                "tp_classifications": {"type": "integer"},
                "fp_classifications": {"type": "integer"},
                "unknown_classifications": {"type": "integer"},
                "escalations_to_l2": {"type": "integer"},
                "cases_created": {"type": "integer"},
                "alerts_closed": {"type": "integer"},
                "avg_confidence": {"type": "float"},
                "actions_by_tier": {
                    "type": "object",
                    "properties": {
                        "tier_0_auto_approved": {"type": "integer"},
                        "tier_1_low_risk": {"type": "integer"},
                        "tier_2_approval_required": {"type": "integer"},
                    },
                },
                "dispatch_pending": {"type": "integer"},
                "dispatch_completed": {"type": "integer"},
                "dispatch_failed": {"type": "integer"},
                "period_hours": {"type": "integer"},
                "created_at": {"type": "date"},
            }
        },
    }


def create_all_indices():
    print("=== Creating Indices ===\n")

    print("Agent registry:")
    create_index("agent-registry", agent_registry_mapping())

    print("\nInvestigation contexts:")
    if create_index("investigation-contexts", investigation_contexts_mapping()):
        ensure_l1_result_mapping()

    print("\nAction policies:")
    create_index("action-policies", action_policies_mapping())

    print("\nDispatch requests:")
    if create_index("dispatch-requests", dispatch_requests_mapping()):
        ensure_dispatch_requests_mapping()

    print("\nApproval requests:")
    create_index("approval-requests", approval_requests_mapping())

    print("\nKnowledge bases:")
    kb_mapping = knowledge_base_mapping()
    for idx in KNOWLEDGE_BASE_INDICES:
        create_index(idx, kb_mapping)

    print("\nCompliance evidence:")
    create_index("kb-compliance", compliance_mapping())

    print("\nAgent metrics:")
    create_index("agent-metrics", agent_metrics_mapping())

    print()


def seed_action_policies():
    """Seed default action policies into the action-policies index."""
    print("=== Seeding Action Policies ===\n")

    policies = [
        {
            "action_type": "tag_alert",
            "risk_tier": "tier_0",
            "allowed_callers": ["*"],
            "requires_approval": False,
            "description": "Tag an alert as true positive or false positive",
        },
        {
            "action_type": "close_alert",
            "risk_tier": "tier_0",
            "allowed_callers": ["*"],
            "requires_approval": False,
            "description": "Close a security alert",
        },
        {
            "action_type": "acknowledge_alert",
            "risk_tier": "tier_0",
            "allowed_callers": ["*"],
            "requires_approval": False,
            "description": "Acknowledge a security alert",
        },
        {
            "action_type": "create_note",
            "risk_tier": "tier_0",
            "allowed_callers": ["*"],
            "requires_approval": False,
            "description": "Add a note to an alert or case",
        },
        {
            "action_type": "add_knowledge",
            "risk_tier": "tier_0",
            "allowed_callers": ["*"],
            "requires_approval": False,
            "description": "Add a document to a knowledge base",
        },
        {
            "action_type": "search",
            "risk_tier": "tier_0",
            "allowed_callers": ["*"],
            "requires_approval": False,
            "description": "Search operations (Elasticsearch, knowledge base, web)",
        },
        {
            "action_type": "create_case",
            "risk_tier": "tier_1",
            "allowed_callers": ["*"],
            "auto_approve": {
                "min_confidence": 0.7,
                "max_blast_radius": 1,
                "required_evidence_count": 1,
            },
            "requires_approval": False,
            "description": "Create a security case for investigation",
        },
        {
            "action_type": "create_rule",
            "risk_tier": "tier_1",
            "allowed_callers": ["*"],
            "auto_approve": {
                "min_confidence": 0.8,
                "max_blast_radius": 1,
                "required_evidence_count": 2,
            },
            "requires_approval": False,
            "description": "Create a detection rule (disabled by default)",
        },
        {
            "action_type": "run_playbook_step",
            "risk_tier": "tier_1",
            "allowed_callers": ["*"],
            "auto_approve": {
                "min_confidence": 0.7,
                "max_blast_radius": 5,
                "required_evidence_count": 1,
            },
            "requires_approval": False,
            "description": "Execute a single playbook step",
        },
        {
            "action_type": "isolate_host",
            "risk_tier": "tier_2",
            "allowed_callers": ["*"],
            "requires_approval": True,
            "approval_channel": "cases",
            "rollback_workflow": "unisolate_host",
            "ttl_minutes": 30,
            "description": "Isolate a host from the network via Elastic Defend",
        },
        {
            "action_type": "enable_rule_production",
            "risk_tier": "tier_2",
            "allowed_callers": ["*"],
            "requires_approval": True,
            "approval_channel": "cases",
            "ttl_minutes": 60,
            "description": "Enable a detection rule in production",
        },
        {
            "action_type": "execute_command",
            "risk_tier": "tier_2",
            "allowed_callers": ["*"],
            "requires_approval": True,
            "approval_channel": "cases",
            "ttl_minutes": 15,
            "description": "Execute a command on an endpoint via response console",
        },
        {
            "action_type": "bulk_operation",
            "risk_tier": "tier_2",
            "allowed_callers": ["*"],
            "requires_approval": True,
            "approval_channel": "cases",
            "ttl_minutes": 60,
            "description": "Bulk operations affecting multiple hosts or rules",
        },
    ]

    url = f"{os.environ['ELASTIC_CLOUD_URL']}/action-policies/_bulk"
    bulk_body = ""
    for policy in policies:
        doc_id = policy["action_type"]
        bulk_body += json.dumps({"index": {"_id": doc_id}}) + "\n"
        bulk_body += json.dumps(policy) + "\n"

    resp = requests.post(
        url,
        headers={**es_headers(), "Content-Type": "application/x-ndjson"},
        data=bulk_body,
        timeout=30,
    )
    if resp.ok:
        result = resp.json()
        errors = sum(1 for item in result.get("items", []) if item.get("index", {}).get("error"))
        total = len(result.get("items", []))
        print(f"  Seeded {total - errors}/{total} policies")
        if errors:
            print(f"  {errors} failed (may already exist)")
    else:
        print(f"  [FAILED] {resp.status_code} — {resp.text[:200]}")

    print()


def seed_operational_knowledge():
    """Seed critical operational knowledge that agents need from day one.

    These documents teach agents to recognise known false positive patterns,
    operational artifacts, and baseline behaviours that would otherwise trigger
    alert spirals or misclassification.
    """
    print("=== Seeding Operational Knowledge ===\n")

    es_url = os.environ.get("ELASTIC_CLOUD_URL", "").strip()
    headers = {
        "Content-Type": "application/json",
        "Authorization": auth_header("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD"),
    }
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    documents = [
        {
            "index": "kb-incidents",
            "id": "fp-response-console-alerts",
            "body": {
                "title": "False Positive Pattern: Elastic Defend Response Console Activity Triggers Behavior-Based Alerts",
                "content": (
                    "Commands executed via Elastic Defend response console appear as child "
                    "processes of elastic-endpoint with the full parent process path "
                    "/opt/Elastic/Endpoint/elastic-endpoint. These commands can trigger ANY "
                    "behavior-based detection rule — including but not limited to Suspicious "
                    "Echo Execution, Suspicious Process Execution, Suspicious Shell Activity, "
                    "and similar behavioral detections. This happens because response console "
                    "commands run shell commands as root, which matches patterns that detection "
                    "rules flag as malicious. This is expected behavior when the agent mesh or "
                    "human analysts use the response console for forensic investigation.\n\n"
                    "Common response console commands that trigger alerts:\n"
                    "- cat /root/.ssh/authorized_keys\n"
                    "- ls -la /etc/cron* /var/spool/cron/crontabs/\n"
                    "- w (check active sessions)\n"
                    "- last -20 (recent logins)\n"
                    "- ps aux | grep [process]\n"
                    "- grep -i fail /var/log/auth.log\n"
                    "- find / -name [file] -mtime -7\n"
                    "- netstat -antp\n\n"
                    "IMPORTANT: Do not blindly dismiss all alerts with elastic-endpoint as "
                    "parent. Verify BOTH conditions: (1) the full parent process path is "
                    "/opt/Elastic/Endpoint/elastic-endpoint (not just the name), AND (2) "
                    "the child command matches a recognisable forensic investigation pattern. "
                    "An attacker with root access could theoretically spoof the process name, "
                    "but the full path at the protected Elastic install location is much harder "
                    "to impersonate. When in doubt, check response console audit logs for "
                    "matching timestamps."
                ),
                "semantic_summary": (
                    "False positive pattern: Elastic Defend response console commands trigger "
                    "behavior-based security alerts. Any command run through the response console "
                    "(execute, execute-and-retrieve) appears as a child process of "
                    "elastic-endpoint at /opt/Elastic/Endpoint/elastic-endpoint. This triggers "
                    "detection rules including Suspicious Echo Execution, Suspicious Process "
                    "Execution, Suspicious Shell Activity, shell command alerts, and any "
                    "behavioral prevention rule that flags root shell activity. These are "
                    "legitimate forensic investigation actions — not malicious. Classify as "
                    "false positive when the parent process path is "
                    "/opt/Elastic/Endpoint/elastic-endpoint AND the command matches common "
                    "investigation patterns. This pattern causes alert spirals when the agent "
                    "mesh investigates endpoints and its own forensic commands trigger new "
                    "alerts. Applies to all behavior-based and malicious behavior prevention "
                    "alerts where elastic-endpoint is the parent process."
                ),
                "category": "false-positive-pattern",
                "source": "operational-learning",
                "tags": [
                    "false-positive",
                    "response-console",
                    "elastic-endpoint",
                    "behavior-detection",
                    "alert-spiral",
                    "malicious-behavior-prevention",
                ],
                "created_at": now,
                "updated_at": now,
                "metadata": {
                    "resolution": "Classify as False Positive after verifying both conditions",
                    "root_cause": (
                        "Response console forensic commands trigger behavior-based detection "
                        "rules because they run as root with shell execution patterns"
                    ),
                    "affected_rules": [
                        "Suspicious Echo Execution",
                        "Suspicious Process Execution",
                        "Suspicious Shell Activity",
                        "Any Malicious Behavior Prevention rule triggered by shell commands",
                    ],
                    "parent_process_path": "/opt/Elastic/Endpoint/elastic-endpoint",
                    "verification_steps": [
                        "Confirm full parent process path (not just name)",
                        "Verify command matches forensic investigation pattern",
                        "Check response console audit logs for matching timestamps if uncertain",
                    ],
                    "recommendation": (
                        "Create detection rule exceptions for commands with elastic-endpoint "
                        "parent process at the protected install path, or dispatch the Detection "
                        "Engineering agent to build a suppression rule."
                    ),
                },
            },
        },
        {
            "index": "kb-playbooks",
            "id": "playbook-response-console-fp",
            "body": {
                "title": "Playbook: Triage Any Alert Where Parent Process Is elastic-endpoint",
                "content": (
                    "This playbook applies to ANY security alert — not just a specific rule — "
                    "where the parent process is elastic-endpoint. Response console commands "
                    "trigger various behavior-based detection rules.\n\n"
                    "Steps:\n"
                    "1. Check if the parent process path is /opt/Elastic/Endpoint/elastic-endpoint "
                    "(the FULL path matters, not just the process name).\n"
                    "2. If the full path matches, the command was run via Elastic Defend response "
                    "console by the agent mesh or a human analyst.\n"
                    "3. Verify the child command matches a recognisable forensic pattern: checking "
                    "SSH keys, cron jobs, auth logs, process lists, network connections, file "
                    "searches, user sessions, or system enumeration.\n"
                    "4. If BOTH conditions are met (correct parent path + forensic command pattern), "
                    "classify as False Positive.\n"
                    "5. Tag the alert as False Positive and close it.\n"
                    "6. Do NOT escalate to L2 or dispatch specialists for confirmed response "
                    "console false positives.\n"
                    "7. If this alert type recurs frequently, consider dispatching the Detection "
                    "Engineering agent to create a rule exception or suppression.\n\n"
                    "CAUTION: Do not dismiss alerts solely based on the process name "
                    "'elastic-endpoint'. Always verify the FULL parent process path. An attacker "
                    "with sufficient access could create a process with a similar name at a "
                    "different path."
                ),
                "semantic_summary": (
                    "Triage playbook for any security alert triggered by Elastic Defend response "
                    "console commands. Applies to all alert types — Suspicious Echo Execution, "
                    "Suspicious Process Execution, shell activity alerts, malicious behavior "
                    "prevention alerts, and any future behavioral rule. When parent process path "
                    "is /opt/Elastic/Endpoint/elastic-endpoint and the command matches a forensic "
                    "investigation pattern, classify as false positive. Do not escalate response "
                    "console false positives. Prevents alert spirals from agent mesh investigation "
                    "activity and manual analyst response console use."
                ),
                "category": "triage-playbook",
                "source": "operational-learning",
                "tags": [
                    "triage",
                    "false-positive",
                    "response-console",
                    "elastic-endpoint",
                    "playbook",
                    "behavior-detection",
                ],
                "created_at": now,
                "updated_at": now,
            },
        },
    ]

    for doc in documents:
        url = f"{es_url}/{doc['index']}/_doc/{doc['id']}"
        resp = requests.put(url, headers=headers, json=doc["body"], timeout=30)
        if resp.status_code in (200, 201):
            result = resp.json().get("result", "unknown")
            print(f"  [OK] {doc['index']}/{doc['id']} ({result})")
        else:
            print(f"  [FAILED] {doc['index']}/{doc['id']}: {resp.status_code} — {resp.text[:200]}")

    print()


def _get_deployed_workflow_names():
    """Build a set of workflow names from the YAML files we deploy.

    Parses the 'name:' field from each YAML to identify which workflows
    belong to this project. Only these will be targeted by delete operations.
    """
    import re

    names = set()
    for workflow_dir in WORKFLOW_DIRS:
        dir_path = REPO_ROOT / workflow_dir
        if not dir_path.exists():
            continue
        for yaml_file in sorted(dir_path.glob("*.yaml")):
            try:
                text = yaml_file.read_text()
            except OSError as exc:
                print(f"  [WARN] Could not read {yaml_file}: {exc}")
                continue
            for line in text.splitlines():
                m = re.match(r"^name:\s*(.+)", line)
                if m:
                    names.add(m.group(1).strip().strip('"').strip("'"))
                    break
    return names


def list_deployed_workflows():
    """List the workflows currently deployed in Kibana.

    The endpoint answers with either a plain list or a paginated object;
    both shapes are normalized to a list of workflow dicts.
    """
    base_url = kibana_base_url()
    headers = kibana_headers()
    try:
        resp = requests.get(f"{base_url}/api/workflows", headers=headers, timeout=30)
    except requests.RequestException as exc:
        raise RuntimeError(f"Could not list workflows: {exc}") from exc
    if not resp.ok:
        raise RuntimeError(f"Could not list workflows: HTTP {resp.status_code}")
    payload = resp.json()
    if isinstance(payload, dict):
        payload = payload.get("data", payload.get("items", []))
    return payload if isinstance(payload, list) else []


def workflow_tags(workflow):
    """Tags of a workflow as a list of strings."""
    out = []
    for tag in workflow.get("tags") or []:
        if isinstance(tag, str):
            out.append(tag)
        elif isinstance(tag, dict) and tag.get("name"):
            out.append(tag["name"])
    return out


def is_mesh_workflow(workflow):
    """True when the workflow belongs to this repo (carries the mesh tag)."""
    return MESH_TAG in workflow_tags(workflow)


def manifest_path():
    """Path of the deployed-workflow manifest (name → id)."""
    return REPO_ROOT / ".oputils" / "workflows-manifest.json"


def load_manifest():
    """Read the manifest of previously deployed workflows."""
    path = manifest_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        print(f"  [WARN] Manifest {path} is not valid JSON; treating it as empty")
        return {}
    except OSError as exc:
        print(f"  [WARN] Could not read the manifest {path}: {exc}")
        return {}


def save_manifest(entries):
    """Write the manifest of deployed workflows (atomic replace)."""
    path = manifest_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n")
        tmp.replace(path)
    except OSError as exc:
        print(f"  [WARN] Could not write the manifest {path}: {exc}")


def delete_workflows(yes=False):
    """Delete the workflows this repo owns (tagged `oputils-mesh`).

    Dry-run by default: it lists what would be deleted and changes nothing.
    Pass yes=True (CLI: `--yes`) to actually delete. Workflows without the
    mesh tag are never touched.
    """
    print("=== Deleting Mesh Workflows ===\n")

    base_url = kibana_base_url()
    headers = kibana_headers()

    workflows = list_deployed_workflows()
    targets = [wf for wf in workflows if is_mesh_workflow(wf)]
    untagged = len(workflows) - len(targets)

    if not targets:
        print(f"  No workflows tagged '{MESH_TAG}' found; nothing to delete.\n")
        return 0

    if not yes:
        print(f"  DRY RUN — {len(targets)} workflow(s) tagged '{MESH_TAG}' would be deleted:")
        for wf in targets:
            print(f"    - {wf.get('name', '')} ({wf.get('id', '')})")
        print(f"\n  {untagged} workflow(s) without the tag are left untouched.")
        print("  Re-run with --yes to perform the deletion.\n")
        return 0

    deleted = 0
    errors = 0
    for wf in targets:
        wf_id = wf.get("id", "")
        name = wf.get("name", wf_id)
        resp = requests.delete(
            f"{base_url}/api/workflows/workflow/{wf_id}?force=true&acknowledgeAclLoss=true",
            headers=headers,
            timeout=30,
        )
        if resp.ok or resp.status_code == 204:
            print(f"  [deleted] {name}")
            deleted += 1
        else:
            print(f"  [FAILED] {name}: {resp.status_code}")
            errors += 1

    print(f"\n  Deleted {deleted} mesh workflow(s), left {untagged} untagged, {errors} error(s)\n")
    return deleted


def import_workflows():
    """Import all workflow YAML files into Kibana.

    For each file the script:
      1. Looks the workflow up by name among the workflows tagged
         `oputils-mesh`; if it exists it PUTs the YAML to update it.
      2. Otherwise it POSTs the YAML verbatim in the Workflows bulk-create
         request envelope (and falls back to a PUT if Kibana answers 409).
      3. Records name → id in the manifest so orphans can be detected.

    Returns a dict mapping workflow_name → workflow_id for use by
    create_tools().
    """
    print("=== Importing Workflows ===\n")

    base_url = kibana_base_url()
    headers = kibana_headers()
    name_to_id = {}

    existing = {}
    try:
        existing = {
            wf.get("name", ""): wf.get("id", "")
            for wf in list_deployed_workflows()
            if is_mesh_workflow(wf) and wf.get("id")
        }
    except RuntimeError as exc:
        if isinstance(exc.__cause__, requests.ConnectionError):
            # Kibana is unreachable, so a POST cannot succeed either — and it cannot
            # duplicate anything. Let the per-workflow POST report the real error.
            print(
                f"  [WARN] Could not list deployed workflows ({exc}); "
                "continuing without the deployed list"
            )
        else:
            # Kibana answered but the deployed list is unknown: a blind POST could
            # duplicate workflows, so abort instead.
            print(f"  [FAILED] Could not list deployed workflows ({exc}); aborting the import")
            raise

    success = 0
    updated = 0
    failed = 0
    failures = []
    manifest = {}

    for workflow_dir in WORKFLOW_DIRS:
        dir_path = REPO_ROOT / workflow_dir
        if not dir_path.exists():
            continue

        yaml_files = sorted(dir_path.glob("*.yaml"))
        if not yaml_files:
            continue

        print(f"  {workflow_dir}/")
        for yaml_file in yaml_files:
            try:
                yaml_content = yaml_file.read_text()
            except OSError as exc:
                print(f"    [FAILED] {yaml_file.name}: {exc}")
                failures.append(f"{yaml_file} ({yaml_file.name}): {exc}")
                failed += 1
                continue

            workflow_name = ""
            try:
                workflow_name = (yaml.safe_load(yaml_content) or {}).get("name", "") or ""
            except yaml.YAMLError:
                workflow_name = ""

            wf_id = existing.get(workflow_name, "")
            resp = None
            if wf_id:
                resp = requests.put(
                    f"{base_url}/api/workflows/workflow/{wf_id}",
                    headers=headers,
                    json={"yaml": yaml_content},
                    timeout=30,
                )
                if resp.ok:
                    name = resp.json().get("name", workflow_name or yaml_file.stem)
                    name_to_id[name] = wf_id
                    manifest[name] = {"id": wf_id, "path": str(yaml_file.relative_to(REPO_ROOT))}
                    print(f"    [updated] {name}")
                    updated += 1
                    time.sleep(0.3)
                    continue
                detail = " ".join(str(getattr(resp, "text", "")).split())[:300]
                print(
                    f"    [FAILED update] {yaml_file.name}: "
                    f"{resp.status_code} - {detail or 'no response detail'}"
                )
                failures.append(
                    f"{yaml_file} ({yaml_file.name}): HTTP {resp.status_code} - "
                    f"{detail or 'no response detail'}"
                )
                failed += 1
                time.sleep(0.3)
                continue

            resp = requests.post(
                f"{base_url}/api/workflows",
                headers=headers,
                json={"workflows": [{"yaml": yaml_content}]},
                timeout=30,
            )

            if resp.ok:
                data = resp.json()
                created = data.get("created", [])
                response_failures = data.get("failures", [])
                for workflow in created:
                    name = workflow.get("name", yaml_file.stem)
                    wf_id = workflow.get("id", "")
                    if wf_id:
                        name_to_id[name] = wf_id
                        manifest[name] = {
                            "id": wf_id,
                            "path": str(yaml_file.relative_to(REPO_ROOT)),
                        }
                    print(f"    [imported] {name}")
                    success += 1
                for failure in response_failures:
                    detail = " ".join(str(failure).split())[:300]
                    print(f"    [FAILED] {yaml_file.name}: {detail or 'no response detail'}")
                    failures.append(
                        f"{yaml_file} ({yaml_file.name}): {detail or 'no response detail'}"
                    )
                    failed += 1
            elif resp.status_code == 409:
                wf_id = resp.json().get("id", "") or existing.get(workflow_name, "")
                if wf_id:
                    put_resp = requests.put(
                        f"{base_url}/api/workflows/workflow/{wf_id}",
                        headers=headers,
                        json={"yaml": yaml_content},
                        timeout=30,
                    )
                    if put_resp.ok:
                        name = put_resp.json().get("name", yaml_file.stem)
                        name_to_id[name] = wf_id
                        manifest[name] = {
                            "id": wf_id,
                            "path": str(yaml_file.relative_to(REPO_ROOT)),
                        }
                        print(f"    [updated] {name}")
                        updated += 1
                    else:
                        detail = " ".join(str(getattr(put_resp, "text", "")).split())[:300]
                        print(
                            f"    [FAILED update] {yaml_file.name}: "
                            f"{put_resp.status_code} - {detail or 'no response detail'}"
                        )
                        failures.append(
                            f"{yaml_file} ({yaml_file.name}): HTTP {put_resp.status_code} - "
                            f"{detail or 'no response detail'}"
                        )
                        failed += 1
                else:
                    detail = "HTTP 409 - conflict without an id"
                    print(f"    [FAILED] {yaml_file.name}: {detail}")
                    failures.append(f"{yaml_file} ({yaml_file.name}): {detail}")
                    failed += 1
            else:
                detail = " ".join(str(getattr(resp, "text", "")).split())[:300]
                print(
                    f"    [FAILED] {yaml_file.name}: {resp.status_code} - "
                    f"{detail or 'no response detail'}"
                )
                failures.append(
                    f"{yaml_file} ({yaml_file.name}): HTTP {resp.status_code} - "
                    f"{detail or 'no response detail'}"
                )
                failed += 1

            time.sleep(0.3)

    previous_manifest = load_manifest()
    save_manifest(manifest)

    deployed = {}
    try:
        deployed = {
            wf.get("name", ""): wf.get("id", "")
            for wf in list_deployed_workflows()
            if is_mesh_workflow(wf)
        }
    except RuntimeError as exc:
        print(f"  [WARN] Could not list deployed workflows ({exc}); skipping orphan report")
    untracked = sorted(set(deployed) - set(manifest))
    stale = sorted(name for name in previous_manifest if name not in deployed)
    missing = sorted(set(_get_deployed_workflow_names()) - set(deployed))
    if untracked:
        print(f"  [ORPHANS] deployed but not in the manifest: {', '.join(untracked)}")
    if stale:
        print(f"  [STALE] in the manifest but not deployed: {', '.join(stale)}")
    if missing:
        print(f"  [MISSING] in the repo but not deployed: {', '.join(missing)}")

    print(f"\n  Total: {success} imported, {updated} updated, {failed} failed")
    print(f"  Captured {len(name_to_id)} workflow name→ID mappings\n")
    print(f"  Manifest: {manifest_path()}\n")
    if failures:
        raise RuntimeError("Workflow imports failed:\n  - " + "\n  - ".join(failures))
    return name_to_id


def fetch_existing_workflow_ids():
    """Fetch name→ID mapping for already-imported workflows in Kibana."""
    base_url = kibana_base_url()
    headers = kibana_headers()
    resp = requests.get(f"{base_url}/api/workflows", headers=headers, timeout=30)
    if not resp.ok:
        print(f"  [WARN] Could not list workflows: {resp.status_code}")
        return {}
    workflows = resp.json()
    if isinstance(workflows, dict):
        workflows = workflows.get("data", workflows.get("items", []))
    return {wf.get("name", ""): wf.get("id", "") for wf in workflows if wf.get("id")}


def fetch_existing_tool_ids():
    """Fetch name→ID mapping for already-created tools in Agent Builder."""
    base_url = kibana_base_url()
    headers = kibana_headers()
    resp = requests.get(f"{base_url}/api/agent_builder/tools", headers=headers, timeout=30)
    if not resp.ok:
        print(f"  [WARN] Could not list tools: {resp.status_code}")
        return {}
    tools = resp.json()
    if isinstance(tools, dict):
        tools = tools.get("data", tools.get("items", []))
    id_to_desc = {}
    for t in tools:
        tid = t.get("id", "")
        desc = t.get("description", "")
        if tid:
            id_to_desc[tid] = desc
    agent_defs = load_agent_definitions()
    name_to_id = {}
    for agent_def in agent_defs:
        for tool in agent_def.get("tools", []):
            expected_id = slugify(tool["name"])
            if expected_id in id_to_desc:
                name_to_id[tool["name"]] = expected_id
    return name_to_id


def slugify(name):
    """Convert a display name to a URL-safe tool/agent ID."""
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return f"security-mesh.{s.strip('-')}"


def load_agent_definitions():
    """Load all agent definition YAML files from agents/definitions/."""
    defs_dir = REPO_ROOT / "agents" / "definitions"
    definitions = []
    for yaml_file in sorted(defs_dir.glob("*.yaml")):
        try:
            agent_def = yaml.safe_load(yaml_file.read_text())
        except (OSError, yaml.YAMLError) as exc:
            print(f"  [WARN] Could not load {yaml_file}: {exc}")
            continue
        if agent_def and "agent_name" in agent_def:
            definitions.append(agent_def)
    return definitions


def _resolve_workflow_id(tool_name, tool_def, workflow_name_to_id):
    """Resolve a workflow ID for a tool, trying multiple strategies.

    1. Direct match: tool display name == workflow name
    2. File-based: read the workflow YAML's name: field from the path in
       the agent definition and look that up instead.
    """
    wf_id = workflow_name_to_id.get(tool_name)
    if wf_id:
        return wf_id

    wf_path = tool_def.get("workflow", "")
    if wf_path:
        wf_file = REPO_ROOT / wf_path
        if wf_file.exists():
            try:
                wf_yaml = yaml.safe_load(wf_file.read_text())
                wf_name = wf_yaml.get("name", "")
                if wf_name:
                    wf_id = workflow_name_to_id.get(wf_name)
                    if wf_id:
                        return wf_id
            except (OSError, yaml.YAMLError) as exc:
                print(f"  [WARN] Could not read workflow {wf_file}: {exc}")

    return None


def create_tools(workflow_name_to_id):
    """Create all tools in Agent Builder via API.

    Reads agent definitions to discover which tools are needed, creates
    workflow tools (linked to imported workflow IDs) and index_search tools.
    Returns a dict mapping tool_display_name → tool_id.
    """
    print("=== Creating Tools in Agent Builder ===\n")

    base_url = kibana_base_url()
    headers = kibana_headers()
    agent_defs = load_agent_definitions()

    tools_seen = {}
    for agent_def in agent_defs:
        for tool in agent_def.get("tools", []):
            name = tool["name"]
            if name in tools_seen:
                continue
            tools_seen[name] = tool

    context_definitions = [
        tool for tool in tools_seen.values() if tool["name"] == "Bounded Alert Context"
    ]
    try:
        if len(context_definitions) != 1:
            raise AlertContextConfigurationError(
                "exactly one bounded alert-context tool is required"
            )
        build_alert_context_tool(context_definitions[0])
        validate_alert_context_schema()
    except AlertContextConfigurationError as error:
        print(f"  [CONFIGURATION ERROR] {error}")
        return {}

    print(f"  Found {len(tools_seen)} unique tools across {len(agent_defs)} agents\n")

    tool_name_to_id = {}
    created = 0
    updated = 0
    skipped = 0
    failed = 0

    for tool_name, tool_def in tools_seen.items():
        tool_id = slugify(tool_name)
        tool_type = tool_def.get("type", "workflow")

        if tool_type == "builtin":
            builtin_id = tool_def.get("tool_id", "")
            if builtin_id:
                tool_name_to_id[tool_name] = builtin_id
                print(f"    [builtin] {tool_name} → {builtin_id}")
            continue

        if tool_name == "Bounded Alert Context":
            payload = build_alert_context_tool(tool_def)
        elif tool_type == "index_search":
            index_name = tool_def.get("index", "")
            payload = {
                "id": tool_id,
                "type": "index_search",
                "name": tool_name,
                "description": tool_def.get("description", f"Search {index_name}"),
                "tags": ["security-mesh"],
                "configuration": {
                    "index_pattern": index_name,
                    "max_rows": 10,
                },
            }
            resp = requests.post(
                f"{base_url}/api/agent_builder/tools",
                headers=headers,
                json=payload,
                timeout=30,
            )
            if resp.ok:
                print(f"    [created] {tool_name} ({tool_id})")
                tool_name_to_id[tool_name] = tool_id
                created += 1
            elif resp.status_code in (400, 409) and "already exists" in resp.text:
                print(f"    [exists]  {tool_name} ({tool_id})")
                tool_name_to_id[tool_name] = tool_id
                skipped += 1
            else:
                print(f"    [MANUAL]  {tool_name} — index_search tools require UI creation")
                print(f"              API response: {resp.status_code} — {resp.text[:300]}")
                print("              Create manually: Agent Builder > Tools > New tool")
                print(f"              Type: Index Search | Index: {index_name} | ID: {tool_id}")
                failed += 1
            time.sleep(0.2)
            continue
        else:
            wf_id = _resolve_workflow_id(tool_name, tool_def, workflow_name_to_id)
            if not wf_id:
                print(f"    [SKIP] {tool_name} — no matching workflow ID found")
                failed += 1
                continue
            payload = {
                "id": tool_id,
                "type": "workflow",
                "description": tool_def.get("description", ""),
                "tags": ["security-mesh"],
                "configuration": {
                    "workflow_id": wf_id,
                },
            }

        resp = requests.post(
            f"{base_url}/api/agent_builder/tools",
            headers=headers,
            json=payload,
            timeout=30,
        )

        if resp.ok:
            print(f"    [created] {tool_name} ({tool_id})")
            tool_name_to_id[tool_name] = tool_id
            created += 1
        elif resp.status_code in (400, 409) and "already exists" in resp.text:
            put_resp = requests.put(
                f"{base_url}/api/agent_builder/tools/{tool_id}",
                headers=headers,
                json={k: v for k, v in payload.items() if k not in ("id", "type")},
                timeout=30,
            )
            if put_resp.ok:
                print(f"    [updated] {tool_name} ({tool_id})")
                tool_name_to_id[tool_name] = tool_id
                updated += 1
            else:
                print(f"    [FAILED update] {tool_name}: {put_resp.status_code}")
                print(f"              {put_resp.text[:500]}")
                failed += 1
        else:
            print(f"    [FAILED]  {tool_name}: {resp.status_code}")
            print(f"              {resp.text[:500]}")
            failed += 1

        time.sleep(0.2)

    print(f"\n  Total: {created} created, {updated} updated, {skipped} existing, {failed} failed\n")
    return tool_name_to_id


MANUALLY_CREATED_TOOLS = {"security-mesh.agent-registry"}


def delete_tools():
    """Delete all security-mesh tools from Agent Builder.

    Uses a two-pass strategy:
      1. Compute expected tool IDs from agent definitions and delete by ID.
      2. List tools from the API and delete any remaining security-mesh.* tools.

    Tools in MANUALLY_CREATED_TOOLS are preserved (they require UI creation
    and would be lost on redeploy).
    """
    print("=== Deleting Security Mesh Tools ===\n")

    base_url = kibana_base_url()
    headers = kibana_headers()

    agent_defs = load_agent_definitions()
    expected_ids = set()
    for agent_def in agent_defs:
        for tool in agent_def.get("tools", []):
            if tool.get("type") == "builtin":
                continue
            expected_ids.add(slugify(tool["name"]))

    deleted = 0
    errors = 0

    expected_ids -= MANUALLY_CREATED_TOOLS
    print(
        f"  Pass 1: deleting {len(expected_ids)} known tool IDs (preserving {len(MANUALLY_CREATED_TOOLS)} manual tools)..."
    )
    for tool_id in sorted(expected_ids):
        del_resp = requests.delete(
            f"{base_url}/api/agent_builder/tools/{tool_id}",
            headers=headers,
            timeout=15,
        )
        if del_resp.ok or del_resp.status_code == 204:
            print(f"    [deleted] {tool_id}")
            deleted += 1
        elif del_resp.status_code == 404:
            pass
        else:
            print(f"    [FAILED] {tool_id}: {del_resp.status_code} — {del_resp.text[:200]}")
            errors += 1
        time.sleep(0.1)

    print("\n  Pass 2: checking for any remaining security-mesh tools via API...")
    resp = requests.get(f"{base_url}/api/agent_builder/tools", headers=headers, timeout=30)
    if resp.ok:
        body = resp.json()
        tools_list = body if isinstance(body, list) else []
        if isinstance(body, dict):
            for key in ("data", "items", "tools", "results"):
                if key in body and isinstance(body[key], list):
                    tools_list = body[key]
                    break
        remaining = [
            t
            for t in tools_list
            if isinstance(t, dict)
            and t.get("id", "").startswith("security-mesh")
            and t.get("id", "") not in MANUALLY_CREATED_TOOLS
        ]
        for tool in remaining:
            tool_id = tool.get("id", "")
            del_resp = requests.delete(
                f"{base_url}/api/agent_builder/tools/{tool_id}",
                headers=headers,
                timeout=15,
            )
            if del_resp.ok or del_resp.status_code == 204:
                print(f"    [deleted] {tool_id}")
                deleted += 1
            time.sleep(0.1)
    else:
        print(f"    [WARN] Could not list tools: {resp.status_code}")

    print(f"\n  Deleted {deleted} tools ({errors} errors)\n")


def create_agents(tool_name_to_id):
    """Create all agents in Agent Builder via API.

    Reads agent definitions, maps their tool lists to tool IDs, and
    creates each agent with system instructions and tool assignments.
    Returns a dict mapping agent_name → agent_builder_id.
    """
    print("=== Creating Agents in Agent Builder ===\n")

    base_url = kibana_base_url()
    headers = kibana_headers()
    agent_defs = load_agent_definitions()
    l1_definitions = [agent for agent in agent_defs if agent["agent_name"] == "L1 Triage Analyst"]
    try:
        l1_context = [
            tool for tool in l1_definitions[0]["tools"] if tool["name"] == "Bounded Alert Context"
        ]
        if len(l1_definitions) != 1 or len(l1_context) != 1:
            raise AlertContextConfigurationError(
                "L1 requires exactly one bounded alert-context tool"
            )
        build_alert_context_tool(l1_context[0])
        validate_alert_context_schema()
    except (AlertContextConfigurationError, IndexError) as error:
        print(f"  [CONFIGURATION ERROR] {error}")
        return {}

    agent_name_to_id = {}
    created = 0
    updated = 0
    skipped = 0
    failed = 0

    for agent_def in agent_defs:
        agent_name = agent_def["agent_name"]
        agent_id = slugify(agent_name)

        tool_ids = []
        builtin_tools = []
        skipped_tools = []
        fallback_tools = []
        for tool in agent_def.get("tools", []):
            if tool.get("type") == "builtin":
                builtin_id = tool.get("tool_id", "")
                if builtin_id:
                    check = requests.get(
                        f"{base_url}/api/agent_builder/tools/{builtin_id}",
                        headers=headers,
                        timeout=10,
                    )
                    if check.ok:
                        tool_ids.append(builtin_id)
                        builtin_tools.append(f"{tool['name']} → {builtin_id}")
                    else:
                        skipped_tools.append(
                            f"{tool['name']} (Connector builtin not enabled/found)"
                        )
                continue

            tid = tool_name_to_id.get(tool["name"])
            if tid:
                tool_ids.append(tid)
            else:
                computed_id = slugify(tool["name"])
                check = requests.get(
                    f"{base_url}/api/agent_builder/tools/{computed_id}",
                    headers=headers,
                    timeout=10,
                )
                if check.ok:
                    tool_ids.append(computed_id)
                    fallback_tools.append(tool["name"])
                else:
                    skipped_tools.append(tool["name"])

        if builtin_tools:
            print(f"    [builtin] {agent_name}: {len(builtin_tools)} platform tool(s):")
            for bt in builtin_tools:
                print(f"              - {bt}")
        if fallback_tools:
            print(f"    [info] {agent_name}: {len(fallback_tools)} tool(s) resolved via fallback:")
            for ft in fallback_tools:
                print(f"           - {ft} → {slugify(ft)}")
        if skipped_tools:
            print(f"    [warn] {agent_name}: {len(skipped_tools)} tool(s) not found, skipped:")
            for st in skipped_tools:
                print(f"           - {st} (create manually in Agent Builder)")

        if agent_name == "L1 Triage Analyst" and skipped_tools:
            print("    [FAILED] L1 assignment blocked: required tool is unavailable")
            failed += 1
            continue

        payload = {
            "id": agent_id,
            "name": agent_name,
            "description": agent_def.get("description", "").strip(),
            "labels": ["security-mesh"],
            "configuration": {
                "instructions": agent_def.get("system_instructions", ""),
                "tools": [{"tool_ids": tool_ids}] if tool_ids else [],
            },
        }

        resp = requests.post(
            f"{base_url}/api/agent_builder/agents",
            headers=headers,
            json=payload,
            timeout=30,
        )

        if resp.ok:
            returned_id = resp.json().get("id", agent_id)
            print(f"    [created] {agent_name} ({returned_id}) — {len(tool_ids)} tools")
            agent_name_to_id[agent_name] = returned_id
            created += 1
        elif resp.status_code in (400, 409) and "already exists" in resp.text:
            put_resp = requests.put(
                f"{base_url}/api/agent_builder/agents/{agent_id}",
                headers=headers,
                json={k: v for k, v in payload.items() if k != "id"},
                timeout=30,
            )
            if put_resp.ok:
                print(f"    [updated] {agent_name} ({agent_id}) — {len(tool_ids)} tools")
                agent_name_to_id[agent_name] = agent_id
                updated += 1
            else:
                print(f"    [FAILED update] {agent_name}: {put_resp.status_code}")
                print(f"              {put_resp.text[:500]}")
                failed += 1
        else:
            print(f"    [FAILED]  {agent_name}: {resp.status_code}")
            print(f"              {resp.text[:500]}")
            failed += 1

        time.sleep(0.3)

    print(f"\n  Total: {created} created, {updated} updated, {skipped} existing, {failed} failed\n")
    return agent_name_to_id


def delete_agents():
    """Delete all security-mesh agents from Agent Builder.

    Uses a two-pass strategy:
      1. Compute expected agent IDs from definitions and delete by ID.
         Also tries the hyphen variant (security-mesh-xxx) for legacy agents.
      2. List agents from the API and delete any remaining security-mesh agents.
    """
    print("=== Deleting Security Mesh Agents ===\n")

    base_url = kibana_base_url()
    headers = kibana_headers()

    agent_defs = load_agent_definitions()
    expected_ids = set()
    for agent_def in agent_defs:
        dot_id = slugify(agent_def["agent_name"])
        expected_ids.add(dot_id)
        hyphen_id = dot_id.replace("security-mesh.", "security-mesh-", 1)
        expected_ids.add(hyphen_id)

    deleted = 0
    errors = 0

    print(f"  Pass 1: deleting {len(expected_ids)} known agent IDs (dot + hyphen variants)...")
    for agent_id in sorted(expected_ids):
        del_resp = requests.delete(
            f"{base_url}/api/agent_builder/agents/{agent_id}",
            headers=headers,
            timeout=15,
        )
        if del_resp.ok or del_resp.status_code == 204:
            print(f"    [deleted] {agent_id}")
            deleted += 1
        elif del_resp.status_code == 404:
            pass
        else:
            print(f"    [FAILED] {agent_id}: {del_resp.status_code} — {del_resp.text[:200]}")
            errors += 1
        time.sleep(0.1)

    print("\n  Pass 2: checking for any remaining security-mesh agents via API...")
    resp = requests.get(f"{base_url}/api/agent_builder/agents", headers=headers, timeout=30)
    if resp.ok:
        body = resp.json()
        agents_list = body if isinstance(body, list) else []
        if isinstance(body, dict):
            for key in ("data", "items", "agents", "results"):
                if key in body and isinstance(body[key], list):
                    agents_list = body[key]
                    break
        remaining = [
            a
            for a in agents_list
            if isinstance(a, dict)
            and (
                a.get("id", "").startswith("security-mesh.")
                or a.get("id", "").startswith("security-mesh-")
            )
        ]
        for agent in remaining:
            agent_id = agent.get("id", "")
            del_resp = requests.delete(
                f"{base_url}/api/agent_builder/agents/{agent_id}",
                headers=headers,
                timeout=15,
            )
            if del_resp.ok or del_resp.status_code == 204:
                print(f"    [deleted] {agent_id}")
                deleted += 1
            time.sleep(0.1)
    else:
        print(f"    [WARN] Could not list agents: {resp.status_code}")

    print(f"\n  Deleted {deleted} agents ({errors} errors)\n")


def register_agents_in_mesh(agent_name_to_builder_id):
    """Register all agents in the agent-registry index for semantic discovery."""
    print("=== Registering Agents in Mesh ===\n")

    agent_defs = load_agent_definitions()
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    bulk_body = ""
    count = 0
    for agent_def in agent_defs:
        reg = agent_def.get("registry_entry")
        if not reg:
            continue

        agent_name = agent_def["agent_name"]
        builder_id = agent_name_to_builder_id.get(agent_name, slugify(agent_name))
        doc_id = slugify(reg.get("agent_name", agent_name))

        doc = {
            "agent_id": builder_id,
            "agent_name": reg["agent_name"],
            "domain": reg["domain"],
            "capabilities": reg.get("capabilities", []),
            "description": reg.get("description", "").strip(),
            "semantic_description": f"{reg['agent_name']}. {reg.get('description', '').strip()}",
            "keywords": reg.get("keywords", []),
            "status": "active",
            "version": "1.0",
            "created_at": now,
            "updated_at": now,
        }

        bulk_body += json.dumps({"index": {"_id": doc_id}}) + "\n"
        bulk_body += json.dumps(doc) + "\n"
        count += 1

    if not bulk_body:
        print("  No registry entries found.\n")
        return

    url = f"{os.environ['ELASTIC_CLOUD_URL']}/agent-registry/_bulk"
    resp = requests.post(
        url,
        headers={**es_headers(), "Content-Type": "application/x-ndjson"},
        data=bulk_body,
        timeout=30,
    )

    if resp.ok:
        result = resp.json()
        errors = sum(1 for item in result.get("items", []) if item.get("index", {}).get("error"))
        print(f"  Registered {count - errors}/{count} agents in mesh")
        if errors:
            for item in result.get("items", []):
                err = item.get("index", {}).get("error")
                if err:
                    print(f"    [error] {err.get('reason', '')[:150]}")
    else:
        print(f"  [FAILED] {resp.status_code} — {resp.text[:200]}")

    print()


def print_manual_steps():
    """Print steps that must be done manually."""
    print("=== Manual Steps (Pre-requisites) ===\n")
    print("  Ensure the following are done in Kibana before running full setup:\n")
    print("  1. Deploy inference endpoint (multilingual-e5-small)")
    print("     Machine Learning > Trained Models > Deploy")
    print()
    print("  2. Create LLM connector")
    print("     Stack Management > Connectors > Create connector")
    print("     (Claude Sonnet, GPT-4o, Gemini, or your preferred model)")
    print("     Enrichment connectors oputils-virustotal and oputils-abuseipdb are")
    print("     auto-provisioned by setup.py; create them by hand if the key is unset")
    print()
    print("  3. Seed knowledge bases (post-setup)")
    print("     Populate kb-* indices with domain-specific data by running:")
    print("     python scripts/setup.py --seed-all-knowledge")
    print("     This will automatically fetch and index MITRE ATT&CK techniques,")
    print("     ECS field definitions, and existing detection rules.")
    print()


def import_workflows_or_exit():
    """Import the workflows, aborting the deploy if the deployed list is unknown."""
    try:
        return import_workflows()
    except RuntimeError as exc:
        print(f"\n  [ERROR] {exc}")
        print("  Aborting: importing without knowing the deployed workflows would duplicate them.")
        sys.exit(1)


def main():
    load_project_env()

    parser = argparse.ArgumentParser(description="Elastic Security Agent Mesh setup")
    parser.add_argument("--validate", action="store_true", help="Validate env vars only")
    parser.add_argument("--indices-only", action="store_true", help="Only create indices")
    parser.add_argument("--workflows-only", action="store_true", help="Only import workflows")
    parser.add_argument("--seed-policies", action="store_true", help="Only seed action policies")
    parser.add_argument(
        "--tools-only",
        action="store_true",
        help="Only create tools (requires workflows already imported)",
    )
    parser.add_argument(
        "--agents-only",
        action="store_true",
        help="Only create agents (requires tools already created)",
    )
    parser.add_argument(
        "--seed-knowledge",
        action="store_true",
        help="Only seed operational knowledge (false positive patterns, playbooks)",
    )
    parser.add_argument("--seed-mitre", action="store_true", help="Seed MITRE ATT&CK data")
    parser.add_argument("--seed-ecs", action="store_true", help="Seed ECS schema data")
    parser.add_argument("--seed-rules", action="store_true", help="Seed Detection Rules data")
    parser.add_argument(
        "--seed-all-knowledge",
        action="store_true",
        help="Seed all knowledge bases (MITRE, ECS, Rules, Operational)",
    )
    parser.add_argument(
        "--delete-workflows",
        action="store_true",
        help="Delete the workflows this repo owns (tagged oputils-mesh); dry-run unless --yes",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm a destructive operation (required to actually delete workflows)",
    )
    parser.add_argument(
        "--delete-all",
        action="store_true",
        help="Delete all mesh agents, tools, and workflows, then re-deploy",
    )
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  Elastic Security Agent Mesh — Setup")
    print("=" * 60)
    print()

    validate_env()

    if args.validate:
        print("Validation complete.")
        return

    if args.delete_all:
        delete_workflows(yes=args.yes)
        delete_agents()
        delete_tools()
        print("\n  Waiting 15s for deletions to propagate...\n")
        time.sleep(15)
        create_all_indices()
        seed_action_policies()
        seed_operational_knowledge()
        ensure_connectors()
        wf_map = import_workflows_or_exit()
        tool_map = create_tools(wf_map)
        agent_map = create_agents(tool_map)
        register_agents_in_mesh(agent_map)
        print_manual_steps()
        print("=" * 60)
        print("  Full re-deploy complete!")
        print("=" * 60)
        print()
        return

    if args.delete_workflows:
        delete_workflows(yes=args.yes)
        return

    if args.indices_only:
        create_all_indices()
        return

    if args.workflows_only:
        import_workflows_or_exit()
        return

    if args.seed_policies:
        seed_action_policies()
        return

    # Add scripts/ to sys.path so we can import the seed scripts
    sys.path.insert(0, str(Path(__file__).resolve().parent))

    if args.seed_all_knowledge:
        seed_operational_knowledge()
        import seed_mitre

        seed_mitre.main()
        import seed_ecs

        seed_ecs.main()
        import seed_rules

        seed_rules.main()
        return

    if args.seed_knowledge:
        seed_operational_knowledge()
        return

    if args.seed_mitre:
        import seed_mitre

        seed_mitre.main()
        return

    if args.seed_ecs:
        import seed_ecs

        seed_ecs.main()
        return

    if args.seed_rules:
        import seed_rules

        seed_rules.main()
        return

    if args.tools_only:
        wf_map = fetch_existing_workflow_ids()
        create_tools(wf_map)
        return

    if args.agents_only:
        tool_map = fetch_existing_tool_ids()
        agent_map = create_agents(tool_map)
        register_agents_in_mesh(agent_map)
        return

    create_all_indices()
    seed_action_policies()
    seed_operational_knowledge()
    ensure_connectors()
    wf_map = import_workflows_or_exit()
    tool_map = create_tools(wf_map)
    agent_map = create_agents(tool_map)
    register_agents_in_mesh(agent_map)
    print_manual_steps()

    print("=" * 60)
    print("  Setup complete!")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
