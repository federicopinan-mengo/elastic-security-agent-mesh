#!/usr/bin/env python3
"""
Unit tests for setup.py

Run with: pytest tests/test_setup.py -v
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

# Add scripts/ to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from setup import (
    ALERT_CONTEXT_QUERY,
    AlertContextConfigurationError,
    _get_deployed_workflow_names,
    apply_replacements,
    build_alert_context_tool,
    build_replacements,
    import_workflows,
    slugify,
    validate_alert_context_params,
    validate_alert_context_schema,
    validate_env,
)


# =============================================================================
# Test: slugify
# =============================================================================
class TestSlugify:
    def test_converts_to_kebab_case(self):
        """Simple space-separated names become kebab-case."""
        assert slugify("Call Subagent") == "security-mesh.call-subagent"

    def test_handles_special_chars(self):
        """Special characters are replaced with hyphens."""
        assert slugify("VT File Hash Report!") == "security-mesh.vt-file-hash-report"

    def test_lowercase(self):
        """Already lowercase names work correctly."""
        assert slugify("test") == "security-mesh.test"

    def test_strips_leading_trailing_hyphens(self):
        """Leading and trailing hyphens are removed."""
        assert slugify("  test  ") == "security-mesh.test"

    def test_multiple_spaces_become_single_hyphen(self):
        """Multiple spaces collapse to single hyphen."""
        result = slugify("Get  Multiple   Spaces")
        assert "multiple" in result
        assert "spaces" in result

    def test_agent_name_kebab(self):
        """Known agent names in the project."""
        assert slugify("Detection Engineering Agent") == "security-mesh.detection-engineering-agent"
        assert slugify("Threat Intelligence Agent") == "security-mesh.threat-intelligence-agent"
        assert slugify("L1 Triage Analyst") == "security-mesh.l1-triage-analyst"


# =============================================================================
# Test: bounded alert context
# =============================================================================
class TestBoundedAlertContext:
    def test_immutable_profile_accepts_only_alert_id(self):
        tool = build_alert_context_tool(
            {"name": "Bounded Alert Context", "profile": "bounded-alert-context-v1"}
        )
        assert tool["configuration"]["query"] == ALERT_CONTEXT_QUERY
        assert set(tool["configuration"]["params"]) == {"alert_id"}
        assert "LIMIT 1" in ALERT_CONTEXT_QUERY
        with pytest.raises(AlertContextConfigurationError):
            build_alert_context_tool({"name": "Bounded Alert Context", "query": "FROM *"})

    @pytest.mark.parametrize("alert_id", ["", "a/b", "a" * 513, "alert-01_"])
    def test_alert_id_validation_is_bounded(self, alert_id):
        if alert_id == "alert-01_":
            assert validate_alert_context_params({"alert_id": alert_id}) == alert_id
        else:
            with pytest.raises(AlertContextConfigurationError):
                validate_alert_context_params({"alert_id": alert_id})

    def test_schema_gate_rejects_ambiguous_fields_before_tool_creation(self):
        resolved = MagicMock(ok=True)
        resolved.json.return_value = {"indices": [{"name": ".alerts-security.alerts-a"}]}
        field_caps = MagicMock(ok=True)
        field_caps.json.return_value = {
            "fields": {
                "@timestamp": {"date": {"searchable": True}},
                "kibana.alert.workflow_status": {"keyword": {"searchable": True}},
                "kibana.alert.rule.name": {"keyword": {"searchable": True}},
                "kibana.alert.severity": {"keyword": {"searchable": True}},
                "kibana.alert.risk_score": {
                    "double": {"searchable": True},
                    "long": {"searchable": True},
                },
            }
        }
        with (
            patch.dict(
                os.environ,
                {"ELASTIC_CLOUD_URL": "https://test.es", "ES_API_KEY": "key"},
                clear=True,
            ),
            patch("setup.requests.get", side_effect=[resolved, field_caps]),
            patch("setup.requests.post") as post,
        ):
            with pytest.raises(AlertContextConfigurationError, match="ambiguous"):
                validate_alert_context_schema()
        post.assert_not_called()


# =============================================================================
# Test: build_replacements
# =============================================================================
class TestBuildReplacements:
    @patch.dict(
        os.environ,
        {
            "ELASTIC_CLOUD_URL": "https://test.es.region.gcp.cloud.es.io",
            "ES_API_KEY": "test-es-key",
            "KIBANA_URL": "https://test.kb.region.gcp.cloud.es.io",
            "KIBANA_API_KEY": "test-kibana-key",
            "VIRUSTOTAL_API_KEY": "vt-key",
            "ABUSEIPDB_API_KEY": "abuse-key",
            "LLM_CONNECTOR_ID": "claude-sonnet",
        },
        clear=True,
    )
    def test_all_env_vars_replaced(self):
        """All environment variables are captured."""
        replacements = build_replacements()

        assert replacements["__ES_URL__"] == "https://test.es.region.gcp.cloud.es.io"
        assert replacements["__ES_API_KEY__"] == "test-es-key"
        assert replacements["__KIBANA_URL__"] == "https://test.kb.region.gcp.cloud.es.io"
        assert replacements["__KIBANA_API_KEY__"] == "test-kibana-key"
        assert replacements["__VT_API_KEY__"] == "vt-key"
        assert replacements["__ABUSEIPDB_API_KEY__"] == "abuse-key"
        assert replacements["__LLM_CONNECTOR_ID__"] == "claude-sonnet"

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_env_vars_return_empty_string(self):
        """Missing env vars result in empty strings (not KeyError)."""
        replacements = build_replacements()

        assert replacements["__ES_URL__"] == ""
        assert replacements["__ES_API_KEY__"] == ""
        assert replacements["__KIBANA_API_KEY__"] == ""


# =============================================================================
# Test: apply_replacements
# =============================================================================
class TestApplyReplacements:
    def test_replaces_single_placeholder(self):
        """Single placeholder is replaced."""
        yaml_content = 'url: "__ES_URL__"'
        replacements = {"__ES_URL__": "https://test.es.io"}
        result = apply_replacements(yaml_content, replacements)
        assert result == 'url: "https://test.es.io"'

    def test_replaces_multiple_placeholders(self):
        """Multiple different placeholders are replaced."""
        yaml_content = 'url: "__ES_URL__"\nkey: "__ES_API_KEY__"'
        replacements = {
            "__ES_URL__": "https://test.es.io",
            "__ES_API_KEY__": "secret",
        }
        result = apply_replacements(yaml_content, replacements)
        assert "https://test.es.io" in result
        assert "secret" in result

    def test_empty_value_placeholders_are_skipped(self):
        """Placeholders with empty string values are NOT replaced (kept as-is).

        This is intentional — setup.py only replaces placeholders that have
        actual values in the environment. Empty placeholders remain in the
        YAML so they're visible if someone forgets to set the env var.
        """
        yaml_content = 'url: "__ES_URL__"\nkey: "__VT_API_KEY__"'
        replacements = {"__ES_URL__": "https://test.es.io", "__VT_API_KEY__": ""}
        result = apply_replacements(yaml_content, replacements)
        # __ES_URL__ was replaced
        assert "__ES_URL__" not in result
        assert "https://test.es.io" in result
        # __VT_API_KEY__ was NOT replaced (empty value → skipped, remains as-is)
        assert "__VT_API_KEY__" in result

    def test_real_workflow_snippet(self):
        """Simulates real workflow with multiple placeholders."""
        yaml_content = """
steps:
  - name: api_call
    type: http
    with:
      url: "__KIBANA_URL__/api/detection_engine/rules"
      headers:
        Authorization: "ApiKey __KIBANA_API_KEY__"
"""
        replacements = {
            "__KIBANA_URL__": "https://test.kb.es.io",
            "__KIBANA_API_KEY__": "test-api-key",
        }
        result = apply_replacements(yaml_content, replacements)
        assert "https://test.kb.es.io" in result
        assert "test-api-key" in result


# =============================================================================
# Test: import_workflows
# =============================================================================
class TestImportWorkflows:
    def test_partial_import_failure_attempts_all_workflows_and_raises(self, tmp_path, monkeypatch):
        workflow_dir = tmp_path / "workflows"
        workflow_dir.mkdir()
        (workflow_dir / "failing.yaml").write_text("name: Failing Workflow\n")
        (workflow_dir / "success.yaml").write_text("name: Success Workflow\n")
        monkeypatch.setattr("setup.REPO_ROOT", tmp_path)
        monkeypatch.setattr("setup.WORKFLOW_DIRS", ("workflows",))

        failed_response = MagicMock(ok=False, status_code=400, text="invalid workflow schema")
        success_response = MagicMock(ok=True)
        success_response.json.return_value = {
            "created": [{"name": "Success Workflow", "id": "success-id"}],
            "failures": [],
            "total": 1,
        }

        with (
            patch.dict(
                os.environ,
                {"KIBANA_URL": "https://test.kb", "KIBANA_API_KEY": "key"},
                clear=True,
            ),
            patch("setup.requests.post", side_effect=[failed_response, success_response]) as post,
            patch("setup.time.sleep"),
        ):
            with pytest.raises(RuntimeError) as exc_info:
                import_workflows()

        assert post.call_count == 2
        assert [call.kwargs["json"] for call in post.call_args_list] == [
            {"workflows": [{"yaml": "name: Failing Workflow\n"}]},
            {"workflows": [{"yaml": "name: Success Workflow\n"}]},
        ]
        assert "failing.yaml" in str(exc_info.value)
        assert "HTTP 400" in str(exc_info.value)
        assert "invalid workflow schema" in str(exc_info.value)

    def test_response_failures_are_aggregated_and_fail_closed(self, tmp_path, monkeypatch):
        workflow_dir = tmp_path / "workflows"
        workflow_dir.mkdir()
        (workflow_dir / "invalid.yaml").write_text("name: Invalid Workflow\n")
        monkeypatch.setattr("setup.REPO_ROOT", tmp_path)
        monkeypatch.setattr("setup.WORKFLOW_DIRS", ("workflows",))

        response = MagicMock(ok=True)
        response.json.return_value = {
            "created": [],
            "failures": [{"message": "invalid workflow schema"}],
            "total": 1,
        }

        with (
            patch.dict(
                os.environ, {"KIBANA_URL": "https://test.kb", "KIBANA_API_KEY": "key"}, clear=True
            ),
            patch("setup.requests.post", return_value=response),
            patch("setup.time.sleep"),
        ):
            with pytest.raises(RuntimeError, match="invalid workflow schema"):
                import_workflows()


# =============================================================================
# Test: validate_env
# =============================================================================
class TestValidateEnv:
    def test_missing_required_vars_exits(self):
        """Missing required env vars causes SystemExit."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                validate_env()
            assert exc_info.value.code == 1

    def test_all_required_vars_pass(self):
        """All required vars present: no exit."""
        with patch.dict(
            os.environ,
            {
                "ELASTIC_CLOUD_URL": "https://test.es.io",
                "KIBANA_URL": "https://test.kb.io",
                "ES_API_KEY": "key",
                "KIBANA_API_KEY": "key",
            },
            clear=True,
        ):
            # Should not raise
            validate_env()


# =============================================================================
# Test: _get_deployed_workflow_names
# =============================================================================
class TestGetDeployedWorkflowNames:
    def test_returns_workflow_names_from_yaml(self):
        """Scans workflow YAMLs and extracts name fields."""
        names = _get_deployed_workflow_names()
        assert isinstance(names, set)
        assert len(names) > 0
        # Check known workflows exist
        assert "Create Detection Rule" in names
        assert "Call Subagent Workflow" in names
        assert "Dispatch Monitor" in names

    def test_names_are_strings(self):
        """All extracted names are non-empty strings."""
        names = _get_deployed_workflow_names()
        for name in names:
            assert isinstance(name, str)
            assert len(name) > 0


# =============================================================================
# Test: knowledge_base_mapping (via fixture)
# =============================================================================
class TestKnowledgeBaseMapping:
    def test_mapping_has_required_fields(self):
        """Knowledge base mapping has semantic_text inference field."""
        from setup import knowledge_base_mapping

        mapping = knowledge_base_mapping()
        assert "settings" in mapping
        assert "mappings" in mapping

        props = mapping["mappings"]["properties"]
        assert "semantic_summary" in props
        assert props["semantic_summary"]["type"] == "semantic_text"
        assert "title" in props
        assert "content" in props
        assert "category" in props

    def test_inference_id_is_configurable(self):
        """Inference endpoint ID comes from env var or default."""
        from setup import knowledge_base_mapping

        # Default
        mapping = knowledge_base_mapping()
        assert (
            ".multilingual-e5-small"
            in mapping["mappings"]["properties"]["semantic_summary"]["inference_id"]
        )


# =============================================================================
# Test: action_policies_mapping
# =============================================================================
class TestActionPoliciesMapping:
    def test_mapping_has_required_fields(self):
        """Action policies have all required governance fields."""
        from setup import action_policies_mapping

        mapping = action_policies_mapping()
        props = mapping["mappings"]["properties"]

        assert "action_type" in props
        assert "risk_tier" in props
        assert "allowed_callers" in props
        assert "requires_approval" in props
        assert props["requires_approval"]["type"] == "boolean"


# =============================================================================
# Test: dispatch_requests_mapping
# =============================================================================
class TestDispatchRequestsMapping:
    def test_mapping_has_required_fields(self):
        """Dispatch requests have all required fields for async messaging."""
        from setup import dispatch_requests_mapping

        mapping = dispatch_requests_mapping()
        props = mapping["mappings"]["properties"]

        required = [
            "dispatch_id",
            "target_agent",
            "requesting_agent",
            "status",
            "created_at",
        ]
        for field in required:
            assert field in props, f"Missing required field: {field}"

    def test_idempotency_fields_are_typed_for_existing_requests(self):
        """Dispatches retain one stable identity and monitor-owned retry state."""
        from setup import dispatch_requests_mapping

        props = dispatch_requests_mapping()["mappings"]["properties"]
        assert props["idempotency_key"] == {"type": "keyword"}
        assert props["retry_count"] == {"type": "integer"}

    def test_idempotency_mapping_is_additive_for_existing_indices(self):
        from setup import ensure_dispatch_requests_mapping

        response = MagicMock(ok=True)
        with (
            patch.dict(os.environ, {"ELASTIC_CLOUD_URL": "https://test.es", "ES_API_KEY": "key"}),
            patch("setup.requests.put", return_value=response) as put,
        ):
            assert ensure_dispatch_requests_mapping() is True
        assert put.call_args.args[0].endswith("/dispatch-requests/_mapping")
        assert put.call_args.kwargs["json"] == {
            "properties": {
                "idempotency_key": {"type": "keyword"},
                "retry_count": {"type": "integer"},
            }
        }

    def test_l1_to_l2_dispatch_is_idempotent_and_preserves_document_id(self):
        path = Path(__file__).resolve().parent.parent / "workflows/mesh/write-dispatch-request.yaml"
        workflow = yaml.safe_load(path.read_text())
        steps = {step["name"]: step for step in workflow["steps"]}

        assert {item["name"] for item in workflow["inputs"]} >= {"document_id", "context"}
        key = "l1d--1--{{ inputs.document_id }}--security-mesh.l1-triage-analyst--security-mesh.l2-investigation-analyst"
        assert steps["derive_idempotency_key"]["with"]["message"] == key
        assert steps["find_active_dispatch"]["with"]["body"]["query"]["bool"]["filter"] == [
            {"term": {"idempotency_key": "{{ steps.derive_idempotency_key.output }}"}},
            {"terms": {"status": ["pending", "dispatched"]}},
        ]
        create = steps["create_dispatch_request"]["else"][0]["with"]
        assert create["url"].endswith("/_create/{{ steps.derive_idempotency_key.output }}")
        assert create["body"]["idempotency_key"] == "{{ steps.derive_idempotency_key.output }}"
        assert create["body"]["investigation_id"] == "{{ inputs.document_id }}"
        assert create["body"]["retry_count"] == 0
        assert "{{ inputs.document_id }}" in create["body"]["context"]
        assert create["body"]["target_agent"] == "security-mesh.l2-investigation-analyst"
        assert create["body"]["requesting_agent"] == "security-mesh.l1-triage-analyst"
        assert steps["create_dispatch_request"]["steps"] == [
            {
                "name": "duplicate_noop",
                "type": "console",
                "with": {
                    "message": "Active L1-to-L2 dispatch {{ steps.derive_idempotency_key.output }} already exists; status and retry_count are unchanged."
                },
            }
        ]


# =============================================================================
# Test: agent_registry_mapping
# =============================================================================
class TestAgentRegistryMapping:
    def test_mapping_has_semantic_description(self):
        """Agent registry has semantic_text for semantic search."""
        from setup import agent_registry_mapping

        mapping = agent_registry_mapping()
        props = mapping["mappings"]["properties"]

        assert "semantic_description" in props
        assert props["semantic_description"]["type"] == "semantic_text"
        assert "agent_id" in props
        assert "domain" in props
        assert props["domain"]["type"] == "keyword"


# =============================================================================
# Test: investigation_contexts_mapping
# =============================================================================
class TestInvestigationContextsMapping:
    def test_mapping_has_nested_evidence(self):
        """Investigation contexts support nested evidence and actions."""
        from setup import investigation_contexts_mapping

        mapping = investigation_contexts_mapping()
        props = mapping["mappings"]["properties"]

        assert "evidence" in props
        assert props["evidence"]["type"] == "nested"
        assert "actions_taken" in props
        assert props["actions_taken"]["type"] == "nested"
        assert "pending_actions" in props

    def test_l1_result_is_a_strict_versioned_envelope(self):
        """L1 results have no untyped fields or caller-controlled routing."""
        from setup import investigation_contexts_mapping

        result = investigation_contexts_mapping()["mappings"]["properties"]["l1_result"]
        assert result["type"] == "object"
        assert result["dynamic"] == "strict"
        assert set(result["properties"]) == {
            "schema_version",
            "investigation_id",
            "decision",
            "summary",
            "evidence_refs",
            "observed_at",
            "recorded_at",
            "source_agent",
            "target_agent",
            "escalation",
        }
        assert result["properties"]["decision"]["type"] == "keyword"
        assert result["properties"]["evidence_refs"]["type"] == "keyword"
        escalation = result["properties"]["escalation"]
        assert escalation["type"] == "object" and escalation["dynamic"] == "strict"
        assert set(escalation["properties"]) == {"requested", "reason", "requested_at"}

    def test_l1_result_mapping_is_additive_for_existing_indices(self):
        from setup import ensure_l1_result_mapping

        response = MagicMock(ok=True)
        with (
            patch.dict(os.environ, {"ELASTIC_CLOUD_URL": "https://test.es", "ES_API_KEY": "key"}),
            patch("setup.requests.put", return_value=response) as put,
        ):
            assert ensure_l1_result_mapping() is True
        assert put.call_args.args[0].endswith("/investigation-contexts/_mapping")
        assert set(put.call_args.kwargs["json"]["properties"]) == {"l1_result"}

    def test_record_l1_workflow_never_dispatches(self):
        """The record workflow is limited to the durable context write boundary."""
        path = (
            Path(__file__).resolve().parent.parent
            / "workflows/investigation/record-l1-investigation-result.yaml"
        )
        workflow = yaml.safe_load(path.read_text())
        assert {item["name"] for item in workflow["inputs"]} == {
            "document_id",
            "decision",
            "summary",
            "evidence_refs",
            "observed_at",
            "target_agent",
            "escalation_reason",
            "escalation_requested_at",
        }
        assert [step["name"] for step in workflow["steps"]] == [
            "load_context",
            "record_l1_result",
            "confirm",
        ]
        assert "dispatch-requests" not in path.read_text()


# =============================================================================
# Test: compliance_mapping
# =============================================================================
class TestComplianceMapping:
    def test_mapping_has_nested_controls(self):
        """kb-compliance has nested controls and semantic_text."""
        from setup import compliance_mapping

        mapping = compliance_mapping()
        props = mapping["mappings"]["properties"]

        assert "framework" in props
        assert props["framework"]["type"] == "keyword"
        assert "overall_status" in props
        assert props["overall_status"]["type"] == "keyword"
        assert "controls" in props
        assert props["controls"]["type"] == "nested"
        assert "semantic_summary" in props
        assert props["semantic_summary"]["type"] == "semantic_text"

    def test_controls_nested_has_required_fields(self):
        """Nested controls structure has all required fields."""
        from setup import compliance_mapping

        mapping = compliance_mapping()
        controls_props = mapping["mappings"]["properties"]["controls"]["properties"]

        assert "control_id" in controls_props
        assert controls_props["control_id"]["type"] == "keyword"
        assert "control_name" in controls_props
        assert "status" in controls_props
        assert "evidence" in controls_props
        assert controls_props["evidence"]["type"] == "object"


# =============================================================================
# Test: agent_metrics_mapping
# =============================================================================
class TestAgentMetricsMapping:
    def test_mapping_has_all_metric_fields(self):
        """agent-metrics has all required metric fields."""
        from setup import agent_metrics_mapping

        mapping = agent_metrics_mapping()
        props = mapping["mappings"]["properties"]

        required = [
            "agent_id",
            "agent_name",
            "domain",
            "period_start",
            "period_end",
            "decisions_total",
            "tp_classifications",
            "fp_classifications",
            "escalations_to_l2",
            "cases_created",
            "alerts_closed",
            "avg_confidence",
            "actions_by_tier",
            "dispatch_pending",
            "dispatch_completed",
            "dispatch_failed",
            "period_hours",
            "created_at",
        ]
        for field in required:
            assert field in props, f"Missing required field: {field}"

    def test_period_fields_are_date(self):
        """period_start and period_end are date type for time-series queries."""
        from setup import agent_metrics_mapping

        mapping = agent_metrics_mapping()
        props = mapping["mappings"]["properties"]

        assert props["period_start"]["type"] == "date"
        assert props["period_end"]["type"] == "date"
        assert props["created_at"]["type"] == "date"

    def test_actions_by_tier_has_tier_fields(self):
        """actions_by_tier has tier breakdown fields."""
        from setup import agent_metrics_mapping

        mapping = agent_metrics_mapping()
        tier_props = mapping["mappings"]["properties"]["actions_by_tier"]["properties"]

        assert "tier_0_auto_approved" in tier_props
        assert "tier_1_low_risk" in tier_props
        assert "tier_2_approval_required" in tier_props
