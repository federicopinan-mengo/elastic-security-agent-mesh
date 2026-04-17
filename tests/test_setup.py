#!/usr/bin/env python3
"""
Unit tests for setup.py

Run with: pytest tests/test_setup.py -v
"""

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Add scripts/ to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from setup import (
    slugify,
    build_replacements,
    apply_replacements,
    validate_env,
    _get_deployed_workflow_names,
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
        assert (
            slugify("Detection Engineering Agent")
            == "security-mesh.detection-engineering-agent"
        )
        assert (
            slugify("Threat Intelligence Agent")
            == "security-mesh.threat-intelligence-agent"
        )
        assert slugify("L1 Triage Analyst") == "security-mesh.l1-triage-analyst"


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
            "KIBANA_SPACE": "my-space",
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
        assert (
            replacements["__KIBANA_URL__"] == "https://test.kb.region.gcp.cloud.es.io"
        )
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
