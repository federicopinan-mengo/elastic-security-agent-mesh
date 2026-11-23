#!/usr/bin/env python3
"""Unit tests for the workflow validators.

Covers the error branches of:

- scripts/validators/workflows.py    (workflow YAML schema)
- scripts/validators/placeholders.py  (unreplaced ``__PLACEHOLDER__`` values)
- scripts/validators/references.py   (agent -> workflow references)

The two validators whose logic lives entirely in ``main()`` (placeholders and
references) are exercised as subprocesses against a temporary repository
layout, because they derive their repository root from ``__file__``.

Run with: pytest tests/test_validators.py -v
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validators.placeholders import KNOWN_PLACEHOLDERS, check_file  # noqa: E402
from scripts.validators.workflows import validate_workflow_yaml  # noqa: E402

VALIDATORS_DIR = ROOT / "scripts" / "validators"


# =============================================================================
# Helpers
# =============================================================================
def validate(tmp_path, content, name="workflow.yaml"):
    """Write a workflow YAML into tmp_path and validate it."""
    path = tmp_path / name
    path.write_text(content)
    return validate_workflow_yaml(path)


def validator_repo(tmp_path):
    """Copy the validator package into a temporary repository root."""
    dest = tmp_path / "scripts" / "validators"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(VALIDATORS_DIR, dest, dirs_exist_ok=True)
    return tmp_path


def run_validator(tmp_path, module):
    """Run a validator's main() against the temporary repository root."""
    return subprocess.run(
        [sys.executable, "-m", f"scripts.validators.{module}"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
    )


# =============================================================================
# Test: workflows validator
# =============================================================================
class TestWorkflowsValidator:
    def test_valid_workflow_has_no_errors(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Valid Workflow\n"
            "steps:\n"
            "  - name: do_thing\n"
            "    type: console\n"
            "    with:\n"
            "      message: hello\n",
        )
        assert errors == []

    def test_malformed_yaml_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: [unclosed\n")
        assert len(errors) == 1
        assert errors[0].startswith("YAML syntax error:")

    def test_empty_file_is_reported(self, tmp_path):
        errors = validate(tmp_path, "")
        assert errors == ["Empty YAML file"]

    def test_non_dictionary_root_is_reported(self, tmp_path):
        errors = validate(tmp_path, "- one\n- two\n")
        assert errors == ["Root must be a dictionary, got list"]

    def test_missing_name_is_reported(self, tmp_path):
        errors = validate(tmp_path, "steps:\n  - name: a\n    type: console\n")
        assert "Missing required field: 'name'" in errors

    def test_empty_name_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: ''\nsteps:\n  - name: a\n    type: console\n")
        assert "'name' must be a non-empty string" in errors

    def test_non_string_name_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: 42\nsteps:\n  - name: a\n    type: console\n")
        assert "'name' must be a non-empty string" in errors

    def test_missing_steps_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: No Steps\n")
        assert "Missing required field: 'steps'" in errors

    def test_non_array_steps_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: Bad Steps\nsteps: not-a-list\n")
        assert "'steps' must be an array" in errors

    def test_empty_steps_list_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: No Steps\nsteps: []\n")
        assert "'steps' must have at least one step" in errors

    def test_non_dictionary_step_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: Bad Step\nsteps:\n  - just-a-string\n")
        assert "Step 0 must be a dictionary" in errors

    def test_step_without_name_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: Bad Step\nsteps:\n  - type: console\n")
        assert "Step 0 missing required field: 'name'" in errors

    def test_empty_step_name_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: Bad Step\nsteps:\n  - name: ''\n    type: console\n")
        assert "Step 0: 'name' must be a non-empty string" in errors

    def test_non_string_step_name_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: Bad Step\nsteps:\n  - name: 7\n    type: console\n")
        assert "Step 0: 'name' must be a non-empty string" in errors

    def test_duplicate_step_names_are_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Duplicate Steps\n"
            "steps:\n"
            "  - name: same\n"
            "    type: console\n"
            "  - name: same\n"
            "    type: console\n",
        )
        assert "Step 1: duplicate step name 'same'" in errors

    def test_step_without_type_is_reported(self, tmp_path):
        errors = validate(tmp_path, "name: Bad Step\nsteps:\n  - name: a\n")
        assert "Step 0 missing required field: 'type'" in errors

    def test_if_step_without_condition_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad If\n"
            "steps:\n"
            "  - name: cond\n"
            "    type: if\n"
            "    steps:\n"
            "      - name: inner\n"
            "        type: console\n",
        )
        assert "Step 'cond': 'if' step missing 'condition'" in errors

    def test_if_step_without_nested_steps_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad If\n"
            "steps:\n"
            "  - name: cond\n"
            "    type: if\n"
            "    with:\n"
            "      condition: 'true'\n",
        )
        assert "Step 'cond': 'if' step missing 'steps'" in errors

    def test_non_array_triggers_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad Triggers\ntriggers: manual\nsteps:\n  - name: a\n    type: console\n",
        )
        assert "'triggers' must be an array" in errors

    def test_non_dictionary_trigger_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad Triggers\ntriggers:\n  - manual\nsteps:\n  - name: a\n    type: console\n",
        )
        assert "Each trigger must be a dictionary" in errors

    def test_trigger_without_type_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad Triggers\ntriggers:\n  - id: t1\nsteps:\n  - name: a\n    type: console\n",
        )
        assert "Trigger missing 'type' field" in errors

    def test_unknown_trigger_type_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad Triggers\n"
            "triggers:\n"
            "  - type: cron\n"
            "steps:\n"
            "  - name: a\n"
            "    type: console\n",
        )
        assert any("Invalid trigger type: 'cron'" in error for error in errors)

    def test_non_dictionary_input_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad Inputs\ninputs:\n  - just-a-string\nsteps:\n  - name: a\n    type: console\n",
        )
        assert "Input must be a dictionary, got str" in errors

    def test_input_without_name_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad Inputs\ninputs:\n  - type: text\nsteps:\n  - name: a\n    type: console\n",
        )
        assert "Input missing 'name' field" in errors

    def test_invalid_inputs_type_is_reported(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Bad Inputs\ninputs: 5\nsteps:\n  - name: a\n    type: console\n",
        )
        assert "'inputs' must be an object or array" in errors

    def test_unknown_action_type_is_allowed(self, tmp_path):
        """Custom action types are tolerated (warning-only design)."""
        errors = validate(
            tmp_path,
            "name: Custom Action\nsteps:\n  - name: a\n    type: my.custom.action\n",
        )
        assert errors == []

    def test_object_form_inputs_are_valid(self, tmp_path):
        errors = validate(
            tmp_path,
            "name: Object Inputs\n"
            "inputs:\n"
            "  alert_id:\n"
            "    type: text\n"
            "steps:\n"
            "  - name: a\n"
            "    type: console\n",
        )
        assert errors == []


class TestWorkflowsValidatorMain:
    def test_valid_repository_passes(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        (repo / "workflows" / "ok.yaml").write_text(
            "name: Ok Workflow\nsteps:\n  - name: a\n    type: console\n"
        )
        result = run_validator(repo, "workflows")
        assert result.returncode == 0
        assert "are valid" in result.stdout

    def test_invalid_workflow_fails_the_run(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        (repo / "workflows" / "bad.yaml").write_text("name: Bad\nsteps: []\n")
        result = run_validator(repo, "workflows")
        assert result.returncode == 1
        assert "Validation FAILED" in result.stdout
        assert "bad.yaml" in result.stdout


# =============================================================================
# Test: placeholders validator
# =============================================================================
class TestPlaceholdersValidator:
    def test_file_without_placeholders_has_no_errors(self, tmp_path):
        path = tmp_path / "clean.yaml"
        path.write_text("name: Clean\nkey: value\n")
        assert check_file(path) == []

    def test_known_placeholder_is_reported(self, tmp_path):
        path = tmp_path / "orphan.yaml"
        path.write_text("name: Orphan\nkey: __ES_API_KEY__\n")
        errors = check_file(path)
        assert len(errors) == 1
        assert errors[0] == "Found orphaned placeholder(s): __ES_API_KEY__"

    def test_multiple_orphans_are_deduplicated_and_sorted(self, tmp_path):
        path = tmp_path / "orphan.yaml"
        path.write_text("a: __ES_API_KEY__\nb: __ES_API_KEY__\nc: __KIBANA_URL__\n")
        errors = check_file(path)
        assert errors == ["Found orphaned placeholder(s): __ES_API_KEY__, __KIBANA_URL__"]

    def test_unknown_double_underscore_token_is_not_a_placeholder(self, tmp_path):
        path = tmp_path / "custom.yaml"
        path.write_text("a: __CUSTOM_THING__\n")
        assert check_file(path) == []

    def test_lowercase_token_is_not_a_placeholder(self, tmp_path):
        path = tmp_path / "lower.yaml"
        path.write_text("a: __es_url__\n")
        assert check_file(path) == []

    def test_unreadable_file_is_reported(self, tmp_path):
        errors = check_file(tmp_path / "missing.yaml")
        assert len(errors) == 1
        assert errors[0].startswith("Cannot read file:")

    def test_every_known_placeholder_is_detected(self, tmp_path):
        for placeholder in sorted(KNOWN_PLACEHOLDERS):
            path = tmp_path / f"{placeholder}.yaml"
            path.write_text(f"value: {placeholder}\n")
            errors = check_file(path)
            assert errors == [f"Found orphaned placeholder(s): {placeholder}"]


class TestPlaceholdersValidatorMain:
    def test_orphaned_placeholder_is_a_warning_not_a_failure(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        (repo / "workflows" / "orphan.yaml").write_text("key: __ES_API_KEY__\n")
        result = run_validator(repo, "placeholders")
        assert result.returncode == 0
        assert "Found orphaned placeholder(s): __ES_API_KEY__" in result.stdout

    def test_clean_repository_passes(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        (repo / "workflows" / "clean.yaml").write_text("key: value\n")
        result = run_validator(repo, "placeholders")
        assert result.returncode == 0
        assert "No orphaned placeholders found" in result.stdout


# =============================================================================
# Test: references validator
# =============================================================================
class TestReferencesValidatorMain:
    def test_valid_references_pass(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        (repo / "workflows" / "one.yaml").write_text(
            "name: One\nsteps:\n  - name: a\n    type: console\n"
        )
        definitions = repo / "agents" / "definitions"
        definitions.mkdir(parents=True)
        (definitions / "agent.yaml").write_text(
            "agent_name: agent\n"
            "tools:\n"
            "  - name: One\n"
            "    type: workflow\n"
            "    workflow: workflows/one.yaml\n"
        )
        result = run_validator(repo, "references")
        assert result.returncode == 0
        assert "All references are valid" in result.stdout

    def test_missing_agents_directory_fails_the_run(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        result = run_validator(repo, "references")
        assert result.returncode == 1
        assert "Agents directory not found" in result.stderr

    def test_dangling_workflow_reference_is_reported(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        definitions = repo / "agents" / "definitions"
        definitions.mkdir(parents=True)
        (definitions / "agent.yaml").write_text(
            "agent_name: agent\n"
            "tools:\n"
            "  - name: Ghost\n"
            "    type: workflow\n"
            "    workflow: workflows/does-not-exist.yaml\n"
        )
        result = run_validator(repo, "references")
        assert result.returncode == 1
        assert "workflow file not found: workflows/does-not-exist.yaml" in result.stdout

    def test_unparsable_agent_definition_is_reported(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        definitions = repo / "agents" / "definitions"
        definitions.mkdir(parents=True)
        (definitions / "agent.yaml").write_text("agent_name: [unclosed\n")
        result = run_validator(repo, "references")
        assert result.returncode == 1
        assert "Cannot read agent" in result.stdout

    def test_unparsable_workflow_is_reported(self, tmp_path):
        repo = validator_repo(tmp_path)
        (repo / "workflows").mkdir()
        (repo / "workflows" / "broken.yaml").write_text("name: [unclosed\n")
        definitions = repo / "agents" / "definitions"
        definitions.mkdir(parents=True)
        (definitions / "agent.yaml").write_text("agent_name: agent\ntools: []\n")
        result = run_validator(repo, "references")
        assert result.returncode == 1
        assert "Cannot read workflow" in result.stdout
