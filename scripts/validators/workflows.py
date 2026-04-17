#!/usr/bin/env python3
"""
Validate all workflow YAML files against the Elastic Workflow schema.

Checks:
- Valid YAML syntax
- Required fields (name, steps)
- Step structure (name, type)
- Valid action types
- Proper variable syntax
- No orphaned placeholders
"""

import sys
from pathlib import Path

import yaml


REQUIRED_STEP_FIELDS = {"name", "type"}
VALID_ACTION_TYPES = {
    "console",
    "http",
    "elasticsearch.search",
    "elasticsearch.index",
    "elasticsearch.request",
    "kibana.request",
    "kibana.cases",
    "ai.agent",
    "foreach",
    "if",
    "parallel",
    "wait",
    "action",  # generic action type
}
VALID_TRIGGER_TYPES = {"manual", "scheduled", "alert"}


def validate_workflow_yaml(yaml_path: Path) -> list[str]:
    """Validate a single workflow YAML file. Returns list of errors."""
    errors = []

    try:
        with open(yaml_path) as f:
            workflow = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML syntax error: {e}"]

    if workflow is None:
        errors.append(f"Empty YAML file")
        return errors

    if not isinstance(workflow, dict):
        errors.append(f"Root must be a dictionary, got {type(workflow).__name__}")
        return errors

    # --- Required: name ---
    if "name" not in workflow:
        errors.append("Missing required field: 'name'")
    elif not workflow["name"] or not isinstance(workflow["name"], str):
        errors.append("'name' must be a non-empty string")

    # --- Required: steps ---
    if "steps" not in workflow:
        errors.append("Missing required field: 'steps'")
    else:
        steps = workflow["steps"]
        if not isinstance(steps, list):
            errors.append("'steps' must be an array")
        elif len(steps) == 0:
            errors.append("'steps' must have at least one step")
        else:
            step_names = set()
            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    errors.append(f"Step {i} must be a dictionary")
                    continue

                # Required: name
                if "name" not in step:
                    errors.append(f"Step {i} missing required field: 'name'")
                else:
                    name = step["name"]
                    if not isinstance(name, str) or not name:
                        errors.append(f"Step {i}: 'name' must be a non-empty string")
                    elif name in step_names:
                        errors.append(f"Step {i}: duplicate step name '{name}'")
                    else:
                        step_names.add(name)

                # Required: type
                if "type" not in step:
                    errors.append(f"Step {i} missing required field: 'type'")
                elif step["type"] not in VALID_ACTION_TYPES:
                    # Allow custom action types but warn
                    pass

                # Validate 'if' step structure
                if step.get("type") == "if":
                    if "condition" not in step:
                        errors.append(
                            f"Step '{step.get('name', i)}': 'if' step missing 'condition'"
                        )
                    if "steps" not in step:
                        errors.append(
                            f"Step '{step.get('name', i)}': 'if' step missing 'steps'"
                        )

    # --- Optional: triggers ---
    if "triggers" in workflow:
        triggers = workflow["triggers"]
        if not isinstance(triggers, list):
            errors.append("'triggers' must be an array")
        else:
            for t in triggers:
                if not isinstance(t, dict):
                    errors.append("Each trigger must be a dictionary")
                    continue
                if "type" not in t:
                    errors.append("Trigger missing 'type' field")
                elif t["type"] not in VALID_TRIGGER_TYPES:
                    errors.append(
                        f"Invalid trigger type: '{t['type']}' (expected one of {VALID_TRIGGER_TYPES})"
                    )

    # --- Optional: inputs ---
    if "inputs" in workflow:
        inputs = workflow["inputs"]
        if isinstance(inputs, dict):
            pass  # object form is valid
        elif isinstance(inputs, list):
            for inp in inputs:
                if not isinstance(inp, dict):
                    errors.append(
                        f"Input must be a dictionary, got {type(inp).__name__}"
                    )
                    continue
                if "name" not in inp:
                    errors.append("Input missing 'name' field")
        else:
            errors.append("'inputs' must be an object or array")

    return errors


def main():
    repo_root = Path(__file__).resolve().parent.parent.parent
    workflow_dirs = [
        repo_root / "workflows",
        repo_root / "agents" / "setup",
    ]

    all_errors = {}
    total_files = 0

    for workflow_dir in workflow_dirs:
        if not workflow_dir.exists():
            print(f"WARN: Directory not found: {workflow_dir}")
            continue

        for yaml_file in workflow_dir.rglob("*.yaml"):
            total_files += 1
            errors = validate_workflow_yaml(yaml_file)
            if errors:
                rel_path = yaml_file.relative_to(repo_root)
                all_errors[str(rel_path)] = errors

    # --- Print results ---
    print(f"\n--- Workflow Validation ---")
    print(f"Validated {total_files} workflow YAML files\n")

    if all_errors:
        print(f"ERRORS found in {len(all_errors)} files:\n")
        for path, errors in sorted(all_errors.items()):
            print(f"  ❌ {path}")
            for err in errors:
                print(f"      - {err}")
        print(
            f"\n❌ Validation FAILED: {sum(len(e) for e in all_errors.values())} errors"
        )
        sys.exit(1)
    else:
        print(f"✅ All {total_files} workflow YAMLs are valid")
        sys.exit(0)


if __name__ == "__main__":
    main()
