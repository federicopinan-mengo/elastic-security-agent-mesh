#!/usr/bin/env python3
"""Guards for the conditions that the workflow engine can actually evaluate.

The engine exposes each step as `{input, output, error}`; it does not expose a
per step status, so a condition on `steps.<name>.status` never matches and the
branch it guards never runs.
"""

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIRS = [ROOT / "workflows", ROOT / "agents" / "setup"]

STATUS_GUARD = re.compile(r"steps\.[A-Za-z_][\w]*\.status\b")


def workflow_files():
    for directory in WORKFLOW_DIRS:
        yield from sorted(directory.rglob("*.yaml"))


def load(path):
    return yaml.safe_load(path.read_text())


def iter_steps(steps):
    """Yield every step, including the ones nested in if/foreach/parallel."""
    if isinstance(steps, dict):
        steps = [steps]
    for step in steps or []:
        if not isinstance(step, dict):
            continue
        yield step
        for key in ("steps", "else"):
            body = step.get(key)
            if isinstance(body, dict):
                body = [body]
            yield from iter_steps(body)


def step_named(workflow, name):
    for step in iter_steps(workflow.get("steps", [])):
        if step.get("name") == name:
            return step
    raise AssertionError(f"no step named {name}")


def test_no_workflow_guards_on_a_step_status():
    """`steps.<name>.status` is not exposed, so the guard can never be true."""
    offenders = []
    for path in workflow_files():
        for match in STATUS_GUARD.finditer(path.read_text()):
            line = path.read_text()[: match.start()].count("\n") + 1
            offenders.append(f"{path.relative_to(ROOT)}:{line}")
    assert not offenders, "conditions on a step status: " + ", ".join(offenders)


@pytest.mark.parametrize(
    "name",
    [
        "create-action-policies-index.yaml",
        "create-agent-registry.yaml",
        "create-approval-requests-index.yaml",
        "create-dispatch-requests-index.yaml",
        "create-investigation-index.yaml",
        "create-knowledge-index.yaml",
    ],
)
def test_the_index_bootstrap_creates_through_the_fallback(name):
    """The index is created only when the check failed, that is when it is missing."""
    workflow = load(ROOT / "agents" / "setup" / name)
    check = step_named(workflow, "check_index_exists")
    on_failure = check.get("on-failure", {})
    fallback = on_failure.get("fallback")
    assert fallback, f"{name}: the check step has no fallback"
    assert on_failure.get("continue") is True, f"{name}: the check step does not continue"
    creates = [step for step in fallback if step.get("type") == "elasticsearch.request"]
    assert creates, f"{name}: the fallback does not create the index"
    assert all(step["with"]["method"] == "PUT" for step in creates)


def test_the_document_removal_deletes_and_reports_the_outcome():
    """The delete is idempotent and the report reads the delete result."""
    workflow = load(ROOT / "workflows" / "knowledge" / "remove-knowledge-document.yaml")
    delete = step_named(workflow, "delete_document")
    assert delete["with"]["method"] == "DELETE"
    assert delete["on-failure"]["continue"] is True
    report = step_named(workflow, "confirm")
    assert "steps.delete_document.output.result" in report["with"]["message"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
