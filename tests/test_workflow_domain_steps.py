"""Structural checks for the domain-step migrations.

These assert the shape of the workflow YAML, not its runtime behavior: the
`cases.*` payloads are only exercised by a live Kibana, so the schema is
pinned here as a contract that a future edit has to keep.
"""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / "workflows"

CASE_WORKFLOWS = {
    "security/response/createcasetool.yaml": "cases.createCase",
    "security/response/get-case-details.yaml": "cases.getCase",
    "security/response/update-case-status.yaml": "cases.updateCase",
    "security/response/add-case-comment.yaml": "cases.addComment",
    "security/response/add-alert-to-case.yaml": "cases.addAlerts",
}


def load(relative_path):
    return yaml.safe_load((WORKFLOWS / relative_path).read_text())


def step_types(workflow):
    return [step["type"] for step in workflow["steps"]]


def all_steps(workflow):
    """Every step of a workflow, including the bodies of if/foreach/parallel."""
    found = []

    def walk(steps):
        for step in steps:
            found.append(step)
            walk(step.get("steps", []))
            otherwise = step.get("else")
            if isinstance(otherwise, dict):
                walk([otherwise])
            elif isinstance(otherwise, list):
                walk(otherwise)

    walk(workflow.get("steps", []))
    return found


def find_step(workflow, name):
    for step in all_steps(workflow):
        if step["name"] == name:
            return step
    raise AssertionError(f"step {name} not found")


@pytest.mark.parametrize("relative_path,expected_type", sorted(CASE_WORKFLOWS.items()))
def test_case_workflows_use_the_cases_domain_steps(relative_path, expected_type):
    workflow = load(relative_path)
    assert expected_type in step_types(workflow)


@pytest.mark.parametrize("relative_path", sorted(CASE_WORKFLOWS))
def test_case_workflows_no_longer_call_the_cases_rest_api(relative_path):
    raw = (WORKFLOWS / relative_path).read_text()
    assert "/api/cases" not in raw
    assert "kibana.request" not in raw


def test_case_references_read_the_case_object():
    """Every case step returns {case: {...}}, so the refs must say .case."""
    workflow = load("security/response/get-case-details.yaml")
    message = find_step(workflow, "output_details")["with"]["message"]
    assert "steps.get_case.output.case.id" in message
    assert "steps.get_case.output.id" not in message


def test_update_case_wraps_the_fields_in_updates():
    """cases.updateCase requires the fields inside an `updates` object."""
    workflow = load("security/response/update-case-status.yaml")
    payload = find_step(workflow, "update_case")["with"]
    assert set(payload) == {"case_id", "version", "updates"}
    assert set(payload["updates"]) == {"status", "severity"}
