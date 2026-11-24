"""The approval monitor must read the comment history, not the last comment.

A decision can be followed by unrelated chatter; the monitor has to keep the
decision it already found.
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / "workflows" / "governance" / "approval-monitor.yaml"


def load():
    return yaml.safe_load(WORKFLOW.read_text())


def all_steps(workflow):
    """Every step of the workflow, including the bodies of if/foreach."""
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


def test_approval_monitor_reads_the_comment_history_not_the_last_comment():
    workflow = load()
    fetch = find_step(workflow, "fetch_recent_comments")
    assert fetch["with"]["query"]["perPage"] >= 20
    assert "fetch_latest_comment" not in {s["name"] for s in all_steps(workflow)}


def test_approval_monitor_decision_ignores_a_negative_approval():
    """'NOT APPROVED' must not be read as an approval."""
    workflow = load()
    decide = find_step(workflow, "decide_approval")["with"]["message"]
    assert "NOT APPROVED" in decide
    assert "Human Approval Required" in decide


def test_approval_monitor_conditions_read_the_decision_token():
    workflow = load()
    conditions = [step.get("condition", "") for step in all_steps(workflow) if step["type"] == "if"]
    decision_conditions = [c for c in conditions if "decide_approval" in c]
    assert len(decision_conditions) >= 3
    assert not [c for c in conditions if "latest_comment_text" in c]
