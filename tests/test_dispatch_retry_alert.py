"""Regression tests for the exhausted-retry alert in dispatch-monitor.yaml.

The audit found that the retry chain in workflows/mesh/dispatch-monitor.yaml
ended without a trace: the exhausted branch was selected from the pre-update
search snapshot, and the failure log always claimed the dispatch had been reset
for retry. These tests pin the fixed behaviour at the workflow-definition
level, because the alert cannot be exercised without a live Kibana.
"""

from pathlib import Path

import yaml

WORKFLOW = (
    Path(__file__).resolve().parent.parent / "workflows" / "mesh" / "dispatch-monitor.yaml"
)


def load_workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def iter_steps(node):
    """Yield every step-like mapping (a dict with a name and a type)."""
    if isinstance(node, dict):
        if isinstance(node.get("name"), str) and isinstance(node.get("type"), str):
            yield node
        for value in node.values():
            yield from iter_steps(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_steps(item)


def step_named(steps, name):
    for step in iter_steps(steps):
        if step["name"] == name:
            return step
    raise AssertionError(f"step {name!r} not found in {WORKFLOW}")


class TestExhaustedRetryAlert:
    def test_agent_failure_branch_contains_the_alert(self):
        """The alert must live in the branch that handles the agent failure."""
        workflow = load_workflow()
        failure_branch = step_named(workflow, "check_failed")
        names = {step["name"] for step in iter_steps(failure_branch)}
        assert "check_retries_exhausted" in names
        assert "notify_failure_on_case" in names

    def test_exhausted_branch_posts_a_case_comment(self):
        """The alert action is a real Case comment, not just a retry config."""
        workflow = load_workflow()
        exhausted = step_named(workflow, "check_retries_exhausted")
        alerts = [
            step
            for step in iter_steps(exhausted.get("steps", []))
            if step.get("type") == "kibana.request"
            and "/api/cases/" in str(step.get("with", {}).get("path", ""))
        ]
        assert alerts, "no kibana.request alert against /api/cases/ in the exhausted branch"
        assert all(alert["with"]["path"].rstrip("/").endswith("/comments") for alert in alerts)

    def test_exhaustion_is_decided_on_persisted_state(self):
        """The branch must not decide exhaustion from the pre-update snapshot."""
        workflow = load_workflow()
        exhausted = step_named(workflow, "check_retries_exhausted")
        condition = exhausted["condition"]
        assert "foreach.item" not in condition
        assert "steps.dispatch_status.output" in condition
        reload_step = step_named(workflow, "reload")
        assert reload_step["with"]["method"] == "GET"
        assert "/_doc/" in reload_step["with"]["path"]

    def test_no_condition_reads_the_stale_retry_count(self):
        """foreach.item._source.retry_count predates the retry increment."""
        workflow = load_workflow()
        for step in iter_steps(workflow):
            condition = step.get("condition")
            if isinstance(condition, str):
                assert "foreach.item._source.retry_count" not in condition

    def test_failure_log_does_not_claim_a_retry_when_exhausted(self):
        """The old log always said the dispatch was reset for retry."""
        workflow = load_workflow()
        for step in iter_steps(workflow):
            if step.get("type") != "console":
                continue
            message = str(step.get("with", {}).get("message", ""))
            assert "reset to pending" not in message
        exhausted = step_named(workflow, "check_retries_exhausted")
        final_log = step_named(exhausted["steps"], "log_failure_final")
        assert "attempts" in final_log["with"]["message"]
