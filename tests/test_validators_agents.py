import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
import yaml

from scripts.validators.agents import ROLE_TOOLSETS, validate_agent_yaml


DEFINITIONS = ROOT / "agents" / "definitions"


@pytest.mark.parametrize("filename, expected", ROLE_TOOLSETS.items())
def test_role_definitions_have_exact_tool_sets(filename, expected):
    agent = yaml.safe_load((DEFINITIONS / filename).read_text())
    assert {tool["name"] for tool in agent["tools"]} == expected
    assert validate_agent_yaml(DEFINITIONS / filename, set()) == []


@pytest.mark.parametrize(
    "filename, prohibited",
    [
        ("l1-triage-analyst.yaml", "Get Investigation"),
        ("l2-investigation-analyst.yaml", "Dispatch Specialist"),
        ("l1-triage-analyst.yaml", "Call Subagent"),
        ("l1-triage-analyst.yaml", "Create Case"),
        ("l2-investigation-analyst.yaml", "Create Timeline"),
        ("l2-investigation-analyst.yaml", "Isolate Host"),
        ("l2-investigation-analyst.yaml", "Request Approval"),
        ("l2-investigation-analyst.yaml", "External Webhook"),
    ],
)
def test_role_definitions_reject_prohibited_or_cross_role_tools(tmp_path, filename, prohibited):
    agent = yaml.safe_load((DEFINITIONS / filename).read_text())
    agent["tools"].append({"name": prohibited})
    path = tmp_path / filename
    path.write_text(yaml.safe_dump(agent))
    assert any("Role tool set must equal" in error for error in validate_agent_yaml(path, set()))
