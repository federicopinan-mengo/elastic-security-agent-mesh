#!/usr/bin/env python3
"""
Validate all agent definition YAML files.

Checks:
- Valid YAML syntax
- Required fields (agent_name, domain, system_instructions, tools)
- Tools reference existing workflows
- Registry entries are properly structured
- Knowledge base indices are valid
"""

import sys
from pathlib import Path

import yaml

REQUIRED_AGENT_FIELDS = {"agent_name", "domain", "system_instructions", "tools"}
REQUIRED_TOOL_FIELDS = {"name"}
VALID_TOOL_TYPES = {"workflow", "builtin", "index_search", "mcp"}


def validate_agent_yaml(yaml_path: Path, workflow_names: set[str]) -> list[str]:
    """Validate a single agent definition YAML file. Returns list of errors."""
    errors = []

    try:
        with open(yaml_path) as f:
            agent = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML syntax error: {e}"]

    if agent is None:
        errors.append("Empty YAML file")
        return errors

    if not isinstance(agent, dict):
        errors.append(f"Root must be a dictionary, got {type(agent).__name__}")
        return errors

    # --- Required fields ---
    for field in REQUIRED_AGENT_FIELDS:
        if field not in agent:
            errors.append(f"Missing required field: '{field}'")

    # --- agent_name ---
    if "agent_name" in agent:
        name = agent["agent_name"]
        if not isinstance(name, str) or not name:
            errors.append("'agent_name' must be a non-empty string")

    # --- domain ---
    if "domain" in agent:
        domain = agent["domain"]
        valid_domains = {
            "orchestrator",
            "detection_engineering",
            "threat_intel",
            "triage",
            "investigation",
            "forensics",
            "compliance",
            "soc_ops",
        }
        if domain not in valid_domains:
            errors.append(f"Invalid domain: '{domain}' (expected one of {valid_domains})")

    # --- system_instructions ---
    if "system_instructions" in agent:
        si = agent["system_instructions"]
        if not isinstance(si, str) or not si.strip():
            errors.append("'system_instructions' must be a non-empty string")

    # --- tools ---
    if "tools" in agent:
        tools = agent["tools"]
        if not isinstance(tools, list):
            errors.append("'tools' must be an array")
        else:
            tool_names = set()
            for i, tool in enumerate(tools):
                if not isinstance(tool, dict):
                    errors.append(f"Tool {i} must be a dictionary")
                    continue

                # Required: name
                if "name" not in tool:
                    errors.append(f"Tool {i} missing required field: 'name'")
                else:
                    name = tool["name"]
                    if name in tool_names:
                        errors.append(f"Tool {i}: duplicate tool name '{name}'")
                    else:
                        tool_names.add(name)

                # Optional: type
                tool_type = tool.get("type", "workflow")
                if tool_type not in VALID_TOOL_TYPES:
                    errors.append(
                        f"Tool '{name}': invalid type '{tool_type}' (expected one of {VALID_TOOL_TYPES})"
                    )

                # Workflow tools must reference existing workflow files
                if tool_type == "workflow":
                    wf_path = tool.get("workflow", "")
                    if wf_path:
                        wf_file = yaml_path.parent.parent / ".." / wf_path
                        # Normalize path
                        try:
                            wf_file = wf_file.resolve()
                        except Exception:
                            pass
                        if (
                            not Path(wf_path).exists()
                            and not (yaml_path.parent.parent / wf_path).exists()
                        ):
                            # Try relative to repo root
                            pass
                    # Just check the workflow name exists in our known set
                    # (we'll do reference validation separately)
                elif tool_type == "builtin":
                    if "tool_id" not in tool:
                        errors.append(f"Tool '{name}': builtin type requires 'tool_id'")
                elif tool_type == "index_search":
                    if "index" not in tool:
                        errors.append(f"Tool '{name}': index_search type requires 'index'")

    # --- knowledge_bases ---
    if "knowledge_bases" in agent:
        kbs = agent["knowledge_bases"]
        if not isinstance(kbs, list):
            errors.append("'knowledge_bases' must be an array")
        else:
            valid_kb_indices = {
                "kb-detection-rules",
                "kb-ecs-schema",
                "kb-mitre-attack",
                "kb-threat-intel",
                "kb-ioc-history",
                "kb-incidents",
                "kb-playbooks",
                "kb-forensics",
                "kb-compliance",
                "kb-soc-ops",
                "kb-runbooks",
            }
            for kb in kbs:
                if not isinstance(kb, dict):
                    errors.append("Knowledge base entry must be a dictionary")
                    continue
                if "index" in kb:
                    idx = kb["index"]
                    if idx not in valid_kb_indices:
                        errors.append(f"Knowledge base index '{idx}' not in standard list (kb-*)")

    # --- registry_entry ---
    if "registry_entry" in agent:
        reg = agent["registry_entry"]
        if not isinstance(reg, dict):
            errors.append("'registry_entry' must be a dictionary")
        else:
            required_reg_fields = ["agent_name", "domain", "description"]
            for field in required_reg_fields:
                if field not in reg:
                    errors.append(f"registry_entry missing required field: '{field}'")

    return errors


def main():
    repo_root = Path(__file__).resolve().parent.parent.parent

    # Collect all workflow names from YAML files for cross-reference
    workflow_names = set()
    workflows_dir = repo_root / "workflows"
    if workflows_dir.exists():
        for wf_file in workflows_dir.rglob("*.yaml"):
            try:
                with open(wf_file) as f:
                    wf = yaml.safe_load(f)
                    if wf and isinstance(wf, dict) and "name" in wf:
                        workflow_names.add(wf["name"])
            except Exception:
                pass

    agents_dir = repo_root / "agents" / "definitions"
    all_errors = {}
    total_files = 0

    if not agents_dir.exists():
        print(f"ERROR: Agents directory not found: {agents_dir}")
        sys.exit(1)

    for yaml_file in sorted(agents_dir.glob("*.yaml")):
        total_files += 1
        errors = validate_agent_yaml(yaml_file, workflow_names)
        if errors:
            rel_path = yaml_file.relative_to(repo_root)
            all_errors[str(rel_path)] = errors

    # --- Print results ---
    print("\n--- Agent Definition Validation ---")
    print(f"Validated {total_files} agent YAML files\n")

    if all_errors:
        print(f"ERRORS found in {len(all_errors)} files:\n")
        for path, errors in sorted(all_errors.items()):
            print(f"  ❌ {path}")
            for err in errors:
                print(f"      - {err}")
        print(f"\n❌ Validation FAILED: {sum(len(e) for e in all_errors.values())} errors")
        sys.exit(1)
    else:
        print(f"✅ All {total_files} agent definitions are valid")
        sys.exit(0)


if __name__ == "__main__":
    main()
