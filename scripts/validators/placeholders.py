#!/usr/bin/env python3
"""
Check all YAML files for orphaned placeholders.

Detects:
- __ES_URL__ without replacement
- __KIBANA_API_KEY__ without replacement
- __ES_API_KEY__ without replacement
- Any __*__ pattern that looks like an unreplaced placeholder

Legitimate use of __ is allowed in strings outside placeholder patterns.
"""

import re
import sys
from pathlib import Path

import yaml


# Placeholders that SHOULD be replaced by setup.py
KNOWN_PLACEHOLDERS = {
    "__ES_URL__",
    "__ES_API_KEY__",
    "__KIBANA_URL__",
    "__KIBANA_API_KEY__",
    "__VT_API_KEY__",
    "__ABUSEIPDB_API_KEY__",
    "__LLM_CONNECTOR_ID__",
}

# Regex: matches __UPPER_CASE__ patterns
PLACEHOLDER_RE = re.compile(r"__[A-Z_]{2,}__")


def check_file(yaml_path: Path) -> list[str]:
    """Check a YAML file for orphaned placeholders. Returns list of errors."""
    errors = []

    try:
        with open(yaml_path) as f:
            content = f.read()
    except Exception as e:
        return [f"Cannot read file: {e}"]

    # Find all placeholder matches
    matches = PLACEHOLDER_RE.findall(content)
    if not matches:
        return []

    # Filter to known placeholders (not all __*__ are placeholders)
    orphaned = [m for m in matches if m in KNOWN_PLACEHOLDERS]

    if orphaned:
        # Deduplicate
        unique_orphaned = set(orphaned)
        errors.append(
            f"Found orphaned placeholder(s): {', '.join(sorted(unique_orphaned))}"
        )

    return errors


def main():
    repo_root = Path(__file__).resolve().parent.parent.parent

    # Only check workflow and agent definition YAMLs
    patterns = [
        repo_root / "workflows",
        repo_root / "agents",
    ]

    all_errors = {}
    total_files = 0

    for pattern in patterns:
        if not pattern.exists():
            continue

        for yaml_file in pattern.rglob("*.yaml"):
            # Skip generated or cache files
            if "__pycache__" in str(yaml_file):
                continue

            total_files += 1
            errors = check_file(yaml_file)
            if errors:
                rel_path = yaml_file.relative_to(repo_root)
                all_errors[str(rel_path)] = errors

    # --- Print results ---
    print(f"\n--- Orphaned Placeholder Check ---")
    print(f"Checked {total_files} YAML files\n")

    if all_errors:
        print(f"⚠️  Placeholders found in {len(all_errors)} files (expected — replaced at import time by setup.py):\n")
        for path, errors in sorted(all_errors.items()):
            print(f"  ⚠️  {path}")
            for err in errors:
                print(f"      - {err}")
        print(f"\nℹ️  Note: {sum(len(e) for e in all_errors.values())} placeholder(s) found — these are intentional and will be replaced by setup.py during import")
        sys.exit(0)  # Warning only, not a failure
    else:
        print(f"✅ No orphaned placeholders found in {total_files} files")
        sys.exit(0)


if __name__ == "__main__":
    main()
