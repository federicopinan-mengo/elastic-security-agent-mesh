"""Guards on how a workflow references the outputs of its own steps."""

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIRS = [REPO_ROOT / "workflows", REPO_ROOT / "agents" / "setup"]

STEP_REF = re.compile(r"steps\.([A-Za-z_][A-Za-z0-9_]*)")
OUTPUT_REF = re.compile(r"steps\.([A-Za-z_][A-Za-z0-9_]*)\.output((?:\.[A-Za-z_][A-Za-z0-9_]*)*)")


def workflow_files():
    for directory in WORKFLOW_DIRS:
        yield from sorted(directory.rglob("*.yaml"))


def step_names(node, names):
    """Collect every step name of a workflow, including the nested bodies."""
    if isinstance(node, dict):
        if "name" in node and "type" in node:
            names.add(node["name"])
        for value in node.values():
            step_names(value, names)
    elif isinstance(node, list):
        for item in node:
            step_names(item, names)
    return names


def references(path):
    """Yield the step names a workflow references, comments excluded."""
    for line in path.read_text().splitlines():
        if line.lstrip().startswith("#"):
            continue
        for match in STEP_REF.finditer(line):
            yield match.group(1)


def test_every_step_reference_points_to_a_step_of_the_same_workflow():
    for path in workflow_files():
        names = step_names(yaml.safe_load(path.read_text()), set())
        for referenced in references(path):
            assert referenced in names, (
                f"{path.name} references steps.{referenced}, which it does not define"
            )


def _is_one_insertion_apart(path_a, path_b):
    """True when one path is the other with a single segment inserted."""
    short, long = sorted((path_a, path_b), key=len)
    short_segments = short.split(".")
    long_segments = long.split(".")
    if len(long_segments) != len(short_segments) + 1:
        return False
    index = 0
    for segment in long_segments:
        if index < len(short_segments) and segment == short_segments[index]:
            index += 1
    return index == len(short_segments)


def test_a_field_is_always_reached_through_the_same_path():
    """A field read twice from the same step must be read the same way.

    The paths that differ by a single segment are the ones where a
    converted step kept a legacy wrapper, or dropped one.
    """
    for path in workflow_files():
        text = "\n".join(
            line for line in path.read_text().splitlines()
            if not line.lstrip().startswith("#")
        )
        per_field = {}
        for match in OUTPUT_REF.finditer(text):
            step, field_path = match.group(1), match.group(2)
            if not field_path:
                continue
            per_field.setdefault((step, field_path.split(".")[-1]), set()).add(field_path)
        for (step, field), paths in per_field.items():
            for path_a in paths:
                for path_b in paths:
                    if path_a != path_b and _is_one_insertion_apart(path_a, path_b):
                        raise AssertionError(
                            f"{path.name}: steps.{step}.{field} is read as {sorted(paths)}"
                        )


def test_the_threat_assessment_reads_the_same_score_it_reports():
    path = WORKFLOW_DIRS[0] / "security" / "enrichment" / "ip-reputation-check.yaml"
    text = path.read_text()
    reported = re.search(
        r"Abuse Confidence Score: \{\{ steps\.check_abuseipdb\.output\.([\w.]+) \}\}", text
    )
    assessed = re.search(
        r"\{% assign (\w+) = steps\.check_abuseipdb\.output\.([\w.]+) %\}", text
    )
    assert reported and assessed, "the workflow must report and assess the score"
    alias, root = assessed.group(1), assessed.group(2)
    assert f"{alias}.abuseConfidenceScore" in text, "the condition must read the score"
    assert reported.group(1) == f"{root}.abuseConfidenceScore"
