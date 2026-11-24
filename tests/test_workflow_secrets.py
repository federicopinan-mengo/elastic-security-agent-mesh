"""Regression guard: no credential material may live in a workflow YAML.

Phase 1f of the security remediation (spec S7). Workflows are imported into
Kibana, so a credential that survives in the YAML is a credential that ships to
the deployment target. Native `elasticsearch.request` / `kibana.request` steps
take the credential from the execution context, and third-party credentials live
in Kibana connectors, so no workflow needs a key.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / "workflows"

# Legacy placeholders substituted by scripts/setup.py before the import path
# stopped substituting anything. None of them may survive in a workflow.
LEGACY_PLACEHOLDERS = (
    "__ES_API_KEY__",
    "__KIBANA_API_KEY__",
    "__VT_API_KEY__",
    "__ABUSEIPDB_API_KEY__",
    "__LLM_CONNECTOR_ID__",
    "__ES_URL__",
    "__KIBANA_URL__",
)

SECRET_NAME_RE = re.compile(r"(api[_-]?key|token|secret|password|passwd|credential)", re.IGNORECASE)
AUTH_HEADER_NAMES = {"authorization", "x-apikey", "api-key", "apikey", "key"}


def workflow_files() -> list[Path]:
    return sorted(WORKFLOWS_DIR.rglob("*.yaml"))


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def find_mappings(node, wanted_key: str):
    """Yield every mapping nested under a key named `wanted_key`."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == wanted_key and isinstance(value, dict):
                yield value
            yield from find_mappings(value, wanted_key)
    elif isinstance(node, list):
        for item in node:
            yield from find_mappings(item, wanted_key)


def test_workflows_directory_is_not_empty():
    assert workflow_files(), "no workflow YAML found to guard"


def test_no_legacy_credential_placeholders():
    offenders = []
    for path in workflow_files():
        text = path.read_text(encoding="utf-8")
        for placeholder in LEGACY_PLACEHOLDERS:
            if placeholder in text:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {placeholder}")
    assert not offenders, "legacy credential placeholders found:\n" + "\n".join(offenders)


def test_no_authentication_headers():
    offenders = []
    for path in workflow_files():
        document = load(path)
        for headers in find_mappings(document, "headers"):
            for name, value in headers.items():
                normalized = str(name).strip().lower()
                if normalized in AUTH_HEADER_NAMES or SECRET_NAME_RE.search(normalized):
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: header {name}")
                if isinstance(value, str) and value.strip().lower().startswith("apikey"):
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}: header {name} carries an API key"
                    )
    assert not offenders, "authentication headers found:\n" + "\n".join(offenders)


def test_no_secret_valued_consts():
    offenders = []
    for path in workflow_files():
        document = load(path)
        for consts in find_mappings(document, "consts"):
            for name, value in consts.items():
                if not SECRET_NAME_RE.search(str(name)):
                    continue
                if value is None or (isinstance(value, str) and not value.strip()):
                    continue
                offenders.append(f"{path.relative_to(REPO_ROOT)}: const {name}")
    assert not offenders, "credential-shaped constants found:\n" + "\n".join(offenders)
