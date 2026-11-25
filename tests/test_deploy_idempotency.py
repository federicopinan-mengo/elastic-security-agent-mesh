"""Deploy idempotency: re-running the setup converges instead of duplicating.

Fakes the Kibana HTTP surface (no network) with an in-memory workflow store.
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import setup  # noqa: E402

WORKFLOW_YAML = """name: Test Workflow
tags:
  - oputils-mesh
  - agent-mesh
triggers:
  - trigger: manual
steps:
  - name: do_thing
    type: elasticsearch.request
    with:
      method: GET
      path: /_cat/indices
"""


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    @property
    def ok(self):
        return 200 <= self.status_code < 300

    def json(self):
        return self._payload


class FakeKibana:
    """In-memory stand-in for the Kibana workflows API."""

    def __init__(self):
        self.workflows = {}
        self.calls = []
        self.conflict_without_id = False

    def _by_name(self, name):
        for wf in self.workflows.values():
            if wf["name"] == name:
                return wf
        return None

    def get(self, url, **kwargs):
        self.calls.append(("GET", url))
        return FakeResponse(200, list(self.workflows.values()))

    def post(self, url, **kwargs):
        self.calls.append(("POST", url))
        content = kwargs["json"]["workflows"][0]["yaml"]
        parsed = yaml.safe_load(content)
        existing = self._by_name(parsed["name"])
        if self.conflict_without_id:
            return FakeResponse(409, {})
        if existing:
            return FakeResponse(409, {"id": existing["id"]})
        wf_id = f"wf-{len(self.workflows) + 1}"
        self.workflows[wf_id] = {
            "id": wf_id,
            "name": parsed["name"],
            "tags": parsed.get("tags", []),
        }
        return FakeResponse(
            200, {"created": [{"name": parsed["name"], "id": wf_id}], "failures": []}
        )

    def put(self, url, **kwargs):
        self.calls.append(("PUT", url))
        wf_id = url.rsplit("/", 1)[-1]
        parsed = yaml.safe_load(kwargs["json"]["yaml"])
        self.workflows[wf_id] = {
            "id": wf_id,
            "name": parsed["name"],
            "tags": parsed.get("tags", []),
        }
        return FakeResponse(200, {"name": parsed["name"], "id": wf_id})

    def delete(self, url, **kwargs):
        self.calls.append(("DELETE", url))
        wf_id = url.split("/workflow/")[-1].split("?")[0]
        self.workflows.pop(wf_id, None)
        return FakeResponse(200, {})

    def calls_of(self, method):
        return [url for verb, url in self.calls if verb == method]


@pytest.fixture
def fake_kibana(monkeypatch):
    fake = FakeKibana()
    for verb in ("get", "post", "put", "delete"):
        monkeypatch.setattr(setup.requests, verb, getattr(fake, verb))
    monkeypatch.setattr(setup.time, "sleep", lambda *_: None)
    monkeypatch.setenv("KIBANA_URL", "https://kibana.example")
    monkeypatch.setenv("KIBANA_API_KEY", "test-key")
    return fake


@pytest.fixture
def repo(tmp_path, monkeypatch):
    workflows_dir = tmp_path / "workflows"
    workflows_dir.mkdir()
    (workflows_dir / "test.yaml").write_text(WORKFLOW_YAML)
    monkeypatch.setattr(setup, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(setup, "WORKFLOW_DIRS", ["workflows"])
    return tmp_path


def test_second_deploy_updates_instead_of_creating(repo, fake_kibana):
    setup.import_workflows()
    assert len(fake_kibana.workflows) == 1

    setup.import_workflows()

    assert len(fake_kibana.workflows) == 1, "second deploy must not duplicate the workflow"
    assert len(fake_kibana.calls_of("POST")) == 1, "second deploy must not POST again"
    assert len(fake_kibana.calls_of("PUT")) == 1, "second deploy must PUT the existing workflow"


def test_manifest_records_deployed_workflows(repo, fake_kibana):
    setup.import_workflows()

    manifest = json.loads((repo / ".oputils" / "workflows-manifest.json").read_text())
    assert manifest["Test Workflow"]["id"] == next(iter(fake_kibana.workflows))
    assert manifest["Test Workflow"]["path"] == "workflows/test.yaml"


def test_orphans_are_reported(repo, fake_kibana, capsys):
    setup.import_workflows()
    fake_kibana.workflows["wf-orphan"] = {
        "id": "wf-orphan",
        "name": "Untracked Workflow",
        "tags": ["oputils-mesh"],
    }

    setup.import_workflows()

    out = capsys.readouterr().out
    assert "ORPHANS" in out
    assert "Untracked Workflow" in out


def test_delete_workflows_is_dry_run_by_default(repo, fake_kibana):
    setup.import_workflows()
    fake_kibana.workflows["wf-other"] = {
        "id": "wf-other",
        "name": "Someone Elses Workflow",
        "tags": ["other"],
    }

    setup.delete_workflows()

    assert len(fake_kibana.workflows) == 2, "dry-run must not delete anything"
    assert fake_kibana.calls_of("DELETE") == []


def test_delete_workflows_removes_only_tagged_workflows(repo, fake_kibana):
    setup.import_workflows()
    fake_kibana.workflows["wf-other"] = {
        "id": "wf-other",
        "name": "Someone Elses Workflow",
        "tags": ["other"],
    }

    deleted = setup.delete_workflows(yes=True)

    assert deleted == 1
    assert list(fake_kibana.workflows) == ["wf-other"]
    assert fake_kibana.calls_of("DELETE")[0].startswith(
        "https://kibana.example/api/workflows/workflow/wf-1"
    )
    assert "force=true" in fake_kibana.calls_of("DELETE")[0]
    assert "acknowledgeAclLoss=true" in fake_kibana.calls_of("DELETE")[0]


def test_import_aborts_when_the_workflow_listing_fails(repo, fake_kibana, monkeypatch):
    def boom(*args, **kwargs):
        raise setup.requests.RequestException("connection reset")

    monkeypatch.setattr(setup.requests, "get", boom)

    with pytest.raises(RuntimeError):
        setup.import_workflows()

    assert fake_kibana.calls_of("POST") == [], "a blind import would duplicate every workflow"


def test_conflict_without_an_id_is_reported_as_a_failure(repo, fake_kibana, capsys):
    fake_kibana.conflict_without_id = True

    with pytest.raises(RuntimeError, match="Workflow imports failed"):
        setup.import_workflows()

    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "[updated]" not in out


def test_stale_manifest_entries_are_reported(repo, fake_kibana, capsys):
    manifest = repo / ".oputils" / "workflows-manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps({"Gone Workflow": {"id": "wf-gone", "path": "workflows/gone.yaml"}})
    )

    setup.import_workflows()

    out = capsys.readouterr().out
    assert "STALE" in out
    assert "Gone Workflow" in out


def test_corrupt_manifest_is_treated_as_empty(repo, fake_kibana):
    manifest = repo / ".oputils" / "workflows-manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("{not json")

    setup.import_workflows()

    assert json.loads(manifest.read_text())["Test Workflow"]["id"]


def test_cli_delete_workflows_is_a_dry_run_without_yes(repo, fake_kibana, monkeypatch):
    setup.import_workflows()
    for var in ("ELASTIC_CLOUD_URL", "ES_API_KEY", "KIBANA_URL", "KIBANA_API_KEY"):
        monkeypatch.setenv(var, "https://kibana.example")
    monkeypatch.setattr(sys, "argv", ["setup.py", "--delete-workflows"])
    monkeypatch.setattr(setup, "validate_endpoints", lambda: None)

    setup.main()

    assert fake_kibana.calls_of("DELETE") == []


def test_cli_delete_workflows_deletes_with_yes(repo, fake_kibana, monkeypatch):
    setup.import_workflows()
    for var in ("ELASTIC_CLOUD_URL", "ES_API_KEY", "KIBANA_URL", "KIBANA_API_KEY"):
        monkeypatch.setenv(var, "https://kibana.example")
    monkeypatch.setattr(sys, "argv", ["setup.py", "--delete-workflows", "--yes"])
    monkeypatch.setattr(setup, "validate_endpoints", lambda: None)

    setup.main()

    assert fake_kibana.calls_of("DELETE"), "--yes must reach the delete call"
