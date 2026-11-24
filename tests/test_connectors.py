"""Connector provisioning: setup.py creates the HTTP connectors the workflows name.

Fakes the Kibana connectors API (no network) with an in-memory connector store.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import setup  # noqa: E402

VT = "oputils-virustotal"
ABUSE = "oputils-abuseipdb"


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


class FakeConnectors:
    """In-memory stand-in for the Kibana connectors API."""

    def __init__(self, existing=None, list_status=200, fail_methods=()):
        self.connectors = list(existing or [])
        self.calls = []
        self.list_status = list_status
        self.fail_methods = set(fail_methods)

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if self.list_status != 200:
            return FakeResponse(self.list_status, {}, "boom")
        return FakeResponse(200, self.connectors)

    def _create_or_update(self, verb, url, kwargs):
        self.calls.append((verb, url, kwargs))
        if verb in self.fail_methods:
            return FakeResponse(500, {}, "kaboom")
        connector_id = url.rsplit("/", 1)[-1]
        self.connectors = [c for c in self.connectors if c.get("id") != connector_id]
        self.connectors.append({"id": connector_id, **kwargs["json"]})
        return FakeResponse(200, {"id": connector_id})

    def post(self, url, **kwargs):
        return self._create_or_update("POST", url, kwargs)

    def put(self, url, **kwargs):
        return self._create_or_update("PUT", url, kwargs)

    def calls_of(self, method):
        return [c for c in self.calls if c[0] == method]

    def bodies(self, method):
        return [c[2]["json"] for c in self.calls_of(method)]


@pytest.fixture
def kibana(monkeypatch):
    fake = FakeConnectors()
    monkeypatch.setattr(setup.requests, "get", fake.get)
    monkeypatch.setattr(setup.requests, "post", fake.post)
    monkeypatch.setattr(setup.requests, "put", fake.put)
    monkeypatch.setenv("KIBANA_URL", "https://kibana.example")
    monkeypatch.setenv("KIBANA_API_KEY", "test-key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-secret")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abuse-secret")
    return fake


def test_first_run_creates_both_connectors(kibana):
    ensured = setup.ensure_connectors()

    assert ensured == [VT, ABUSE]

    posts = kibana.calls_of("POST")
    assert len(posts) == 2, "both connectors must be created on the first run"
    assert kibana.calls_of("PUT") == []

    by_id = {url.rsplit("/", 1)[-1]: kwargs for _, url, kwargs in posts}
    assert set(by_id) == {VT, ABUSE}

    vt_body = by_id[VT]["json"]
    assert vt_body["connector_type_id"] == ".http"
    assert vt_body["config"] == {"url": "https://www.virustotal.com/api/v3"}
    assert vt_body["secrets"]["secretHeaders"]["x-apikey"] == "vt-secret"

    abuse_body = by_id[ABUSE]["json"]
    assert abuse_body["connector_type_id"] == ".http"
    assert abuse_body["config"] == {"url": "https://api.abuseipdb.com/api/v2"}
    assert abuse_body["secrets"]["secretHeaders"]["Key"] == "abuse-secret"

    for _, _, kwargs in posts:
        assert kwargs["headers"]["kbn-xsrf"] == "true"
        assert kwargs["headers"]["Content-Type"] == "application/json"


def test_second_run_updates_instead_of_creating(kibana):
    setup.ensure_connectors()
    kibana.calls.clear()

    ensured = setup.ensure_connectors()

    assert ensured == [VT, ABUSE]
    assert kibana.calls_of("POST") == [], "existing connectors must not be re-created"
    assert len(kibana.calls_of("PUT")) == 2
    assert {url.rsplit("/", 1)[-1] for _, url, _ in kibana.calls_of("PUT")} == {VT, ABUSE}
    assert len(kibana.connectors) == 2, "no duplicate connectors"


def test_missing_env_var_skips_that_connector(kibana, monkeypatch, capsys):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    ensured = setup.ensure_connectors()

    out = capsys.readouterr().out
    assert ensured == [ABUSE]
    assert "VIRUSTOTAL_API_KEY" in out
    assert VT not in {url.rsplit("/", 1)[-1] for _, url, _ in kibana.calls_of("POST")}
    assert "vt-secret" not in out


def test_api_error_does_not_raise(kibana, capsys):
    kibana.fail_methods = {"POST", "PUT"}

    ensured = setup.ensure_connectors()

    out = capsys.readouterr().out
    assert ensured == []
    assert "[WARN]" in out
    assert VT in out and ABUSE in out


def test_listing_error_does_not_raise(monkeypatch, capsys):
    fake = FakeConnectors(list_status=500)
    monkeypatch.setattr(setup.requests, "get", fake.get)
    monkeypatch.setattr(setup.requests, "post", fake.post)
    monkeypatch.setattr(setup.requests, "put", fake.put)
    monkeypatch.setenv("KIBANA_URL", "https://kibana.example")
    monkeypatch.setenv("KIBANA_API_KEY", "test-key")

    ensured = setup.ensure_connectors()

    out = capsys.readouterr().out
    assert ensured == []
    assert "[WARN]" in out
    assert fake.calls_of("POST") == [], "no connector may be created when listing fails"


def test_secret_never_printed(kibana, capsys):
    setup.ensure_connectors()

    out = capsys.readouterr().out
    assert "vt-secret" not in out
    assert "abuse-secret" not in out
