#!/usr/bin/env python3
"""Unit tests for the knowledge-base seed scripts (seed_mitre / seed_ecs / seed_rules).

The HTTP layer is faked with an in-memory Elasticsearch that implements the
semantics the scripts rely on:

- ``index`` with an explicit ``_id`` upserts (overwrite, never duplicate)
- ``create`` fails with 409 when the document already exists

Idempotency is therefore observable: running a seeder twice must create zero
new documents on the second run.

Run with: pytest tests/test_seed_scripts.py -v
"""

import json
import sys
from pathlib import Path

import pytest

# Add scripts/ to path (same convention as tests/test_setup.py)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import seed_ecs  # noqa: E402
import seed_mitre  # noqa: E402
import seed_rules  # noqa: E402

ES_URL = "https://es.test.example"
KIBANA_URL = "https://kibana.test.example"


# =============================================================================
# Test doubles
# =============================================================================
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


class FakeHTTP:
    """In-memory Elasticsearch/Kibana stand-in for the seed scripts."""

    def __init__(self):
        self.responses = {}
        self.store = {}  # (index, _id) -> document
        self.bulk_ops = []  # (op, index, _id)
        self.created = []  # (index, _id) of documents that did not exist before
        self.conflicts = []  # (index, _id) rejected because the doc already existed
        self.get_calls = []

    def add_response(self, url, response):
        self.responses[url] = response

    def get(self, url, **kwargs):
        self.get_calls.append(url)
        if url not in self.responses:
            raise AssertionError(f"unexpected GET {url}")
        return self.responses[url]

    def post(self, url, **kwargs):
        assert url.endswith("/_bulk"), f"unexpected POST {url}"
        index = url.split("/")[-2]
        lines = [line for line in kwargs["data"].splitlines() if line.strip()]
        items = []
        for i in range(0, len(lines), 2):
            action = json.loads(lines[i])
            doc = json.loads(lines[i + 1])
            op = next(iter(action))
            doc_id = action[op].get("_id")
            key = (index, doc_id)
            self.bulk_ops.append((op, index, doc_id))
            if op == "create" and key in self.store:
                self.conflicts.append(key)
                items.append(
                    {
                        "create": {
                            "_id": doc_id,
                            "status": 409,
                            "error": {"type": "version_conflict_engine_exception"},
                        }
                    }
                )
                continue
            if key not in self.store:
                self.created.append(key)
            self.store[key] = doc
            items.append({op: {"_id": doc_id, "status": 200}})
        return FakeResponse(
            200,
            {"took": 1, "errors": bool(self.conflicts), "items": items},
        )


# =============================================================================
# Fixtures / payloads
# =============================================================================
MITRE_STIX = {
    "type": "bundle",
    "id": "bundle--0",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--0",
            "name": "Spearphishing Attachment",
            "description": "Adversaries send malicious attachments.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}],
        },
        {
            "type": "malware",
            "id": "malware--0",
            "name": "Emotet",
            "description": "A banking trojan.",
            "external_references": [],
        },
        {
            "type": "identity",
            "id": "identity--0",
            "name": "Unrelated identity object",
        },
    ],
}

ECS_CSV = (
    "Field,Type,Level,Description\n"
    '@timestamp,date,core,"Event timestamp"\n'
    'host.name,keyword,core,"Hostname of the host"\n'
    ',keyword,core,"Row without a field name"\n'
)

KIBANA_RULES = {
    "data": [
        {
            "id": "rule-1",
            "name": "Suspicious Login",
            "description": "Login from a new ASN.",
            "severity": "high",
            "risk_score": 73,
            "tags": ["login"],
            "enabled": True,
            "author": ["detection-engineering"],
        },
        {
            "id": "rule-2",
            "name": "Suspicious Process",
            "description": "Rare parent process.",
            "severity": "medium",
            "risk_score": 47,
            "tags": ["process"],
            "enabled": False,
            "author": ["detection-engineering"],
        },
    ]
}


@pytest.fixture
def es_env(monkeypatch):
    monkeypatch.setenv("ELASTIC_CLOUD_URL", ES_URL)
    monkeypatch.setenv("ES_API_KEY", "es-key")
    monkeypatch.setenv("KIBANA_URL", KIBANA_URL)
    monkeypatch.setenv("KIBANA_API_KEY", "kbn-key")
    return monkeypatch


# =============================================================================
# Idempotency
# =============================================================================
class TestSeedMitreIdempotency:
    def test_second_run_creates_no_duplicate_documents(self, es_env):
        fake = FakeHTTP()
        fake.add_response(seed_mitre.MITRE_URL, FakeResponse(200, payload=MITRE_STIX))
        es_env.setattr(seed_mitre, "requests", fake)

        seed_mitre.main()
        first_created = list(fake.created)
        first_ids = sorted(key for _, key in fake.store)

        seed_mitre.main()

        assert sorted(key for _, key in fake.store) == first_ids
        assert fake.created == first_created, "second run created new documents"
        assert len(fake.created) == 2, "one document per whitelisted MITRE object"
        assert fake.conflicts == []

    def test_documents_use_stable_mitre_ids_as_elasticsearch_ids(self, es_env):
        fake = FakeHTTP()
        fake.add_response(seed_mitre.MITRE_URL, FakeResponse(200, payload=MITRE_STIX))
        es_env.setattr(seed_mitre, "requests", fake)

        seed_mitre.main()

        assert sorted(key for _, key in fake.store) == ["attack-pattern--0", "malware--0"]
        assert fake.store[("kb-mitre-attack", "attack-pattern--0")]["title"].startswith(
            "T1566.001: Spearphishing Attachment"
        )

    def test_only_whitelisted_object_types_are_indexed(self, es_env):
        fake = FakeHTTP()
        fake.add_response(seed_mitre.MITRE_URL, FakeResponse(200, payload=MITRE_STIX))
        es_env.setattr(seed_mitre, "requests", fake)

        seed_mitre.main()

        assert ("kb-mitre-attack", "identity--0") not in fake.store
        assert {op for op, _, _ in fake.bulk_ops} == {"index"}


class TestSeedEcsIdempotency:
    def test_second_run_creates_no_duplicate_documents(self, es_env):
        fake = FakeHTTP()
        fake.add_response(seed_ecs.ECS_CSV_URL, FakeResponse(200, text=ECS_CSV))
        es_env.setattr(seed_ecs, "requests", fake)

        seed_ecs.main()
        first_created = list(fake.created)
        first_ids = sorted(key for _, key in fake.store)

        seed_ecs.main()

        assert sorted(key for _, key in fake.store) == first_ids
        assert fake.created == first_created, "second run created new documents"
        assert len(fake.created) == 2, "one document per ECS field"
        assert fake.conflicts == []

    def test_documents_use_the_field_name_as_elasticsearch_id(self, es_env):
        fake = FakeHTTP()
        fake.add_response(seed_ecs.ECS_CSV_URL, FakeResponse(200, text=ECS_CSV))
        es_env.setattr(seed_ecs, "requests", fake)

        seed_ecs.main()

        assert sorted(key for _, key in fake.store) == ["@timestamp", "host.name"]
        assert fake.store[("kb-ecs-schema", "@timestamp")]["title"] == "ECS Field: @timestamp"

    def test_rows_without_a_field_name_are_skipped(self, es_env):
        fake = FakeHTTP()
        fake.add_response(seed_ecs.ECS_CSV_URL, FakeResponse(200, text=ECS_CSV))
        es_env.setattr(seed_ecs, "requests", fake)

        seed_ecs.main()

        assert all(doc_id for _, doc_id in fake.store)
        assert len(fake.store) == 2


class TestSeedRulesIdempotency:
    def test_second_run_creates_no_duplicate_documents(self, es_env):
        fake = FakeHTTP()
        fake.add_response(
            f"{KIBANA_URL}/api/detection_engine/rules/_find?per_page=10000",
            FakeResponse(200, payload=KIBANA_RULES),
        )
        es_env.setattr(seed_rules, "requests", fake)

        seed_rules.main()
        first_created = list(fake.created)
        first_ids = sorted(key for _, key in fake.store)

        seed_rules.main()

        assert sorted(key for _, key in fake.store) == first_ids
        assert fake.created == first_created, "second run created new documents"
        assert len(fake.created) == 2, "one document per detection rule"
        assert fake.conflicts == []

    def test_documents_use_the_rule_id_as_elasticsearch_id(self, es_env):
        fake = FakeHTTP()
        fake.add_response(
            f"{KIBANA_URL}/api/detection_engine/rules/_find?per_page=10000",
            FakeResponse(200, payload=KIBANA_RULES),
        )
        es_env.setattr(seed_rules, "requests", fake)

        seed_rules.main()

        assert sorted(key for _, key in fake.store) == ["rule-1", "rule-2"]
        assert fake.store[("kb-detection-rules", "rule-1")]["metadata"]["risk_score"] == 73

    def test_rules_are_fetched_from_the_kibana_detection_engine(self, es_env):
        fake = FakeHTTP()
        fake.add_response(
            f"{KIBANA_URL}/api/detection_engine/rules/_find?per_page=10000",
            FakeResponse(200, payload=KIBANA_RULES),
        )
        es_env.setattr(seed_rules, "requests", fake)

        seed_rules.main()

        assert fake.get_calls == [f"{KIBANA_URL}/api/detection_engine/rules/_find?per_page=10000"]


# =============================================================================
# Failure handling
# =============================================================================
class TestSeedFailureHandling:
    def test_mitre_requires_elastic_cloud_url(self, monkeypatch, capsys):
        monkeypatch.delenv("ELASTIC_CLOUD_URL", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            seed_mitre.main()
        assert exc_info.value.code == 1
        assert "ELASTIC_CLOUD_URL environment variable not set" in capsys.readouterr().out

    def test_mitre_requires_an_api_key(self, monkeypatch, capsys):
        monkeypatch.setenv("ELASTIC_CLOUD_URL", ES_URL)
        monkeypatch.delenv("ES_API_KEY", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            seed_mitre.main()
        assert exc_info.value.code == 1
        assert "ES_API_KEY environment variable not set" in capsys.readouterr().out

    def test_mitre_exits_when_the_download_fails(self, es_env, capsys):
        fake = FakeHTTP()
        fake.add_response(seed_mitre.MITRE_URL, FakeResponse(404, text="not found"))
        es_env.setattr(seed_mitre, "requests", fake)

        with pytest.raises(SystemExit) as exc_info:
            seed_mitre.main()

        assert exc_info.value.code == 1
        assert "Failed to download MITRE STIX: 404" in capsys.readouterr().out

    def test_ecs_exits_when_the_download_fails(self, es_env, capsys):
        fake = FakeHTTP()
        fake.add_response(seed_ecs.ECS_CSV_URL, FakeResponse(500, text="boom"))
        es_env.setattr(seed_ecs, "requests", fake)

        with pytest.raises(SystemExit) as exc_info:
            seed_ecs.main()

        assert exc_info.value.code == 1
        assert "Failed to download ECS Schema: 500" in capsys.readouterr().out

    def test_rules_require_a_kibana_url(self, monkeypatch, capsys):
        monkeypatch.setenv("ELASTIC_CLOUD_URL", ES_URL)
        monkeypatch.setenv("ES_API_KEY", "es-key")
        monkeypatch.delenv("KIBANA_URL", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            seed_rules.main()
        assert exc_info.value.code == 1
        assert "KIBANA_URL environment variable not set" in capsys.readouterr().out

    def test_rules_exit_when_the_rule_fetch_fails(self, es_env, capsys):
        fake = FakeHTTP()
        fake.add_response(
            f"{KIBANA_URL}/api/detection_engine/rules/_find?per_page=10000",
            FakeResponse(403, text="forbidden"),
        )
        es_env.setattr(seed_rules, "requests", fake)

        with pytest.raises(SystemExit) as exc_info:
            seed_rules.main()

        assert exc_info.value.code == 1
        assert "Failed to fetch rules: 403" in capsys.readouterr().out

    @pytest.mark.xfail(
        strict=False,
        reason=(
            "Gap: seed_rules builds the Elasticsearch _id from rule['id'] only. "
            "A detection rule without an id gets _id '' and every such rule "
            "overwrites the previous one, so rules are silently lost."
        ),
    )
    def test_rules_without_an_id_still_get_distinct_documents(self, es_env):
        fake = FakeHTTP()
        fake.add_response(
            f"{KIBANA_URL}/api/detection_engine/rules/_find?per_page=10000",
            FakeResponse(
                200,
                payload={
                    "data": [
                        {"name": "Rule Without Id One"},
                        {"name": "Rule Without Id Two"},
                    ]
                },
            ),
        )
        es_env.setattr(seed_rules, "requests", fake)

        seed_rules.main()

        assert len(fake.store) == 2, "rules without an id collapse into a single document"

    def test_bulk_failure_is_reported_without_aborting_the_seed(self, es_env, capsys):
        """Current behaviour: a failed bulk call is printed, main() still returns.

        Gap (not fixed here, scripts/ is out of scope): the seeder exits 0 even
        though nothing was indexed, so a failed bulk is invisible to CI.
        """
        fake = FakeHTTP()
        fake.add_response(seed_mitre.MITRE_URL, FakeResponse(200, payload=MITRE_STIX))
        es_env.setattr(seed_mitre, "requests", fake)

        def failing_post(url, **kwargs):
            return FakeResponse(500, text="bulk failed")

        fake.post = failing_post

        seed_mitre.main()

        assert "Bulk indexing failed: 500" in capsys.readouterr().out
