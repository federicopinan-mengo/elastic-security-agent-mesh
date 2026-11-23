#!/usr/bin/env python3
"""Tests for the two supported authentication modes: API key and user/password.

Both modes must produce a working Authorization header for every target the
repo talks to (Elasticsearch, Kibana) through setup.py and the seed scripts.
"""

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import auth  # noqa: E402
import seed_ecs  # noqa: E402
import seed_mitre  # noqa: E402
import seed_rules  # noqa: E402
import setup  # noqa: E402

AUTH_VARS = [
    "ES_API_KEY",
    "ES_USERNAME",
    "ES_PASSWORD",
    "KIBANA_API_KEY",
    "KIBANA_USERNAME",
    "KIBANA_PASSWORD",
]


@pytest.fixture(autouse=True)
def clean_auth_env(monkeypatch):
    """Start every test from a blank authentication environment."""
    for name in AUTH_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ELASTIC_CLOUD_URL", "https://es.test.example")
    monkeypatch.setenv("KIBANA_URL", "https://kibana.test.example")


def test_basic_auth_encodes_the_credentials():
    expected = base64.b64encode(b"user:password").decode()
    assert auth.basic_auth("user", "password") == f"Basic {expected}"


def test_auth_header_prefers_the_api_key(monkeypatch):
    monkeypatch.setenv("ES_API_KEY", "es-key")
    monkeypatch.setenv("ES_USERNAME", "user")
    monkeypatch.setenv("ES_PASSWORD", "password")
    assert auth.auth_header("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD") == "ApiKey es-key"


def test_auth_header_falls_back_to_the_user_and_password(monkeypatch):
    monkeypatch.setenv("ES_USERNAME", "user")
    monkeypatch.setenv("ES_PASSWORD", "password")
    header = auth.auth_header("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD")
    assert header == auth.basic_auth("user", "password")


@pytest.mark.parametrize(
    "username,password",
    [("user", ""), ("", "password")],
)
def test_auth_header_rejects_an_incomplete_pair(monkeypatch, username, password):
    monkeypatch.setenv("ES_USERNAME", username)
    monkeypatch.setenv("ES_PASSWORD", password)
    with pytest.raises(RuntimeError, match="ES_API_KEY"):
        auth.auth_header("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD")


def test_auth_mode_reports_the_configured_mode(monkeypatch):
    assert auth.auth_mode("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD") == "not configured"
    monkeypatch.setenv("ES_USERNAME", "user")
    monkeypatch.setenv("ES_PASSWORD", "password")
    assert auth.auth_mode("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD") == "user/password"
    monkeypatch.setenv("ES_API_KEY", "es-key")
    assert auth.auth_mode("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD") == "api key"


def test_a_whitespace_only_api_key_falls_back_to_the_user_and_password(monkeypatch):
    monkeypatch.setenv("ES_API_KEY", "   ")
    monkeypatch.setenv("ES_USERNAME", "user")
    monkeypatch.setenv("ES_PASSWORD", "password")
    header = auth.auth_header("ES_API_KEY", "ES_USERNAME", "ES_PASSWORD")
    assert header == auth.basic_auth("user", "password")


def test_no_script_builds_an_authorization_header_by_hand():
    """Every Authorization header must go through scripts/auth.py."""
    scripts = Path(__file__).resolve().parent.parent / "scripts"
    for name in ("setup.py", "seed_ecs.py", "seed_mitre.py", "seed_rules.py"):
        source = (scripts / name).read_text()
        assert "ApiKey" not in source, f"{name} builds an Authorization header by hand"


def test_setup_headers_use_the_api_key(monkeypatch):
    monkeypatch.setenv("ES_API_KEY", "es-key")
    monkeypatch.setenv("KIBANA_API_KEY", "kibana-key")
    assert setup.es_headers()["Authorization"] == "ApiKey es-key"
    assert setup.kibana_headers()["Authorization"] == "ApiKey kibana-key"


def test_setup_headers_use_the_user_and_password(monkeypatch):
    monkeypatch.setenv("ES_USERNAME", "es-user")
    monkeypatch.setenv("ES_PASSWORD", "es-password")
    monkeypatch.setenv("KIBANA_USERNAME", "kb-user")
    monkeypatch.setenv("KIBANA_PASSWORD", "kb-password")
    assert setup.es_headers()["Authorization"] == auth.basic_auth("es-user", "es-password")
    assert setup.kibana_headers()["Authorization"] == auth.basic_auth("kb-user", "kb-password")


def test_validate_env_accepts_a_user_and_password_without_api_keys(monkeypatch, capsys):
    monkeypatch.setenv("ES_USERNAME", "es-user")
    monkeypatch.setenv("ES_PASSWORD", "es-password")
    monkeypatch.setenv("KIBANA_USERNAME", "kb-user")
    monkeypatch.setenv("KIBANA_PASSWORD", "kb-password")
    setup.validate_env()
    assert "user/password" in capsys.readouterr().out


def test_validate_env_rejects_an_incomplete_user_pair(monkeypatch):
    monkeypatch.setenv("ES_USERNAME", "es-user")
    with pytest.raises(SystemExit):
        setup.validate_env()


def test_the_seed_scripts_accept_a_user_and_password(monkeypatch):
    monkeypatch.setenv("ES_USERNAME", "es-user")
    monkeypatch.setenv("ES_PASSWORD", "es-password")
    monkeypatch.setenv("KIBANA_USERNAME", "kb-user")
    monkeypatch.setenv("KIBANA_PASSWORD", "kb-password")
    expected_es = auth.basic_auth("es-user", "es-password")
    assert seed_ecs.es_headers()["Authorization"] == expected_es
    assert seed_mitre.es_headers()["Authorization"] == expected_es
    assert seed_rules.es_headers()["Authorization"] == expected_es
    assert seed_rules.kibana_headers()["Authorization"] == auth.basic_auth("kb-user", "kb-password")
