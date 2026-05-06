"""Tests for elastic_logs_search."""
from elastic_logs_search import ElasticLogsSearch


def test_import():
    """Verify ElasticLogsSearch can be imported."""
    assert ElasticLogsSearch is not None


def test_nl_to_esql_time_filter():
    """Verify time filter conversion."""
    tool = ElasticLogsSearch.__new__(ElasticLogsSearch)
    tool.index_patterns = ["logs-*", "*-logs-*", "logs-generic-default-*"]

    query = tool._nl_to_esql("last hour")
    assert "NOW() - 1h" in query

    query = tool._nl_to_esql("última hora")
    assert "NOW() - 1h" in query

    query = tool._nl_to_esql("last 24 hours")
    assert "NOW() - 1d" in query

    query = tool._nl_to_esql("últimas 24 horas")
    assert "NOW() - 1d" in query

    query = tool._nl_to_esql("último día")
    assert "NOW() - 1d" in query

    query = tool._nl_to_esql("last 7 days")
    assert "NOW() - 7d" in query

    query = tool._nl_to_esql("última semana")
    assert "NOW() - 7d" in query

    query = tool._nl_to_esql("today")
    assert "NOW() - 1d" in query

    query = tool._nl_to_esql("hoy")
    assert "NOW() - 1d" in query


def test_nl_to_esql_keyword_filter():
    """Verify keyword filter conversion."""
    tool = ElasticLogsSearch.__new__(ElasticLogsSearch)
    tool.index_patterns = ["logs-*", "*-logs-*", "logs-generic-default-*"]

    query = tool._nl_to_esql("show me errors")
    assert "MATCH(message, 'error')" in query

    query = tool._nl_to_esql("buscar errores")
    assert "MATCH(message, 'error')" in query

    query = tool._nl_to_esql("warning messages")
    assert "MATCH(message, 'warning')" in query

    query = tool._nl_to_esql("alerts with warn")
    assert "MATCH(message, 'warning')" in query

    query = tool._nl_to_esql("failed connections")
    assert "MATCH(message, 'fail')" in query

    query = tool._nl_to_esql("timeout issues")
    assert "MATCH(message, 'timeout')" in query


def test_nl_to_esql_fields():
    """Verify base select fields are included."""
    tool = ElasticLogsSearch.__new__(ElasticLogsSearch)
    tool.index_patterns = ["logs-*", "*-logs-*", "logs-generic-default-*"]

    query = tool._nl_to_esql("show me logs")
    assert "@timestamp" in query
    assert "message" in query
    assert "log.level" in query
    assert "host.name" in query


def test_nl_to_esql_combined():
    """Verify combined time and keyword filters."""
    tool = ElasticLogsSearch.__new__(ElasticLogsSearch)
    tool.index_patterns = ["logs-*", "*-logs-*", "logs-generic-default-*"]

    query = tool._nl_to_esql("errors in the last hour")
    assert "NOW() - 1h" in query
    assert "MATCH(message, 'error')" in query


def test_nl_to_esql_index_patterns():
    """Verify index patterns are used."""
    tool = ElasticLogsSearch.__new__(ElasticLogsSearch)
    tool.index_patterns = ["logs-*", "*-logs-*", "logs-generic-default-*"]

    query = tool._nl_to_esql("show me logs")
    assert "FROM logs-*,*-logs-*,logs-generic-default-*" in query
