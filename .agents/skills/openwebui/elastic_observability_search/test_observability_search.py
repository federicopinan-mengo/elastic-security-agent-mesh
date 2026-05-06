"""Tests for elastic_observability_search."""
from elastic_observability_search import ElasticObservabilitySearch


def test_import():
    """Verify ElasticObservabilitySearch can be imported."""
    assert ElasticObservabilitySearch is not None


def test_nl_to_esql_time_filter():
    """Verify time filter conversion for APM data."""
    tool = ElasticObservabilitySearch.__new__(ElasticObservabilitySearch)
    tool.index_patterns = ["metrics-*", "traces-*", "apm-*", "logs-apm-*"]

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

    query = tool._nl_to_esql("últimos 7")
    assert "NOW() - 7d" in query

    query = tool._nl_to_esql("today")
    assert "NOW() - 1d" in query

    query = tool._nl_to_esql("hoy")
    assert "NOW() - 1d" in query


def test_nl_to_esql_apm_filters():
    """Verify APM-specific filters (error, slow)."""
    tool = ElasticObservabilitySearch.__new__(ElasticObservabilitySearch)
    tool.index_patterns = ["metrics-*", "traces-*", "apm-*", "logs-apm-*"]

    # Error filter
    query = tool._nl_to_esql("show me errors")
    assert "event.outcome == 'failure'" in query

    query = tool._nl_to_esql("errores de APM")
    assert "event.outcome == 'failure'" in query

    # Slow filter
    query = tool._nl_to_esql("slow transactions")
    assert "event.duration >= 1000" in query

    # "lento" must be a substring in the query
    query = tool._nl_to_esql("servicio lento")
    assert "event.duration >= 1000" in query


def test_nl_to_esql_fields():
    """Verify base select fields are included."""
    tool = ElasticObservabilitySearch.__new__(ElasticObservabilitySearch)
    tool.index_patterns = ["metrics-*", "traces-*", "apm-*", "logs-apm-*"]

    query = tool._nl_to_esql("show me APM data")
    assert "@timestamp" in query
    assert "service.name" in query
    assert "service.environment" in query
    assert "event.duration" in query
    assert "event.outcome" in query


def test_nl_to_esql_combined():
    """Verify combined time and APM filters."""
    tool = ElasticObservabilitySearch.__new__(ElasticObservabilitySearch)
    tool.index_patterns = ["metrics-*", "traces-*", "apm-*", "logs-apm-*"]

    query = tool._nl_to_esql("errors in the last hour")
    assert "NOW() - 1h" in query
    assert "event.outcome == 'failure'" in query

    query = tool._nl_to_esql("slow traces today")
    assert "NOW() - 1d" in query
    assert "event.duration >= 1000" in query


def test_nl_to_esql_index_patterns():
    """Verify index patterns are used."""
    tool = ElasticObservabilitySearch.__new__(ElasticObservabilitySearch)
    tool.index_patterns = ["metrics-*", "traces-*", "apm-*", "logs-apm-*"]

    query = tool._nl_to_esql("show me APM data")
    assert "FROM metrics-*,traces-*,apm-*,logs-apm-*" in query


def test_nl_to_esql_limit():
    """Verify LIMIT clause is present."""
    tool = ElasticObservabilitySearch.__new__(ElasticObservabilitySearch)
    tool.index_patterns = ["metrics-*", "traces-*", "apm-*", "logs-apm-*"]

    query = tool._nl_to_esql("show me traces")
    assert "LIMIT 50" in query