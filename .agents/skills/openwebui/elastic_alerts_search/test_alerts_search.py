"""Tests for elastic_alerts_search."""
from elastic_alerts_search import ElasticAlertsSearch


def test_import():
    """Verify ElasticAlertsSearch can be imported."""
    assert ElasticAlertsSearch is not None


def test_nl_to_esql_time_filter():
    """Verify time filter conversion."""
    tool = ElasticAlertsSearch.__new__(ElasticAlertsSearch)
    tool.index_patterns = [".alerts-security.alerts-*", ".siem-signals-default-*"]
    tool.schema = {}

    query = tool._nl_to_esql("last hour")
    assert "NOW() - 1h" in query

    query = tool._nl_to_esql("last 24 hours")
    assert "NOW() - 1d" in query

    query = tool._nl_to_esql("last 7 days")
    assert "NOW() - 7d" in query


def test_nl_to_esql_severity_filter():
    """Verify severity filter conversion."""
    tool = ElasticAlertsSearch.__new__(ElasticAlertsSearch)
    tool.index_patterns = [".alerts-security.alerts-*", ".siem-signals-default-*"]
    tool.schema = {}

    query = tool._nl_to_esql("critical alerts")
    assert "alert.severity == 'critical'" in query

    query = tool._nl_to_esql("high severity alerts")
    assert "alert.severity == 'high'" in query

    query = tool._nl_to_esql("medium alerts")
    assert "alert.severity == 'medium'" in query

    query = tool._nl_to_esql("low alerts")
    assert "alert.severity == 'low'" in query


def test_nl_to_esql_status_filter():
    """Verify status filter conversion."""
    tool = ElasticAlertsSearch.__new__(ElasticAlertsSearch)
    tool.index_patterns = [".alerts-security.alerts-*", ".siem-signals-default-*"]
    tool.schema = {}

    query = tool._nl_to_esql("open alerts")
    assert "alert.status == 'active'" in query

    query = tool._nl_to_esql("closed alerts")
    assert "alert.status == 'closed'" in query

    query = tool._nl_to_esql("acknowledged alerts")
    assert "alert.status == 'acknowledged'" in query


def test_nl_to_esql_fields():
    """Verify base select fields are included."""
    tool = ElasticAlertsSearch.__new__(ElasticAlertsSearch)
    tool.index_patterns = [".alerts-security.alerts-*", ".siem-signals-default-*"]
    tool.schema = {}

    query = tool._nl_to_esql("show me alerts")
    assert "alert.id" in query
    assert "alert.rule.name" in query
    assert "alert.severity" in query
    assert "alert.status" in query
    assert "kibana.alert.reason" in query
    assert "@timestamp" in query