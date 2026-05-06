"""Basic import test for elastic_fleet_search."""
from elastic_fleet_search import ElasticFleetSearch


def test_import():
    """Verify ElasticFleetSearch can be imported."""
    assert ElasticFleetSearch is not None


def test_nl_to_esql_time_filter():
    """Verify time filter conversion."""
    tool = ElasticFleetSearch.__new__(ElasticFleetSearch)
    tool.index_patterns = ["fleet-agents-*", "metrics-fleet.agent-default-*"]
    tool.schema = {}

    query = tool._nl_to_esql("last hour")
    assert "NOW() - 1h" in query

    query = tool._nl_to_esql("last 24 hours")
    assert "NOW() - 1d" in query

    query = tool._nl_to_esql("last 7 days")
    assert "NOW() - 7d" in query


def test_nl_to_esql_status_filter():
    """Verify status filter conversion."""
    tool = ElasticFleetSearch.__new__(ElasticFleetSearch)
    tool.index_patterns = ["fleet-agents-*", "metrics-fleet.agent-default-*"]
    tool.schema = {}

    query = tool._nl_to_esql("online agents")
    assert "agent.status == 'online'" in query

    query = tool._nl_to_esql("offline agents")
    assert "agent.status == 'offline'" in query


def test_nl_to_esql_fields():
    """Verify base select fields are included."""
    tool = ElasticFleetSearch.__new__(ElasticFleetSearch)
    tool.index_patterns = ["fleet-agents-*", "metrics-fleet.agent-default-*"]
    tool.schema = {}

    query = tool._nl_to_esql("show me agents")
    assert "agent.id" in query
    assert "agent.name" in query
    assert "agent.status" in query
    assert "host.name" in query
