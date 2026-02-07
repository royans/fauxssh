import pytest
from unittest.mock import MagicMock, call
from ssh_honeypot.core.db_postgres import PostgresBackend


class MockPostgresBackend(PostgresBackend):
    def __init__(self):
        self._pool = MagicMock()
        self.conn_params = {}
        self._mock_conn = MagicMock()

    def _get_conn(self):
        return self._mock_conn


def test_get_recent_top_commands_by_risk_postgres_logic():
    # Setup
    backend = MockPostgresBackend()
    mock_conn = backend._get_conn()
    mock_cursor = mock_conn.cursor()

    # Mock return data
    mock_cursor.fetchall.return_value = [
        ("SELECT * FROM users", 100, 5, 2),
        ("version", 0, 20, 1),
    ]

    # Execute
    results = backend.get_recent_top_commands_by_risk(protocol="mysql", limit=10)

    # Verify Logic
    assert len(results) == 2
    assert results[0]["command"] == "SELECT * FROM users"
    assert results[0]["risk"] == 100
    assert results[1]["command"] == "version"
    assert results[1]["risk"] == 0

    # Verify Query Structure (Postgres uses %s)
    args, _ = mock_cursor.execute.call_args
    query_str = args[0]

    assert "LEFT JOIN command_analysis" in query_str
    assert "COALESCE(ca.risk_score, 0)" in query_str
    assert "LIMIT %s" in query_str
    assert "s.protocol = %s" in query_str
