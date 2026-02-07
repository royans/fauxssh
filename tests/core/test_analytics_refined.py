import pytest
import sqlite3
import datetime
from datetime import timedelta
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.analytics_engine import AnalyticsEngine


class MockDBBackend:
    def __init__(self, conn):
        self.conn = conn
        self.is_postgres = False
        self.placeholder = "?"

    def _get_conn(self):
        # Ensure row_factory is set for the connection
        self.conn.row_factory = sqlite3.Row
        return self.conn


@pytest.fixture
def engine():
    # Helper to create a fresh DB and engine for each test
    def _create():
        conn = sqlite3.connect(":memory:")
        c = conn.cursor()
        c.execute(
            "CREATE TABLE sessions (session_id TEXT, remote_ip TEXT, username TEXT, password TEXT, start_time TEXT, end_time TEXT, client_version TEXT, fingerprint TEXT, protocol TEXT, summary TEXT, risk_score REAL)"
        )
        c.execute(
            "CREATE TABLE interactions (id INTEGER PRIMARY KEY, session_id TEXT, timestamp TEXT, remote_ip TEXT, command TEXT, response TEXT, source TEXT, request_md5 TEXT)"
        )
        c.execute(
            "CREATE TABLE command_analysis (command_hash TEXT, risk_score REAL, explanation TEXT, activity_type TEXT)"
        )
        c.execute(
            "CREATE TABLE ip_intelligence (ip TEXT PRIMARY KEY, country TEXT, city TEXT, isp TEXT, hostname TEXT, org TEXT, asn TEXT, network_type TEXT, abuse_tags TEXT)"
        )

        # Use UTC for consistency with SQLite datetime('now')
        now = datetime.datetime.now(datetime.timezone.utc)

        # Session 1: SSH (1 hour ago)
        c.execute(
            "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES ('s1', '1.1.1.1', 'ssh', ?)",
            (now - timedelta(hours=1),),
        )
        c.execute(
            "INSERT INTO interactions (session_id, command, timestamp, request_md5, remote_ip) VALUES ('s1', 'ls', ?, 'h1', '1.1.1.1')",
            (now - timedelta(minutes=50),),
        )
        c.execute(
            "INSERT INTO command_analysis (command_hash, risk_score) VALUES ('h1', 10)"
        )

        # Session 2: Telnet (2 hours ago)
        c.execute(
            "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES ('s2', '2.2.2.2', 'telnet', ?)",
            (now - timedelta(hours=2),),
        )
        c.execute(
            "INSERT INTO interactions (session_id, command, timestamp, request_md5, remote_ip) VALUES ('s2', 'id', ?, 'h2', '2.2.2.2')",
            (now - timedelta(minutes=100),),
        )
        c.execute(
            "INSERT INTO command_analysis (command_hash, risk_score) VALUES ('h2', 90)"
        )

        # Session 3: HTTP (3 hours ago)
        c.execute(
            "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES ('s3', '3.3.3.3', 'http', ?)",
            (now - timedelta(hours=3),),
        )

        # Intelligence Data for ASN count
        c.execute("INSERT INTO ip_intelligence (ip, asn) VALUES ('1.1.1.1', 'AS100')")
        c.execute("INSERT INTO ip_intelligence (ip, asn) VALUES ('2.2.2.2', 'AS200')")
        c.execute(
            "INSERT INTO ip_intelligence (ip, asn) VALUES ('3.3.3.3', 'AS100')"
        )  # Duplicate ASN

        conn.commit()
        return AnalyticsEngine(MockDBBackend(conn))

    return _create()


def test_get_dashboard_totals(engine):
    with patch("ssh_honeypot.core.analytics_engine.get_ignored_ips", return_value=[]):
        totals = engine.get_dashboard_totals(hours=24)
        # 3 sessions, 2 commands, 3 unique IPs, 2 unique ASNs
        assert totals["total_sessions"] == 3
        assert totals["total_commands"] == 2
        assert totals["unique_ips"] == 3
        assert totals["unique_asns"] == 2


def test_multi_protocol_filtering_single(engine):
    # Single protocol filter
    sessions = engine.get_recent_sessions(protocol_filter="ssh")
    assert len(sessions) == 1
    # sqlite3.Row supports name access
    assert sessions[0]["protocol"] == "ssh"


def test_multi_protocol_filtering_list(engine):
    # List protocol filter
    sessions = engine.get_recent_sessions(protocol_filter=["ssh", "telnet"])
    assert len(sessions) == 2
    protocols = [s["protocol"] for s in sessions]
    assert "ssh" in protocols
    assert "telnet" in protocols


def test_totals_time_window(engine):
    # Test shorter time window (e.g. 1.5 hours)
    # We use SQLite datetime('now') in AnalyticsEngine, so we must be careful with 'now' in tests.
    # In tests, we insert explicit timestamps.
    with patch("ssh_honeypot.core.analytics_engine.get_ignored_ips", return_value=[]):
        totals = engine.get_dashboard_totals(hours=1.5)
        # s1 is 1h ago, s2 is 2h ago, s3 is 3h ago.
        assert totals["total_sessions"] == 1  # Only s1
        assert totals["total_commands"] == 1  # Only from s1
