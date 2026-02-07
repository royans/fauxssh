import pytest
import sqlite3
import datetime
from datetime import timedelta
from ssh_honeypot.core.analytics_engine import AnalyticsEngine


class MockDBBackend:
    def __init__(self, conn):
        self.conn = conn
        self.is_postgres = False
        self.placeholder = "?"

    def _get_conn(self):
        self.conn.row_factory = sqlite3.Row
        return self.conn


@pytest.fixture
def engine():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute(
        "CREATE TABLE sessions (session_id TEXT, remote_ip TEXT, username TEXT, password TEXT, start_time TEXT, end_time TEXT, client_version TEXT, fingerprint TEXT, protocol TEXT, summary TEXT, risk_score REAL)"
    )
    c.execute(
        "CREATE TABLE interactions (id INTEGER PRIMARY KEY, session_id TEXT, timestamp TEXT, remote_ip TEXT, command TEXT, response TEXT, source TEXT, request_md5 TEXT)"
    )
    c.execute(
        "CREATE TABLE ip_intelligence (ip TEXT PRIMARY KEY, country TEXT, city TEXT, isp TEXT, hostname TEXT, org TEXT, asn TEXT, network_type TEXT, abuse_tags TEXT)"
    )

    # Insert Data
    now = datetime.datetime.now(datetime.timezone.utc)

    # Check if we should use string format for SQLite
    # AnalyticsEngine uses datetime objects where possible or standardizes them.
    # We'll just use ISO strings for DB insertion to be safe.

    # 3 Sessions from US, 1 from DE
    # US1: 2 ssh sessions
    c.execute(
        "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES ('s1', '1.1.1.1', 'ssh', ?)",
        ((now - timedelta(hours=1)).isoformat(),),
    )
    c.execute(
        "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES ('s2', '1.1.1.1', 'ssh', ?)",
        ((now - timedelta(hours=2)).isoformat(),),
    )

    # US2: 1 http session
    c.execute(
        "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES ('s3', '2.2.2.2', 'http', ?)",
        ((now - timedelta(hours=3)).isoformat(),),
    )

    # DE1: 1 telnet session
    c.execute(
        "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES ('s4', '3.3.3.3', 'telnet', ?)",
        ((now - timedelta(hours=4)).isoformat(),),
    )

    # Interactions (for ASNs/IPs command counts)
    c.execute(
        "INSERT INTO interactions (session_id, timestamp) VALUES ('s1', ?)",
        (now.isoformat(),),
    )
    c.execute(
        "INSERT INTO interactions (session_id, timestamp) VALUES ('s1', ?)",
        (now.isoformat(),),
    )  # 2 cmds
    c.execute(
        "INSERT INTO interactions (session_id, timestamp) VALUES ('s2', ?)",
        (now.isoformat(),),
    )  # 1 cmd

    # Intelligence
    c.execute(
        "INSERT INTO ip_intelligence (ip, country, asn, org) VALUES ('1.1.1.1', 'United States', 'AS100', 'Google')"
    )
    c.execute(
        "INSERT INTO ip_intelligence (ip, country, asn, org) VALUES ('2.2.2.2', 'United States', 'AS200', 'Amazon')"
    )
    c.execute(
        "INSERT INTO ip_intelligence (ip, country, asn, org) VALUES ('3.3.3.3', 'Germany', 'AS300', 'Telekom')"
    )

    conn.commit()
    return AnalyticsEngine(MockDBBackend(conn))


def test_get_top_countries(engine):
    stats = engine.get_top_countries(hours=24)
    assert len(stats) >= 2

    # Sort by unique IPs desc
    us = next(s for s in stats if s["country"] == "United States")
    de = next(s for s in stats if s["country"] == "Germany")

    # US: 1.1.1.1 and 2.2.2.2 = 2 unique IPs
    assert us["unique_ips"] == 2
    # Total sessions: s1, s2, s3 = 3
    assert us["total_sessions"] == 3
    # Check Protocols
    assert us["protocols"]["ssh"]["unique_ips"] == 1  # 1.1.1.1
    assert us["protocols"]["ssh"]["sessions"] == 2
    assert us["protocols"]["http"]["unique_ips"] == 1  # 2.2.2.2

    # DE: 3.3.3.3 = 1 unique IP
    assert de["unique_ips"] == 1
    assert de["total_sessions"] == 1


def test_get_top_ips(engine):
    stats = engine.get_top_ips(hours=24)
    # 1.1.1.1 should have 2 sessions, 3 cmds (2+1)
    ip1 = next(s for s in stats if s["ip"] == "1.1.1.1")
    assert ip1["total_sessions"] == 2
    assert ip1["total_commands"] == 3
    assert ip1["country"] == "United States"
    assert ip1["protocols"]["ssh"]["sessions"] == 2

    # 3.3.3.3
    ip3 = next(s for s in stats if s["ip"] == "3.3.3.3")
    assert ip3["total_sessions"] == 1
    assert ip3["protocols"]["telnet"]["sessions"] == 1


def test_get_top_asns(engine):
    stats = engine.get_top_asns(hours=24)
    # AS100 (Google): 1.1.1.1 (Target)
    as100 = next(s for s in stats if s["asn"] == "AS100")
    assert as100["unique_ips"] == 1
    assert as100["total_sessions"] == 2
    assert as100["total_commands"] == 3
