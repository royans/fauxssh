import os
import sqlite3
import pytest
from datetime import datetime, timedelta
from ssh_honeypot.core.database import SQLiteBackend


@pytest.fixture
def db_backend(tmp_path):
    db_file = tmp_path / "test_honeypot.sqlite"
    backend = SQLiteBackend(str(db_file))
    return backend


def test_infographic_stats_new_fields(db_backend):
    # Setup - Inject some data for current and previous windows
    now = datetime.now()
    yesterday = now - timedelta(days=1)

    conn = db_backend._get_conn()
    c = conn.cursor()

    # Sessions
    c.execute(
        "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES (?, ?, ?, ?)",
        ("sid1", "1.1.1.1", "ssh", now.strftime("%Y-%m-%d %H:%M:%S")),
    )
    c.execute(
        "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES (?, ?, ?, ?)",
        ("sid2", "2.2.2.2", "mysql", now.strftime("%Y-%m-%d %H:%M:%S")),
    )
    c.execute(
        "INSERT INTO sessions (session_id, remote_ip, protocol, start_time) VALUES (?, ?, ?, ?)",
        ("sid_old", "3.3.3.3", "ssh", yesterday.strftime("%Y-%m-%d %H:%M:%S")),
    )

    # Interactions
    c.execute(
        "INSERT INTO interactions (session_id, command, timestamp, request_md5) VALUES (?, ?, ?, ?)",
        ("sid1", "ls -la", now.strftime("%Y-%m-%d %H:%M:%S"), "md5_1"),
    )
    c.execute(
        "INSERT INTO interactions (session_id, command, timestamp, request_md5) VALUES (?, ?, ?, ?)",
        ("sid2", "SELECT 1", now.strftime("%Y-%m-%d %H:%M:%S"), "md5_2"),
    )

    # Risk Analysis
    c.execute(
        "INSERT INTO command_analysis (command_hash, risk_score) VALUES (?, ?)",
        ("md5_1", 9),
    )

    # Payloads
    c.execute(
        "INSERT INTO malicious_payloads (url, url_hash, timestamp) VALUES (?, ?, ?)",
        ("http://malware.com/x", "url_hash", now.strftime("%Y-%m-%d %H:%M:%S")),
    )

    conn.commit()
    conn.close()

    stats = db_backend.get_infographic_stats(hours=24)

    # Verify new fields
    assert "trends" in stats
    assert "ips" in stats["trends"]
    assert "sessions" in stats["trends"]
    assert "commands" in stats["trends"]

    assert "total_networks" in stats
    assert "total_payloads" in stats
    assert stats["total_payloads"] == 1

    assert "top_mysql_commands" in stats
    assert len(stats["top_mysql_commands"]) > 0
    assert stats["top_mysql_commands"][0]["command"] == "SELECT 1"

    assert "top_redis_commands" in stats
    assert "top_mcp_commands" in stats
    assert "protocol_activity" in stats
    assert stats["protocol_activity"]["ssh"] > 0

    assert "top_ssh_risk" in stats
    assert len(stats["top_ssh_risk"]) > 0
    assert stats["top_ssh_risk"][0]["risk"] == 9
    assert stats["top_ssh_risk"][0]["ips"] == 1

    assert "service_dist" in stats
    # Check if sessions and commands counts are there (New Structure: name, value)
    ssh_dist = next(s for s in stats["service_dist"] if s["name"] == "SSH")
    assert "value" in ssh_dist
    assert ssh_dist["value"] > 0

    assert "protocol_stats" in stats
    assert "ssh" in stats["protocol_stats"]
    assert stats["protocol_stats"]["ssh"]["sessions"] > 0
    assert stats["protocol_stats"]["ssh"]["interactions"] > 0
    assert stats["protocol_stats"]["ssh"]["ips"] > 0


def test_daily_trends(db_backend):
    trends = db_backend.get_daily_session_counts(days=7)
    assert len(trends) == 7
    assert "label" in trends[0]
    assert "count" in trends[0]
