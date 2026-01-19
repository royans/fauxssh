import pytest
import sqlite3
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.core.database import HoneyDB


@pytest.fixture
def test_db():
    # Use temporary file DB because :memory: is unique per connection
    # and HoneyDB opens new connection for each query
    import tempfile

    fd, path = tempfile.mkstemp()
    os.close(fd)

    db = HoneyDB(path)
    # Initialize schema
    conn = db._get_conn()
    c = conn.cursor()
    # Create necessary table for test
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            username TEXT,
            auth_method TEXT,
            auth_data TEXT,
            success BOOLEAN,
            client_version TEXT,
            fingerprint TEXT,
            protocol TEXT
        )
    """
    )
    conn.commit()
    conn.close()

    yield db

    # Cleanup
    try:
        os.remove(path)
    except:
        pass


def log_event(db, ip, user, success, protocol="ssh"):
    db.log_auth_event(ip, user, "password", "pwd", success, "SSH-2.0", None, protocol)


def test_root_desperation_normal(test_db):
    # Case: Fresh IP -> NORMAL
    assert test_db.check_root_desperation("1.1.1.1") == "NORMAL"


def test_root_desperation_block(test_db):
    # Case: Successful non-root login -> BLOCK
    log_event(test_db, "2.2.2.2", "user", True, protocol="ssh")
    assert test_db.check_root_desperation("2.2.2.2") == "BLOCK"


def test_root_desperation_allow(test_db):
    # Case: 2 failed root attempts -> ALLOW
    log_event(test_db, "3.3.3.3", "root", False, protocol="ssh")
    log_event(test_db, "3.3.3.3", "root", False, protocol="ssh")
    assert test_db.check_root_desperation("3.3.3.3") == "ALLOW"


def test_root_desperation_fail_conditions(test_db):
    # Case: 1 failed attempt -> NORMAL (Wait for 2 failures)
    log_event(test_db, "4.4.4.4", "root", False, protocol="ssh")
    assert test_db.check_root_desperation("4.4.4.4") == "NORMAL"

    # Case: 3 failures (Already failed 3rd time) -> NORMAL (Rule is exactly 2 prior failures to allow 3rd)
    # If they fail the 3rd allowed attempt, they are back to normal (failed).
    log_event(test_db, "4.4.4.4", "root", False, protocol="ssh")
    log_event(test_db, "4.4.4.4", "root", False, protocol="ssh")
    assert test_db.check_root_desperation("4.4.4.4") == "NORMAL"


def test_ssh_only_scope(test_db):
    # Case: Success via Telnet should NOT block SSH root (per user rule)
    log_event(test_db, "5.5.5.5", "user", True, protocol="telnet")
    assert test_db.check_root_desperation("5.5.5.5") == "NORMAL"

    # But success via SSH does block
    log_event(test_db, "5.5.5.5", "user", True, protocol="ssh")
    assert test_db.check_root_desperation("5.5.5.5") == "BLOCK"
