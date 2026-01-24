import pytest
import os
import sqlite3
from ssh_honeypot.core.database import HoneyDB


@pytest.fixture
def db():
    # Use a fresh in-memory or temp DB for isolation test
    db_path = "test_protocol_iso.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    db_inst = HoneyDB(db_path=db_path)
    yield db_inst

    if os.path.exists(db_path):
        os.remove(db_path)


def test_protocol_isolation(db):
    """
    Verifies that MySQL commands do not leak into SSH stats.
    """
    # 1. Start a MySQL Session
    mysql_sid = "mysql-sess-123"
    db.start_session(
        session_id=mysql_sid,
        ip="1.1.1.1",
        username="root",
        password="password",
        client_version="mysql-client-8.0",
        protocol="mysql",  # The fix
    )

    # 2. Log a MySQL command
    db.log_interaction(
        session_id=mysql_sid,
        cwd="mysql",
        command="CREATE DATABASE leak_test",
        response="OK",
        source="llm",
    )

    # 3. Start an SSH Session
    ssh_sid = "ssh-sess-456"
    db.start_session(
        session_id=ssh_sid,
        ip="2.2.2.2",
        username="admin",
        password="password",
        client_version="OpenSSH_8.0",
        protocol="ssh",
    )

    # 4. Log an SSH command
    db.log_interaction(
        session_id=ssh_sid,
        cwd="/root",
        command="ls -la",
        response="total 0",
        source="llm",
    )

    # 5. Fetch Infographic Stats
    stats = db.get_infographic_stats(hours=1)

    # 6. Assertions
    ssh_cmds = [c["command"] for c in stats.get("top_ssh_commands", [])]
    mysql_cmds = [c["command"] for c in stats.get("top_mysql_commands", [])]

    print(f"SSH Commands: {ssh_cmds}")
    print(f"MySQL Commands: {mysql_cmds}")

    assert "ls -la" in ssh_cmds
    assert "CREATE DATABASE leak_test" not in ssh_cmds
    assert "CREATE DATABASE leak_test" in mysql_cmds
    assert "ls -la" not in mysql_cmds

    # 7. Check Top Passwords (should also be isolated)
    passwords = [p["password"] for p in stats.get("top_passwords", [])]
    # We added protocol='ssh' filter to top_passwords, so MySQL password shouldn't be there
    # Wait, the current implementation of start_session puts password in the sessions table.
    # get_infographic_stats filters sessions for top_passwords by protocol='ssh'.
    # Our MySQL session now has protocol='mysql'

    # Actually, in our test we used 'password' for both.
    # Let's use unique ones.


def test_password_isolation(db):
    # 1. MySQL Session with unique password
    db.start_session(
        session_id="m1",
        ip="1.1.1.1",
        username="root",
        password="MYSQL_SECRET",
        client_version="v1",
        protocol="mysql",
    )

    # 2. SSH Session with unique password
    db.start_session(
        session_id="s1",
        ip="2.2.2.2",
        username="admin",
        password="SSH_SECRET",
        client_version="v2",
        protocol="ssh",
    )

    # Ensure interactions exist for sessions to be counted (if end_session deletes empty ones)
    db.log_interaction("m1", "mysql", "SELECT 1", "1")
    db.log_interaction("s1", "/", "ls", "ok")

    stats = db.get_infographic_stats(hours=1)
    passwords = [p["password"] for p in stats.get("top_passwords", [])]

    assert "SSH_SECRET" in passwords
    assert "MYSQL_SECRET" not in passwords
