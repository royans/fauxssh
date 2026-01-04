import pytest
import sqlite3
import os
import json
import sys
from unittest.mock import MagicMock, patch

# Ensure we can import the tool
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from tools.analytics import fs_inspector

@pytest.fixture
def mock_db(tmp_path):
    """Creates a temporary SQLite database with user filesystem data."""
    db_file = tmp_path / "test_honeypot.sqlite"
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    
    # Create user_filesystem table
    c.execute('''
        CREATE TABLE user_filesystem (
            ip TEXT,
            username TEXT,
            path TEXT,
            parent_path TEXT,
            type TEXT,
            metadata TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_accessed TIMESTAMP,
            is_deleted BOOLEAN DEFAULT 0,
            PRIMARY KEY (ip, username, path)
        )
    ''')
    
    # Insert sample data
    # User 1: attacker@192.168.1.100
    c.execute("""
        INSERT INTO user_filesystem (ip, username, path, type, metadata, content)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ("192.168.1.100", "attacker", "/tmp/malware.sh", "file", json.dumps({"size": 123}), "rm -rf /"))
    
    c.execute("""
        INSERT INTO user_filesystem (ip, username, path, type, metadata, content)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ("192.168.1.100", "attacker", "/root/secrets.txt", "file", json.dumps({"size": 50}), "top secret"))

    # User 2: guest@10.0.0.5
    c.execute("""
        INSERT INTO user_filesystem (ip, username, path, type, metadata, content)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ("10.0.0.5", "guest", "/home/guest/notes", "file", json.dumps({"size": 10}), "hello"))

    conn.commit()
    conn.close()
    return str(db_file)

@pytest.fixture(autouse=True)
def configure_console():
    """Ensure rich console has enough width for tests."""
    fs_inspector.console.width = 200

def test_list_all_files(mock_db, capsys):
    """Verify listing all files works."""
    conn = fs_inspector.get_db_connection(mock_db)
    fs_inspector.list_user_files(conn)
    conn.close()
    
    captured = capsys.readouterr()
    assert "attacker" in captured.out
    assert "guest" in captured.out
    assert "/tmp/malware.sh" in captured.out
    assert "/home/guest/notes" in captured.out

def test_filter_by_ip(mock_db, capsys):
    """Verify filtering by IP."""
    conn = fs_inspector.get_db_connection(mock_db)
    fs_inspector.list_user_files(conn, ip="192.168.1.100")
    conn.close()
    
    captured = capsys.readouterr()
    assert "attacker" in captured.out
    assert "guest" not in captured.out

def test_filter_by_user(mock_db, capsys):
    """Verify filtering by Username."""
    conn = fs_inspector.get_db_connection(mock_db)
    fs_inspector.list_user_files(conn, username="guest")
    conn.close()
    
    captured = capsys.readouterr()
    assert "guest" in captured.out
    assert "attacker" not in captured.out

def test_cat_content(mock_db, capsys):
    """Verify showing file content."""
    conn = fs_inspector.get_db_connection(mock_db)
    fs_inspector.show_file_content(conn, "192.168.1.100", "attacker", "/tmp/malware.sh")
    conn.close()
    
    captured = capsys.readouterr()
    assert "rm -rf /" in captured.out

def test_cat_missing_file(mock_db, capsys):
    """Verify cat on missing file handles gracefully."""
    conn = fs_inspector.get_db_connection(mock_db)
    fs_inspector.show_file_content(conn, "192.168.1.100", "attacker", "/tmp/missing")
    conn.close()
    
    captured = capsys.readouterr()
    assert "File not found" in captured.out

def test_tree_view(mock_db, capsys):
    """Verify tree view output."""
    conn = fs_inspector.get_db_connection(mock_db)
    fs_inspector.list_user_files(conn, tree_view=True)
    conn.close()
    
    captured = capsys.readouterr()
    assert "192.168.1.100 (attacker)" in captured.out
    assert "📄 /tmp/malware.sh" in captured.out
    assert "📄 /tmp/malware.sh" in captured.out

def test_delete_confirmed(mock_db, capsys):
    """Verify deletion works when confirmed."""
    conn = fs_inspector.get_db_connection(mock_db)
    # Mocking Confirm.ask inside fs_inspector module
    with patch("tools.analytics.fs_inspector.Confirm.ask", return_value=True):
        fs_inspector.delete_user_files(conn, ip="192.168.1.100")
        
    captured = capsys.readouterr()
    assert "Successfully deleted 2 files" in captured.out
    
    # Verify deletion
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM user_filesystem WHERE ip='192.168.1.100'")
    assert cursor.fetchone()[0] == 0
    conn.close()

def test_delete_cancelled(mock_db, capsys):
    """Verify deletion aborts when cancelled."""
    conn = fs_inspector.get_db_connection(mock_db)
    with patch("tools.analytics.fs_inspector.Confirm.ask", return_value=False):
        fs_inspector.delete_user_files(conn, ip="192.168.1.100")
        
    captured = capsys.readouterr()
    assert "Deletion cancelled" in captured.out
    
    # Verify NO deletion
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM user_filesystem WHERE ip='192.168.1.100'")
    assert cursor.fetchone()[0] == 2
    conn.close()

def test_delete_skip_confirm(mock_db, capsys):
    """Verify deletion works with skip_confirm."""
    conn = fs_inspector.get_db_connection(mock_db)
    fs_inspector.delete_user_files(conn, ip="192.168.1.100", skip_confirm=True)
        
    captured = capsys.readouterr()
    assert "Successfully deleted 2 files" in captured.out
    
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM user_filesystem WHERE ip='192.168.1.100'")
    assert cursor.fetchone()[0] == 0
    conn.close()

def test_delete_specific_file(mock_db, capsys):
    """Verify deleting a specific file works."""
    conn = fs_inspector.get_db_connection(mock_db)
    
    # Target /root/secrets.txt specifically
    with patch("tools.analytics.fs_inspector.Confirm.ask", return_value=True):
        fs_inspector.delete_user_files(conn, ip="192.168.1.100", username="attacker", filepath="/root/secrets.txt")
        
    captured = capsys.readouterr()
    assert "Successfully deleted 1 files" in captured.out
    assert "Target File: /root/secrets.txt" in captured.out
    
    # Verify exact deletion
    cursor = conn.cursor()
    # Should still have malware.sh
    cursor.execute("SELECT count(*) FROM user_filesystem WHERE ip='192.168.1.100' AND path='/tmp/malware.sh'")
    assert cursor.fetchone()[0] == 1
    # Secrets gone
    cursor.execute("SELECT count(*) FROM user_filesystem WHERE ip='192.168.1.100' AND path='/root/secrets.txt'")
    assert cursor.fetchone()[0] == 0
    conn.close()
