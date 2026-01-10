import pytest
import datetime
from unittest.mock import MagicMock, patch
from ssh_honeypot.handlers.unix.cmd_who import WhoCommand
from ssh_honeypot.handlers.unix.cmd_w import WCommand
from ssh_honeypot.handlers.unix.cmd_last import LastCommand

@pytest.fixture
def mock_db():
    db = MagicMock()
    # Setup standard active sessions
    db.get_active_sessions.return_value = [
        {'user': 'root', 'ip': '192.168.1.55', 'start_time': '2023-10-27T10:00:00', 'session_id': 'sess1', 'tty': 'pts/0'},
        {'user': 'user', 'ip': '10.0.0.5', 'start_time': '2023-10-27T10:05:00', 'session_id': 'sess2', 'tty': 'pts/1'}
    ]
    # Setup recent sessions for last
    db.get_recent_sessions.return_value = [
        {'user': 'user', 'ip': '10.0.0.5', 'start_time': '2023-10-27T10:05:00', 'end_time': None, 'session_id': 'sess2', 'tty': 'pts/1'},
        {'user': 'root', 'ip': '192.168.1.55', 'start_time': '2023-10-27T10:00:00', 'end_time': '2023-10-27T10:30:00', 'session_id': 'sess1', 'tty': 'pts/0'}
    ]
    return db

def test_who_output(mock_db):
    handler = WhoCommand(mock_db, MagicMock())
    context = {}
    output, _, _ = handler.handle("who", context)
    
    assert "root     pts/0        2023-10-27 10:00 (192.168.1.55)" in output
    assert "user     pts/1        2023-10-27 10:05 (10.0.0.5)" in output

def test_w_output(mock_db):
    handler = WCommand(mock_db, MagicMock())
    context = {}
    # Mock datetime to ensure consistent header check? 
    # Or just check substrings.
    output, _, _ = handler.handle("w", context)
    
    # Check header parts
    assert "load average:" in output
    assert "2 users" in output
    # Check body
    assert "root     pts/0    192.168.1.55     10:00" in output
    assert "user     pts/1    10.0.0.5         10:05" in output

def test_last_output(mock_db):
    handler = LastCommand(mock_db, MagicMock())
    context = {}
    
    # Patch random to ensure deterministic output for LAST 2 OCTETS
    # Logic in cmd_last: ip_parts[2] = str(random.randint(0, 255))
    # We want original IP 10.0.0.5 -> 10.0.0.5 (parts[2]=0, parts[3]=5)
    # mock_random.randint.side_effect = ...
    
    # Actually, simpler to just allow ANY IP in output check or partial match strings.
    # checking "user     pts/1        10.0." is safer.
    
    output, _, _ = handler.handle("last", context)
    
    # Check formatting
    # Active session - user (10.0.0.5)
    # Anonymized: 10.0.X.Y
    assert "user     pts/1        10.0." in output
    assert "still logged in" in output
    
    # Closed session - root (192.168.1.55)
    # Anonymized: 192.168.X.Y
    assert "root     pts/0        192.168." in output
    assert "- 10:30" in output
    
    assert "wtmp begins" in output

def test_no_db_graceful_handling():
    # If DB is missing for some reason
    handler = WhoCommand(None, MagicMock())
    context = {} 
    output, _, _ = handler.handle("who", context)
    assert output == "\n" # Empty lines?
    
