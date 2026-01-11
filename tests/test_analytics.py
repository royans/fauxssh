import pytest
import sqlite3
import os
import sys
from unittest.mock import MagicMock, patch

# Add tools/analytics to path to import analyze
sys.path.append(os.path.join(os.path.dirname(__file__), "../tools/analytics"))

# We import the module to test its functions
import analyze


@pytest.fixture
def mock_db_conn():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()

    # Create necessary schemas
    c.execute(
        "CREATE TABLE sessions (session_id TEXT, remote_ip TEXT, username TEXT, password TEXT, start_time TEXT, end_time TEXT, client_version TEXT, fingerprint TEXT)"
    )
    c.execute(
        "CREATE TABLE interactions (id INTEGER PRIMARY KEY, session_id TEXT, timestamp TEXT, remote_ip TEXT, username TEXT, command TEXT, response TEXT, source TEXT, duration_ms INTEGER, request_md5 TEXT, response_md5 TEXT, response_head TEXT, response_size INTEGER)"
    )
    c.execute(
        "CREATE TABLE command_analysis (command_hash TEXT, risk_score REAL, explanation TEXT, activity_type TEXT)"
    )

    conn.commit()
    conn.row_factory = sqlite3.Row
    return conn


def extract_text(renderable):
    """
    Helper to extract plain text string from Rich renderables (Text, Group, etc.)
    Used to fix tests after switching to Rich objects in Command column.
    """
    from rich.text import Text
    from rich.console import Group

    if isinstance(renderable, str):
        return renderable
    if isinstance(renderable, Text):
        return renderable.plain
    if isinstance(renderable, Group):
        # Join the string representation of renderables in the group
        # For our use case (Command + Rule + Output), the first item is the command Text
        # But let's be robust and join all Text parts
        parts = []
        for r in renderable.renderables:
            if isinstance(r, Text):
                parts.append(r.plain)
            # Ignore Rules for text comparison
        return "\n".join(parts)
    return str(renderable)


def test_unique_pct_calculation(mock_db_conn, capsys):
    # ... (setup code omitted, same as before) ...
    c = mock_db_conn.cursor()

    # 1. Setup Sessions (Define Total Unique IPs = 4)
    sessions = [
        ("s1", "10.0.0.1"),
        ("s2", "10.0.0.2"),
        ("s3", "10.0.0.3"),
        ("s4", "10.0.0.4"),
    ]
    for sid, ip in sessions:
        c.execute(
            "INSERT INTO sessions (session_id, remote_ip) VALUES (?, ?)", (sid, ip)
        )

    # 2. Setup Interactions
    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashX', 'cmdX', '2026-01-01 10:00:00')"
    )
    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s2', 'hashX', 'cmdX', '2026-01-01 10:00:00')"
    )
    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s3', 'hashY', 'cmdY', '2026-01-01 10:00:00')"
    )

    mock_db_conn.commit()

    with patch("analyze.get_db_connection", return_value=mock_db_conn):
        with patch("analyze.console.print") as mock_print:
            analyze.list_commands(limit=10)

            args, _ = mock_print.call_args
            table = args[0]

            unique_cells = list(table.columns[6].cells)
            cmd_cells = [extract_text(c) for c in table.columns[3].cells]

            # Verify Command X (cmdX) -> 50.0%
            idx_x = cmd_cells.index("cmdX")
            assert unique_cells[idx_x] == "50.0%"

            # Verify Command Y (cmdY) -> 75.0%
            idx_y = cmd_cells.index("cmdY")
            assert unique_cells[idx_y] == "75.0%"


def test_unique_pct_shared_ip(mock_db_conn):
    c = mock_db_conn.cursor()
    c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES ('s1', '10.0.0.1')")
    c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES ('s2', '10.0.0.2')")

    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashZ', 'cmdZ', '2026-01-01')"
    )
    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashZ', 'cmdZ', '2026-01-01')"
    )

    mock_db_conn.commit()

    with patch("analyze.get_db_connection", return_value=mock_db_conn):
        with patch("analyze.console.print") as mock_print:
            analyze.list_commands(limit=10)
            args, _ = mock_print.call_args
            table = args[0]

            unique_cells = list(table.columns[6].cells)
            cmd_cells = [extract_text(c) for c in table.columns[3].cells]

            idx = cmd_cells.index("cmdZ")
            assert unique_cells[idx] == "50.0%"


def setup_sorting_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "CREATE TABLE sessions (session_id TEXT, remote_ip TEXT, username TEXT, password TEXT, start_time TEXT, end_time TEXT, client_version TEXT, fingerprint TEXT)"
    )
    c.execute(
        "CREATE TABLE interactions (id INTEGER PRIMARY KEY, session_id TEXT, timestamp TEXT, remote_ip TEXT, username TEXT, command TEXT, response TEXT, source TEXT, duration_ms INTEGER, request_md5 TEXT, response_md5 TEXT, response_head TEXT, response_size INTEGER)"
    )
    c.execute(
        "CREATE TABLE command_analysis (command_hash TEXT, risk_score REAL, explanation TEXT, activity_type TEXT)"
    )

    c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES ('s1', '10.0.0.1')")
    c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES ('s2', '10.0.0.2')")

    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashCommon', 'cmdCommon', '2026-01-01 10:00:00')"
    )
    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s2', 'hashCommon', 'cmdCommon', '2026-01-01 10:05:00')"
    )
    c.execute(
        "INSERT INTO command_analysis (command_hash, risk_score) VALUES ('hashCommon', 1.0)"
    )

    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashRare', 'cmdRare', '2026-01-01 10:01:00')"
    )
    c.execute(
        "INSERT INTO command_analysis (command_hash, risk_score) VALUES ('hashRare', 10.0)"
    )

    conn.commit()
    return conn


def test_sorting_risk():
    conn = setup_sorting_db()
    with patch("analyze.get_db_connection", return_value=conn):
        with patch("analyze.console.print") as mock_print:
            analyze.list_commands(limit=10, sort_param="Risk:Desc")
            args, _ = mock_print.call_args
            table = args[0]
            cmd_cells = [extract_text(c) for c in table.columns[3].cells]
            assert cmd_cells[0] == "cmdRare"
            assert cmd_cells[1] == "cmdCommon"


def test_sorting_risk_asc():
    conn = setup_sorting_db()
    with patch("analyze.get_db_connection", return_value=conn):
        with patch("analyze.console.print") as mock_print:
            analyze.list_commands(limit=10, sort_param="Risk:Asc")
            args, _ = mock_print.call_args
            table = args[0]
            cmd_cells = [extract_text(c) for c in table.columns[3].cells]
            assert cmd_cells[0] == "cmdCommon"


def test_sorting_unique():
    conn = setup_sorting_db()
    with patch("analyze.get_db_connection", return_value=conn):
        with patch("analyze.console.print") as mock_print:
            analyze.list_commands(limit=10, sort_param="Unique:Desc")
            args, _ = mock_print.call_args
            table = args[0]
            cmd_cells = [extract_text(c) for c in table.columns[3].cells]
            assert cmd_cells[0] == "cmdRare"
            assert cmd_cells[1] == "cmdCommon"


def test_ipv6_mapped_filtering():
    conn = setup_sorting_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO sessions (session_id, remote_ip, username) VALUES ('sMapped', '::ffff:192.168.1.5', 'uMapped')"
    )
    c.execute(
        "INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('sMapped', 'h', 'cmdMapped', '2026-01-01 12:00:00')"
    )
    conn.commit()

    with patch("analyze.get_db_connection", return_value=conn):
        with patch("analyze.console.print") as mock_print:
            analyze.list_commands(limit=10, ip_filter="192.168.1.5")

            if not mock_print.called:
                assert False, "List commands should have printed a table"

            args, _ = mock_print.call_args
            table = args[0]

            assert table.row_count == 1
            cmd_cells = [extract_text(c) for c in table.columns[3].cells]
            assert "cmdMapped" in cmd_cells
