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
    c.execute("CREATE TABLE sessions (session_id TEXT, remote_ip TEXT, username TEXT, password TEXT, start_time TEXT, end_time TEXT, client_version TEXT, fingerprint TEXT)")
    c.execute("CREATE TABLE interactions (id INTEGER PRIMARY KEY, session_id TEXT, timestamp TEXT, remote_ip TEXT, username TEXT, command TEXT, response TEXT, source TEXT, duration_ms INTEGER, request_md5 TEXT, response_md5 TEXT, response_head TEXT, response_size INTEGER)")
    c.execute("CREATE TABLE command_analysis (command_hash TEXT, risk_score REAL, explanation TEXT, activity_type TEXT)")
    
    conn.commit()
    conn.row_factory = sqlite3.Row
    return conn

def test_unique_pct_calculation(mock_db_conn, capsys):
    """
    Test Unique% Calculation Logic:
    Scenario:
    - 4 Unique IPs total in the system (A, B, C, D)
    - Command X is run by IPs: A, B (2 IPs)
    - Frequency = 2/4 = 50%
    - Unique% = 100 - 50 = 50%
    
    - Command Y is run by IP: C (1 IP)
    - Frequency = 1/4 = 25%
    - Unique% = 100 - 25 = 75%
    """
    c = mock_db_conn.cursor()
    
    # 1. Setup Sessions (Define Total Unique IPs = 4)
    # IPs: 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4
    sessions = [
        ('s1', '10.0.0.1'),
        ('s2', '10.0.0.2'),
        ('s3', '10.0.0.3'),
        ('s4', '10.0.0.4')
    ]
    for sid, ip in sessions:
        c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES (?, ?)", (sid, ip))
        
    # 2. Setup Interactions
    # Command X (hash='hashX'): Run by s1(IP1) and s2(IP2)
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashX', 'cmdX', '2026-01-01 10:00:00')")
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s2', 'hashX', 'cmdX', '2026-01-01 10:00:00')")
    
    # Command Y (hash='hashY'): Run by s3(IP3) only
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s3', 'hashY', 'cmdY', '2026-01-01 10:00:00')")
    
    mock_db_conn.commit()
    
    # Mock get_db_connection to return our in-memory DB
    with patch('analyze.get_db_connection', return_value=mock_db_conn):
        # We need to capture the output printed to console
        with patch('analyze.console.print') as mock_print:
             # Run list_commands
             analyze.list_commands(limit=10)
             
             # Extract the table object passed to console.print
             # Rich Table objects hold data in .columns or .rows (internal structure)
             # Easier way: Verify the calculated values appeared in the table data
             
             # The table is the first arg to the first call
             args, _ = mock_print.call_args
             table = args[0]
             
             # Iterate rows to verify values
             # Rich Table stores rows in columns... getting data out is a bit tricky without exporting
             # We can check columns[4] which is "Unique%"
             
             # Let's inspect the columns. Note: Order matters.
             # 0:Time, 1:IP, 2:User, 3:Command, 4:Size, 5:Src, 6:Unique%, 7:Risk, 8:Analysis
             
             unique_col_index = 6
             cmd_col_index = 3
             
             # Extract data from columns (Rich API structure)
             # This depends on rich version, commonly table.columns[i]._cells
             unique_cells = list(table.columns[unique_col_index].cells)
             cmd_cells = list(table.columns[cmd_col_index].cells)
             
             # Verify Command X (cmdX) -> 50.0%
             # Verify Command Y (cmdY) -> 75.0%
             
             # Find index of cmdX
             idx_x = cmd_cells.index('cmdX')
             assert unique_cells[idx_x] == '50.0%'
             
             # Find index of cmdY
             idx_y = cmd_cells.index('cmdY') 
             assert unique_cells[idx_y] == '75.0%'

def test_unique_pct_shared_ip(mock_db_conn):
    """
    Test logic when one IP runs command multiple times.
    Should count as 1 IP regarding frequency.
    Total IPs = 2 (A, B)
    IP A runs Cmd Z 100 times.
    IP B never runs Cmd Z.
    Freq = 1 (IP A) / 2 (Total IPs) = 50%
    Unique% = 50%
    """
    c = mock_db_conn.cursor()
    c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES ('s1', '10.0.0.1')")
    c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES ('s2', '10.0.0.2')")
    
    # IP 1 runs cmdZ twice
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashZ', 'cmdZ', '2026-01-01')")
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashZ', 'cmdZ', '2026-01-01')")
    
    mock_db_conn.commit()
    
    with patch('analyze.get_db_connection', return_value=mock_db_conn):
        with patch('analyze.console.print') as mock_print:
             analyze.list_commands(limit=10)
             args, _ = mock_print.call_args
             table = args[0]
             
             unique_cells = list(table.columns[6].cells) # Unique% col
             cmd_cells = list(table.columns[3].cells)    # Command col
             
             idx = cmd_cells.index('cmdZ')
             # 1 unique IP out of 2 total IPs = 50% freq -> 50% unique
             assert unique_cells[idx] == '50.0%'

def setup_sorting_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("CREATE TABLE sessions (session_id TEXT, remote_ip TEXT, username TEXT, password TEXT, start_time TEXT, end_time TEXT, client_version TEXT, fingerprint TEXT)")
    c.execute("CREATE TABLE interactions (id INTEGER PRIMARY KEY, session_id TEXT, timestamp TEXT, remote_ip TEXT, username TEXT, command TEXT, response TEXT, source TEXT, duration_ms INTEGER, request_md5 TEXT, response_md5 TEXT, response_head TEXT, response_size INTEGER)")
    c.execute("CREATE TABLE command_analysis (command_hash TEXT, risk_score REAL, explanation TEXT, activity_type TEXT)")
    
    # 1. Setup Sessions
    c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES ('s1', '10.0.0.1')")
    c.execute("INSERT INTO sessions (session_id, remote_ip) VALUES ('s2', '10.0.0.2')")
    
    # 2. Setup Interactions/Analysis
    # cmdCommon (1.0 risk, common)
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashCommon', 'cmdCommon', '2026-01-01 10:00:00')")
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s2', 'hashCommon', 'cmdCommon', '2026-01-01 10:05:00')")
    c.execute("INSERT INTO command_analysis (command_hash, risk_score) VALUES ('hashCommon', 1.0)")
    
    # cmdRare (10.0 risk, rare)
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('s1', 'hashRare', 'cmdRare', '2026-01-01 10:01:00')")
    c.execute("INSERT INTO command_analysis (command_hash, risk_score) VALUES ('hashRare', 10.0)")
    
    conn.commit()
    return conn

def test_sorting_risk():
    conn = setup_sorting_db()
    with patch('analyze.get_db_connection', return_value=conn):
        with patch('analyze.console.print') as mock_print:
             analyze.list_commands(limit=10, sort_param="Risk:Desc")
             args, _ = mock_print.call_args
             table = args[0]
             cmd_cells = list(table.columns[3].cells) 
             assert cmd_cells[0] == 'cmdRare'
             assert cmd_cells[1] == 'cmdCommon'

def test_sorting_risk_asc():
    conn = setup_sorting_db()
    with patch('analyze.get_db_connection', return_value=conn):
        with patch('analyze.console.print') as mock_print:
             analyze.list_commands(limit=10, sort_param="Risk:Asc")
             args, _ = mock_print.call_args
             table = args[0]
             cmd_cells = list(table.columns[3].cells)
             assert cmd_cells[0] == 'cmdCommon'

def test_sorting_unique():
    conn = setup_sorting_db()
    with patch('analyze.get_db_connection', return_value=conn):
        with patch('analyze.console.print') as mock_print:
             analyze.list_commands(limit=10, sort_param="Unique:Desc")
             args, _ = mock_print.call_args
             table = args[0]
             cmd_cells = list(table.columns[3].cells)
             assert cmd_cells[0] == 'cmdRare'
             assert cmd_cells[1] == 'cmdCommon'

def test_ipv6_mapped_filtering():
    """
    Test that filtering by '1.2.3.4' finds '::ffff:1.2.3.4'
    """
    conn = setup_sorting_db()
    c = conn.cursor()
    # Insert a session with mapped IPv6
    c.execute("INSERT INTO sessions (session_id, remote_ip, username) VALUES ('sMapped', '::ffff:192.168.1.5', 'uMapped')")
    c.execute("INSERT INTO interactions (session_id, request_md5, command, timestamp) VALUES ('sMapped', 'h', 'cmdMapped', '2026-01-01 12:00:00')")
    conn.commit()
    
    with patch('analyze.get_db_connection', return_value=conn):
        with patch('analyze.console.print') as mock_print:
             # Filter by pure IPv4
             analyze.list_commands(limit=10, ip_filter="192.168.1.5")
             
             if not mock_print.called:
                 assert False, "List commands should have printed a table"
                 
             args, _ = mock_print.call_args
             table = args[0]
             
             # Should be 1 row
             assert table.row_count == 1
             # IP column might be cleaned, check Command column
             cmd_cells = list(table.columns[3].cells)
             assert 'cmdMapped' in cmd_cells
