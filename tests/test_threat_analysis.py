import pytest
import sqlite3
import os
import json
from unittest.mock import MagicMock, patch
from ssh_honeypot.honey_db import HoneyDB
from ssh_honeypot.llm_interface import LLMInterface

# --- HoneyDB Tests ---

@pytest.fixture
def test_db(tmp_path):
    db_path = tmp_path / "test_honey.sqlite"
    db = HoneyDB(str(db_path))
    return db

def test_save_and_get_analysis(test_db):
    cmd_hash = "md5hash123"
    cmd = "rm -rf /"
    analysis = {
        "type": "Impact",
        "stage": "Actions",
        "risk": 10,
        "explanation": "Destructive command"
    }

    test_db.save_analysis(cmd_hash, cmd, analysis)

    saved = test_db.get_analysis(cmd_hash)
    assert saved is not None
    assert saved['hash'] == cmd_hash
    assert saved['text'] == cmd
    assert saved['type'] == "Impact"
    assert saved['risk'] == 10

def test_get_unanalyzed_commands(test_db):
    # Insert interaction
    conn = test_db._get_conn()
    conn.execute("INSERT INTO sessions (session_id) VALUES ('sess1')")
    # Interaction 1: Unanalyzed
    conn.execute("""
        INSERT INTO interactions (session_id, request_md5, command) 
        VALUES ('sess1', 'hash1', 'ls -la')
    """)
    # Interaction 2: Analyzed
    conn.execute("""
        INSERT INTO interactions (session_id, request_md5, command) 
        VALUES ('sess1', 'hash2', 'rm -rf /')
    """)
    conn.execute("""
        INSERT INTO command_analysis (command_hash, command_text) VALUES ('hash2', 'rm -rf /')
    """)
    # Interaction 3: Invalid hash
    conn.execute("""
        INSERT INTO interactions (session_id, request_md5, command) 
        VALUES ('sess1', 'unknown', 'weird')
    """)
    conn.commit()
    conn.close()

    unanalyzed = test_db.get_unanalyzed_commands(limit=10)
    
    # Should only return hash1
    assert len(unanalyzed) == 1
    assert unanalyzed[0][0] == 'hash1'
    assert unanalyzed[0][1] == 'ls -la'

# --- LLM Interface Tests ---

@pytest.fixture
def llm():
    return LLMInterface(api_key="fake_key_for_test")

@patch('ssh_honeypot.llm_interface.requests.post')
def test_analyze_command(mock_post, llm):
    # Mock Response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        'candidates': [{
            'content': {
                'parts': [{
                    'text': '```json\n{"type": "Recon", "stage": "Recon", "risk": 2, "explanation": "Simple list"}\n```'
                }]
            }
        }]
    }
    mock_post.return_value = mock_resp

    result = llm.analyze_command("ls")
    
    assert result['type'] == "Recon"
    assert result['risk'] == 2
    assert result['explanation'] == "Simple list"

@patch('ssh_honeypot.llm_interface.requests.post')
def test_analyze_command_failure(mock_post, llm):
    # Mock Failure
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_post.return_value = mock_resp

    result = llm.analyze_command("ls")
    
    assert result['type'] == "Unknown"
    assert "Analysis Failed" in result['explanation']

def test_analyze_batch_success(llm):
    llm._call_api = MagicMock(return_value='''
    [
        {"hash": "h1", "analysis": {"type": "Recon", "stage": "Recon", "risk": 1, "explanation": "test1"}},
        {"hash": "h2", "analysis": {"type": "Exec", "stage": "Exp", "risk": 9, "explanation": "test2"}}
    ]
    ''')
    
    commands = [("h1", "ls"), ("h2", "rm -rf /")]
    results = llm.analyze_batch(commands)
    
    assert len(results) == 2
    assert results["h1"]["type"] == "Recon"
    assert results["h2"]["risk"] == 9

def test_analyze_batch_malformed(llm):
    llm._call_api = MagicMock(return_value='NOT JSON')
    commands = [("h1", "ls")]
    results = llm.analyze_batch(commands)
    assert len(results) == 0 # Returns empty dict on failure
