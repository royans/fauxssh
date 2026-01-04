
import pytest
from unittest.mock import MagicMock, patch
import paramiko
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.server import HoneypotServer

@pytest.fixture
def mock_db():
    # Patch SSHPOT_TEST_MODE to None so logic actually runs
    with patch.dict(os.environ, {'SSHPOT_TEST_MODE': ''}, clear=False):
        # Also patch db
        with patch('ssh_honeypot.server.db') as mock:
            yield mock

def test_anti_harvesting_allow_new_user_initially(mock_db):
    # Setup: No existing creds for this IP
    mock_db.get_unique_creds_last_24h.return_value = set()
    
    server = HoneypotServer("1.2.3.4")
    
    # Should be deferred to standard check (success if not root)
    result = server.check_auth_password("user1", "pass")
    assert result == paramiko.AUTH_SUCCESSFUL

def test_anti_harvesting_allow_existing_cred(mock_db):
    # Setup: 'user1'/'pass' already logged in
    mock_db.get_unique_creds_last_24h.return_value = {("user1", "pass")}
    
    server = HoneypotServer("1.2.3.4")
    
    # Should allow ('user1', 'pass') again regardless of probability (it's in the set)
    result = server.check_auth_password("user1", "pass")
    assert result == paramiko.AUTH_SUCCESSFUL

def test_anti_harvesting_block_new_pwd_limit_reached(mock_db):
    # Setup: 5 unique users already compromised
    mock_db.get_unique_creds_last_24h.return_value = {("u1", "p"), ("u2", "p"), ("u3", "p"), ("u4", "p"), ("u5", "p")}
    
    server = HoneypotServer("1.2.3.4")
    
    # Existing user ('u1') with NEW password should be blocked IMMEDIATELY due to user mismatch check
    result = server.check_auth_password("u1", "newpass")
    assert result == paramiko.AUTH_FAILED

def test_anti_harvesting_block_new_password_known_user(mock_db):
    """
    Verify that if a user has already authenticated successfully, 
    any attempt to use a DIFFERENT password for that user fails 100%.
    """
    mock_db.get_unique_creds_last_24h.return_value = {("u1", "p1")}
    server = HoneypotServer("1.2.3.4")
    
    # Correct password -> Success (Already tested above)
    assert server.check_auth_password("u1", "p1") == paramiko.AUTH_SUCCESSFUL
    
    # New password -> FAIL
    assert server.check_auth_password("u1", "wrong_pass") == paramiko.AUTH_FAILED
    

def test_anti_harvesting_probability_escalation(mock_db):
    # Setup: 2 distinct users -> 40% rejection probability
    mock_db.get_unique_creds_last_24h.return_value = {("u1", "p"), ("u2", "p")}
    
    server = HoneypotServer("1.2.3.4")
    
    # Run 1000 trials with a NEW username
    rejections = 0
    total = 1000
    for _ in range(total):
        # Must use NEW username to trigger probability check (and not hit known-user block)
        res = server.check_auth_password("u_new", "pass_attempt")
        if res == paramiko.AUTH_FAILED:
            rejections += 1
            
    # Expected: ~40% rejections (400)
    # Allow loose margin for randomness (300-500)
    print(f"Rejections for 2 users (40% target): {rejections}")
    assert 300 <= rejections <= 500
