
import pytest
from unittest.mock import MagicMock, patch
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.core.database import HoneyDB

@pytest.fixture
def honey_db():
    # Mock the database backend
    with patch('ssh_honeypot.core.database.sqlite3') as mock_sql:
        # Create instance
        db = HoneyDB("test.db")
        
        # Patch validate_anti_harvesting to IGNORE test mode for these tests
        # We need to test the logic, so we must ensure os.getenv('SSHPOT_TEST_MODE') returns None
        # But since we are running under SSHPOT_TEST_MODE=1 in shell, we need to mock it.
        pass
        
    db.get_unique_creds_last_24h = MagicMock()
    return db

@pytest.fixture(autouse=True)
def clean_env():
    # Ensure SSHPOT_TEST_MODE is filtered out for these tests
    with patch.dict(os.environ, {}, clear=False):
        if 'SSHPOT_TEST_MODE' in os.environ:
            del os.environ['SSHPOT_TEST_MODE']
        yield

def test_anti_harvesting_allow_new_user_initially(honey_db):
    # Setup: No existing creds for this IP
    honey_db.get_unique_creds_last_24h.return_value = set()
    
    # Should be deferred to standard check (passed=True)
    is_safe, reason = honey_db.validate_anti_harvesting("1.2.3.4", "user1", "pass")
    assert is_safe is True
    assert reason is None

def test_anti_harvesting_allow_existing_cred(honey_db):
    # Setup: 'user1'/'pass' already logged in
    honey_db.get_unique_creds_last_24h.return_value = {("user1", "pass")}
    
    # Should allow ('user1', 'pass') again regardless of probability (it's in the set)
    is_safe, reason = honey_db.validate_anti_harvesting("1.2.3.4", "user1", "pass")
    assert is_safe is True
    assert reason is None

def test_anti_harvesting_block_new_pwd_limit_reached(honey_db):
    # Setup: 5 unique users already compromised
    honey_db.get_unique_creds_last_24h.return_value = {("u1", "p"), ("u2", "p"), ("u3", "p"), ("u4", "p"), ("u5", "p")}
    
    # Mock config to ensure limit is 5
    with patch('ssh_honeypot.core.config.config.get', return_value=5):
        # Existing user ('u1') with NEW password should be blocked IMMEDIATELY due to user mismatch check
        is_safe, reason = honey_db.validate_anti_harvesting("1.2.3.4", "u1", "newpass")
        assert is_safe is False
        assert "Known user, new password denied" in reason

def test_anti_harvesting_block_new_password_known_user(honey_db):
    """
    Verify that if a user has already authenticated successfully, 
    any attempt to use a DIFFERENT password for that user fails 100%.
    """
    honey_db.get_unique_creds_last_24h.return_value = {("u1", "p1")}
    
    # Correct password -> Success
    is_safe, reason = honey_db.validate_anti_harvesting("1.2.3.4", "u1", "p1")
    assert is_safe is True
    
    # New password -> FAIL
    is_safe, reason = honey_db.validate_anti_harvesting("1.2.3.4", "u1", "wrong_pass")
    assert is_safe is False
    assert "Known user, new password denied" in reason
    
def test_anti_harvesting_probability_escalation(honey_db):
    # Setup: 2 distinct users -> 40% rejection probability
    honey_db.get_unique_creds_last_24h.return_value = {("u1", "p"), ("u2", "p")}
    
    # Mock config
    with patch('ssh_honeypot.core.config.config.get', return_value=5):
         with patch('os.getenv', return_value=None): # Ensure no test mode
            # Run 1000 trials with a NEW username
            rejections = 0
            total = 1000
            
            # 2 distinct users compromised
            # prob = 2 / max_auth
            expected_prob = 2.0 / 5.0
            expected_count = int(total * expected_prob)
            
            # Allow loose margin (+/- 10%)
            margin = 100 
            
            for _ in range(total):
                # Must use NEW username to trigger probability check (and not hit known-user block)
                is_safe, reason = honey_db.validate_anti_harvesting("1.2.3.4", "u_new", "pass_attempt")
                if not is_safe:
                    rejections += 1
            
            # Expected: ~400 for max_auth=5
            print(f"Rejections for 2 users (Target Prob: {expected_prob:.2f}): {rejections}")
            assert (expected_count - margin) <= rejections <= (expected_count + margin)
