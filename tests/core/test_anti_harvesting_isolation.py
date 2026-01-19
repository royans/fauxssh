import pytest
import tempfile
import os
import shutil
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.database import HoneyDB


@pytest.fixture
def db():
    # Use temp file for persistence across connections
    fd, path = tempfile.mkstemp()
    os.close(fd)  # Close handle so HoneyDB can use it

    honey_db = HoneyDB(path)
    yield honey_db

    # Cleanup
    try:
        os.unlink(path)
    except:
        pass


@pytest.fixture(autouse=True)
def clean_env():
    # Ensure FAUXSSH_TEST_MODE is filtered out for these tests
    with patch.dict(os.environ, {}, clear=False):
        if "FAUXSSH_TEST_MODE" in os.environ:
            del os.environ["FAUXSSH_TEST_MODE"]
        yield


def test_anti_harvesting_ip_isolation():
    """
    Verifies that anti-harvesting rules for one IP do not affect another IP.
    """

    # Setup DB using temp file
    fd, path = tempfile.mkstemp()
    os.close(fd)
    db = HoneyDB(path)

    try:
        # Patch config to have a known limit (e.g., 5)
        with patch("ssh_honeypot.core.config.config") as mock_config:
            mock_config.get.return_value = 5

            # Scenario:
            # IP A logs in as 'root' with 'pass1' (Success)
            # IP A tries 'root' with 'pass2' (Blocked - Cred Stuffing protection)
            # IP B logs in as 'root' with 'pass3' (Should be Allowed - Isolation)

            ip_a = "192.168.1.10"
            ip_b = "192.168.1.20"
            user = "root"

            # 1. IP A Success
            db.start_session("sess_a_1", ip_a, user, "pass1", "SSH-2.0-Client")

            # Ensure it's recorded
            creds_a = db.get_unique_creds_last_24h(ip_a)
            assert ("root", "pass1") in creds_a

            # 2. IP A Block Check
            # Now validate_anti_harvesting for IP A with NEW password
            passed, reason = db.validate_anti_harvesting(ip_a, user, "pass2")
            assert not passed, "IP A should be blocked for new password on known user"
            assert "Known user, new password denied" in reason

            # 3. IP B Check
            # IP B has NO history. Should be allowed to log in as 'root'
            passed_b, reason_b = db.validate_anti_harvesting(ip_b, user, "pass3")
            assert passed_b, f"IP B should be allowed. Reason: {reason_b}"

            # 4. Verify IP B doesn't see IP A's history
            creds_b = db.get_unique_creds_last_24h(ip_b)
            assert len(creds_b) == 0

            # 5. IP B Success (Recording it)
            db.start_session("sess_b_1", ip_b, user, "pass3", "SSH-2.0-Client")

            # 6. IP B re-check (Same creds allowed)
            passed_b_2, _ = db.validate_anti_harvesting(ip_b, user, "pass3")
            assert passed_b_2, "IP B should be allowed for same credentials"

            # 7. IP B Block Check (New Password)
            passed_b_3, reason_b_3 = db.validate_anti_harvesting(ip_b, user, "pass4")
            assert not passed_b_3, "IP B should be blocked for new password now"
    finally:
        os.unlink(path)
