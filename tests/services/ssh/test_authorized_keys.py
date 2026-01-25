import unittest
from unittest.mock import MagicMock, patch
import paramiko
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ssh_honeypot.services.ssh.server import HoneypotServer


class TestAuthorizedKeys(unittest.TestCase):
    @patch("ssh_honeypot.services.ssh.server.clogger")
    @patch("ssh_honeypot.services.ssh.server.db")
    def test_authorized_keys_success(self, mock_db, mock_clogger):
        # Setup Server (mocking socket/transport)
        server = HoneypotServer("1.2.3.4")
        # server.client_ip = '1.2.3.4'  # Already set by init
        server.transport_ref = MagicMock()
        server.transport_ref.remote_version = "SSH-2.0-TestClient"
        # Fix for JSON serialization error in clogger: ensure fingerprint attributes return strings, not mocks
        server.transport_ref.remote_cipher = "aes128-ctr"
        server.transport_ref.remote_mac = "hmac-sha2-256"
        server.transport_ref.remote_compression = "none"
        server.transport_ref.kex_alg = "diffie-hellman-group14-sha1"
        server.transport_ref._latest_kex_init = None

        # Define Test Key
        # We need a valid paramiko PKey. RSA is easiest to mock or create.
        # But server uses key.get_name() and key.get_base64()
        mock_key = MagicMock()
        mock_key.get_name.return_value = "ssh-rsa"
        mock_key.get_base64.return_value = "AAAA_TEST_KEY_BASE64"

        username = "testuser"
        auth_path = f"/home/{username}/.ssh/authorized_keys"

        # Test Case 1: Key exists in DB
        # Mock DB returning the authorized_keys file
        mock_db.get_user_node.side_effect = lambda ip, u, path: (
            {
                "type": "file",
                "content": "ssh-rsa AAAA_TEST_KEY_BASE64 comment\nssh-ed25519 OTHERKEY comment",
            }
            if path == auth_path
            else None
        )

        # Execute
        result = server.check_auth_publickey(username, mock_key)

        # Verify
        self.assertEqual(result, paramiko.AUTH_SUCCESSFUL)

        # Regression Requirement: Ensure server.username is set!
        self.assertEqual(server.username, username)

        # Check that proper logging happened with success=True
        mock_clogger.log_event.assert_called()
        args, kwargs = mock_clogger.log_event.call_args
        event_type = args[0]
        data = args[1]
        self.assertEqual(event_type, "auth")
        self.assertEqual(data["username"], username)
        self.assertEqual(data["method"], "publickey")
        self.assertTrue(data["success"])

    @patch("ssh_honeypot.services.ssh.server.clogger")
    @patch("ssh_honeypot.services.ssh.server.db")
    def test_authorized_keys_failure(self, mock_db, mock_clogger):
        server = HoneypotServer("1.2.3.4")
        server.transport_ref = MagicMock()
        server.transport_ref.remote_version = "SSH-2.0-TestClient"
        # Fix for JSON serialization error
        server.transport_ref.remote_cipher = "aes128-ctr"
        server.transport_ref.remote_mac = "hmac-sha2-256"
        server.transport_ref.remote_compression = "none"
        server.transport_ref.kex_alg = "diffie-hellman-group14-sha1"
        server.transport_ref._latest_kex_init = None

        mock_key = MagicMock()
        mock_key.get_name.return_value = "ssh-rsa"
        mock_key.get_base64.return_value = "AAAA_WRONG_KEY"

        username = "testuser"
        auth_path = f"/home/{username}/.ssh/authorized_keys"

        # Test Case 2: File exists but key missing
        mock_db.get_user_node.return_value = {
            "type": "file",
            "content": "ssh-rsa AAAA_TEST_KEY_BASE64 comment",
        }

        result = server.check_auth_publickey(username, mock_key)
        self.assertEqual(result, paramiko.AUTH_FAILED)
        mock_clogger.log_event.assert_called()
        args, kwargs = mock_clogger.log_event.call_args
        data = args[1]
        self.assertFalse(data["success"])

    @patch("ssh_honeypot.services.ssh.server.db")
    def test_authorized_keys_no_file(self, mock_db):
        server = HoneypotServer("1.2.3.4")
        mock_key = MagicMock()
        mock_key.get_name.return_value = "ssh-rsa"
        mock_key.get_base64.return_value = "AAAA_TEST"

        # Test Case 3: No file
        mock_db.get_user_node.return_value = None

        result = server.check_auth_publickey("testuser", mock_key)
        self.assertEqual(result, paramiko.AUTH_FAILED)


if __name__ == "__main__":
    unittest.main()
