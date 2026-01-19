import unittest
from unittest.mock import MagicMock, patch
import socket
from ssh_honeypot.core.payload_manager import PayloadManager


class TestSSRFProtection(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.pm = PayloadManager(self.mock_db)

    @patch("socket.getaddrinfo")
    def test_block_private_ip(self, mock_getaddrinfo):
        # Simulate resolving specific host to private IP
        # getaddrinfo returns list of tuples: (family, type, proto, canonname, sockaddr)
        # sockaddr is (ip, port) for IPv4
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.5", 80))
        ]

        url = "http://internal-host/malware.sh"
        is_safe, reason = self.pm._is_safe_url(url)
        self.assertFalse(is_safe)
        self.assertIn("Private IP", reason)

    @patch("socket.getaddrinfo")
    def test_block_localhost(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
        ]

        url = "http://localhost/setup.py"
        is_safe, reason = self.pm._is_safe_url(url)
        self.assertFalse(is_safe)
        self.assertIn("Loopback IP", reason)

    @patch("socket.getaddrinfo")
    def test_block_link_local(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))
        ]

        url = "http://169.254.169.254/latest/meta-data/"
        is_safe, reason = self.pm._is_safe_url(url)
        self.assertFalse(is_safe)
        self.assertIn("Link-Local IP", reason)

    def test_block_basic_auth(self):
        # No DNS needed for this check
        url = "http://admin:password@example.com/secret"
        is_safe, reason = self.pm._is_safe_url(url)
        self.assertFalse(is_safe)
        self.assertIn("Basic Auth", reason)

    @patch("socket.getaddrinfo")
    def test_allow_safe_public_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))
        ]

        url = "http://google.com/file"
        is_safe, reason = self.pm._is_safe_url(url)
        self.assertTrue(is_safe)
        self.assertEqual(reason, "Safe")

    @patch("socket.getaddrinfo")
    def test_block_dns_rebinding_attempt_mixed(self, mock_getaddrinfo):
        # If DNS returns multiple IPs and ONE is private, we should block.
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80)),
        ]

        url = "http://sketchy-host.com/"
        is_safe, reason = self.pm._is_safe_url(url)
        self.assertFalse(is_safe)
        self.assertIn("Private IP", reason)


if __name__ == "__main__":
    unittest.main()
