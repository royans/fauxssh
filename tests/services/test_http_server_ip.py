import unittest
from unittest.mock import MagicMock
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler


class TestHTTPServerIP(unittest.TestCase):
    def test_get_client_ip_direct(self):
        # Mock handler
        handler = MagicMock()
        handler.headers = {}
        handler.client_address = ("1.2.3.4", 12345)

        # Bind method from class
        get_ip = HoneyHTTPHandler.get_client_ip.__get__(handler, HoneyHTTPHandler)

        self.assertEqual(get_ip(), "1.2.3.4")

    def test_get_client_ip_x_forwarded(self):
        # Mock handler
        handler = MagicMock()
        handler.headers = {"X-Forwarded-For": "10.0.0.1, 192.168.1.1"}
        handler.client_address = ("127.0.0.1", 8080)

        # Bind method
        get_ip = HoneyHTTPHandler.get_client_ip.__get__(handler, HoneyHTTPHandler)

        self.assertEqual(get_ip(), "10.0.0.1")

    def test_get_client_ip_x_forwarded_single(self):
        handler = MagicMock()
        handler.headers = {"X-Forwarded-For": "10.0.0.5"}
        handler.client_address = ("127.0.0.1", 8080)

        get_ip = HoneyHTTPHandler.get_client_ip.__get__(handler, HoneyHTTPHandler)

        self.assertEqual(get_ip(), "10.0.0.5")

    def test_get_client_ip_no_headers_attr(self):
        # Use a raw mock that definitely doesn't have headers unless we add it
        # We need to ensure getattr(obj, 'headers') raises or returns default depending on implementation
        # The mock object will return a MagicMock for accessing .headers usually.
        # We need to simulate it NOT existing.
        handler = MagicMock(spec=[])  # Empty spec, no attributes
        handler.client_address = ("1.2.3.4", 12345)

        # Bind method
        get_ip = HoneyHTTPHandler.get_client_ip.__get__(handler, HoneyHTTPHandler)

        # This should NOT raise AttributeError
        self.assertEqual(get_ip(), "1.2.3.4")


if __name__ == "__main__":
    unittest.main()
