import unittest
from unittest.mock import MagicMock, patch
import threading
import http.client
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler, MANAGEMENT_PATHS
from ssh_honeypot.core.config import config


class TestStatsExclusion(unittest.TestCase):
    @patch("ssh_honeypot.services.http_server.server.log")
    def setUp(self, mock_log):
        self.server_mock = MagicMock()
        self.server_mock.honey_db = MagicMock()
        self.server_mock.analytics_engine = MagicMock()

        # Bypass BaseHTTPRequestHandler.__init__ to avoid socket interactions
        with patch.object(
            HoneyHTTPHandler,
            "__init__",
            lambda self, request, client_address, server: None,
        ):
            self.handler = HoneyHTTPHandler(
                MagicMock(), ("127.0.0.1", 8888), self.server_mock
            )

        # Manually set attributes expected by methods
        self.handler.server = self.server_mock
        self.handler.client_address = ("127.0.0.1", 8888)
        self.handler.wfile = MagicMock()
        self.handler.rfile = MagicMock()
        self.handler.path = "/"

    @patch("ssh_honeypot.services.http_server.server.log")
    def test_log_message_exclusion(self, mock_log):
        # Case 1: /api/v2/path -> Should NOT log
        self.handler.path = "/api/v2/totals"
        self.handler.log_message("GET %s", "/api/v2/totals")
        mock_log.info.assert_not_called()

        # Case 2: /favicon.ico -> Should NOT log (in MANAGEMENT_PATHS)
        self.handler.path = "/favicon.ico"
        self.handler.log_message("GET %s", "/favicon.ico")
        mock_log.info.assert_not_called()

        # Case 3: /random -> Should log
        self.handler.path = "/random"
        self.handler.client_address = ("127.0.0.1", 12345)
        self.handler.log_message("GET %s", "/random")
        mock_log.info.assert_called()

    @patch("ssh_honeypot.services.http_server.server.clogger")
    @patch("ssh_honeypot.services.http_server.server.dos_protector")
    @patch("ssh_honeypot.services.http_server.server.universal_cache")
    def test_handle_honey_request_exclusion(self, mock_cache, mock_dos, mock_clogger):
        # Configure handler for processing
        self.handler.path = "/favicon.ico"
        self.handler.requestline = "GET /favicon.ico HTTP/1.1"
        self.handler.request_version = "HTTP/1.1"
        self.handler.client_address = ("127.0.0.1", 12345)
        self.handler.headers = {"User-Agent": "TestAgent"}

        # Mock config to allow stats serving
        with patch.object(config, "get", return_value=True):
            self.handler.handle_honey_request("GET")

        # Assertion: clogger.log_event should NOT be called for favicon
        mock_clogger.log_event.assert_not_called()

        # Verify it sent a 404
        # We can check calls to send_response
        # But since we mocked everything, just ensuring no log_event is key.

    @patch("ssh_honeypot.services.http_server.server.clogger")
    def test_api_v2_exclusion(self, mock_clogger):
        self.handler.path = "/api/v2/totals?hours=24"
        self.handler.requestline = "GET /api/v2/totals?hours=24 HTTP/1.1"
        self.handler.request_version = "HTTP/1.1"
        self.handler.client_address = ("127.0.0.1", 12345)

        # Mock analytics engine response
        self.server_mock.analytics_engine.get_dashboard_totals.return_value = {
            "sessions": 0
        }

        # Mock rate limit check
        self.server_mock.honey_db.check_api_rate_limit.return_value = (True, "OK")

        # Handle request
        with patch.object(config, "get", return_value=True):
            self.handler.handle_honey_request("GET")

        # Should return early and NOT log interaction
        mock_clogger.log_event.assert_not_called()
