import unittest
from unittest.mock import MagicMock, patch
import os
import io
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler


class MockRequest:
    def __init__(self, path, headers=None):
        self.path = path
        self.headers = headers or {}

    def makefile(self, *args, **kwargs):
        return io.BytesIO(b"")

    def sendall(self, data):
        pass


class TestHTTPMgmtRouting(unittest.TestCase):
    @patch("ssh_honeypot.services.http_server.server.log")
    @patch("ssh_honeypot.services.http_server.server.config")
    @patch("ssh_honeypot.services.http_server.server.os.path.exists")
    @patch("ssh_honeypot.services.http_server.server.open", create=True)
    def test_stats_with_queries(self, mock_open, mock_exists, mock_config, mock_log):
        # 1. Setup mocks
        mock_config.get.return_value = True  # showstats = True
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.read.return_value = (
            "<html>Stats Page</html>"
        )

        # 2. Mock handler
        mock_server = MagicMock()
        mock_server.honey_db = MagicMock()
        mock_server.llm_interface = MagicMock()

        # Path with query
        request = MockRequest("/stats_request.html?view=payloads&md5=abc")

        # We need to partially mock the handler to avoid starting a real server
        with (
            patch.object(HoneyHTTPHandler, "finish"),
            patch.object(HoneyHTTPHandler, "setup"),
            patch.object(HoneyHTTPHandler, "handle"),
        ):

            handler = HoneyHTTPHandler(request, ("127.0.0.1", 12345), mock_server)
            handler.wfile = MagicMock()
            handler.path = request.path

            # Mock BaseHTTPRequestHandler methods to avoid side effects
            handler.send_response = MagicMock()
            handler.send_header = MagicMock()
            handler.end_headers = MagicMock()

            # Mock rate limit return to avoid ValueError
            mock_server.honey_db.check_llm_rate_limit.return_value = (True, "")

            # 3. Execute
            handler.handle_honey_request("GET")

            # 4. Verify: Should have called send_response(200)
            handler.send_response.assert_called_with(200)

            # Verify LLM was NOT called
            self.assertFalse(mock_server.llm_interface.generate_response.called)

            # Verify it served the asset
            mock_open.assert_called_with(unittest.mock.ANY, "r")
            self.assertTrue(handler.wfile.write.called)


if __name__ == "__main__":
    unittest.main()
