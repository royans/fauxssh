import unittest
import threading
import time
import socket
import urllib.request
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.http_server.server import (
    HoneyHTTPHandler,
    ThreadingHTTPServer,
)


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("localhost", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestHeadersIntegration(unittest.TestCase):
    def setUp(self):
        self.port = get_free_port()
        # Configure Mocks
        self.db_mock = MagicMock()
        self.db_mock.get_cached_response.return_value = None  # Force Cache Miss
        self.db_mock.check_llm_rate_limit.return_value = (True, "OK")  # Allow

        self.llm_mock = MagicMock()
        self.llm_mock.generate_response.return_value = "<html>Integration</html>"

        # We need to construct the server manually to inject mocks
        self.server = ThreadingHTTPServer(("localhost", self.port), HoneyHTTPHandler)
        self.server.honey_db = self.db_mock
        self.server.llm_interface = self.llm_mock

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        # Give server a moment to start
        time.sleep(0.1)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=1)

    @patch("ssh_honeypot.services.http_server.server.config")
    @patch("ssh_honeypot.services.http_server.server.dos_protector")
    @patch("ssh_honeypot.services.http_server.server.EventLogger")
    def test_custom_headers_integration(self, mock_logger, mock_dos, mock_config):
        # Configure Mocks
        def config_side_effect(section, key):
            if section == "http" and key == "headers":
                return {"X-Integ-Test": "Works"}
            if section == "http" and key == "server_header":
                return "IntegrationServer/1.0"
            if section == "http" and key == "llm_rpm":
                return 100
            if section == "http" and key == "llm_rpd":
                return 1000
            return None

        mock_config.get.side_effect = config_side_effect
        mock_dos.is_allowed.return_value = True

        # Make Request
        url = f"http://localhost:{self.port}/"
        try:
            with urllib.request.urlopen(url) as response:
                headers = response.info()
                self.assertEqual(headers.get("X-Integ-Test"), "Works")
                self.assertEqual(headers.get("Server"), "IntegrationServer/1.0")
                self.assertEqual(
                    response.read().decode("utf-8"), "<html>Integration</html>"
                )
        except Exception as e:
            self.fail(f"Request failed: {e}")


if __name__ == "__main__":
    unittest.main()
