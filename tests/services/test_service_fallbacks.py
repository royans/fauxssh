import unittest
import os
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler
from ssh_honeypot.core.llm import LLMInterface
from ssh_honeypot.core.config import config


class TestServiceFallbacks(unittest.TestCase):

    # --- HTTP Fallback Test ---
    def test_http_404_fallback(self):
        # Mock Handler using MagicMock for server/db/llm
        handler = MagicMock(spec=HoneyHTTPHandler)
        handler.version_string.return_value = "Apache/2.4.52 (Ubuntu)"
        handler.headers = {"Host": "localhost"}

        # Manually attach the _get_fallback_404 method from the class to the mock
        # Because we mocked the instance, we need to call the unbound method or recreate logic
        # Better: Instantiate the real class with mocked request/server

        # Actually, let's just test the Logic directly if possible, or simple subclass
        # Subclassing to bypass __init__ complexity
        class MockHandler(HoneyHTTPHandler):
            def __init__(self):
                self.headers = {"Host": "localhost"}

            def version_string(self):
                return "Apache/2.4.52 (Ubuntu)"

        h = MockHandler()
        content = h._get_fallback_404()

        self.assertIn("404 Not Found", content)
        self.assertIn("Apache/2.4.52", content)
        self.assertIn("<!DOCTYPE HTML", content)

    def test_http_404_fallback_nginx(self):
        class MockHandlerNginx(HoneyHTTPHandler):
            def __init__(self):
                self.headers = {"Host": "localhost"}

            def version_string(self):
                return "nginx/1.18.0"

        h = MockHandlerNginx()
        content = h._get_fallback_404()
        self.assertIn("nginx/1.18.0", content)
        self.assertIn("<center><h1>404 Not Found</h1></center>", content)

    # --- SSH/LLM Fallback Test ---
    @patch("ssh_honeypot.core.llm.config")
    def test_llm_fallback_messages(self, mock_config):
        # Ensure config returns empty for api_key
        mock_config.get.side_effect = lambda section, key, *args: (
            "" if section == "llm" and key == "api_key" else None
        )

        # Initialize LLM without API Key (and mocked config)
        llm = LLMInterface(api_key="")

        # 1. Generic Command
        resp = llm.generate_response("foobar", "/")
        self.assertEqual(resp, "bash: foobar: command not found")

        # 2. Network Command (wget)
        resp = llm.generate_response("wget http://evil.com", "/")
        self.assertEqual(resp, "wget: unable to resolve host address")

        # 3. SSH Command
        # Force Test Mode to avoid potential sleep/delays
        with patch.dict(os.environ, {"SSHPOT_TEST_MODE": "1"}):
            resp = llm.generate_response("ssh user@host", "/")
            self.assertEqual(
                resp, "ssh: connect to host example.com port 22: Connection timed out"
            )


if __name__ == "__main__":
    unittest.main()
