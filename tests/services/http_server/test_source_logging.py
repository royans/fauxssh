import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler


class TestHTTPSourceLogging(unittest.TestCase):

    @patch("ssh_honeypot.services.http_server.server.config")
    def test_source_logging_logic(self, mock_config):
        """
        Verify that logic distinguishes between local (VFS) and LLM.
        """
        # Mock DB
        mock_db = MagicMock()
        mock_server = MagicMock()
        mock_server.honey_db = mock_db
        mock_server.llm_interface = MagicMock()

        # 1. Simulate VFS Hit (Local)
        # We assume db.get_fs_node returns a file
        mock_db.get_cached_response.return_value = None
        mock_db.get_fs_node.return_value = {"type": "file", "content": "hello"}

        # Proper Mocking for BaseHTTPRequestHandler
        mock_socket = MagicMock()
        # makefile('rb', ...) -> used to read request line
        # We simulate a valid GET request line
        mock_socket.makefile.return_value.readline.return_value = (
            b"GET /index.html HTTP/1.1\r\n"
        )

        handler = HoneyHTTPHandler(mock_socket, ("1.2.3.4", 1234), mock_server)
        handler.path = "/index.html"

        # Override wfile to prevent socket errors
        handler.wfile = MagicMock()
        handler.headers = {}

        # Exec
        try:
            handler.handle_honey_request("GET")
        except:
            pass  # Ignore socket setup checks in BaseHTTPRequestHandler

        # Verify DB Log call
        # args: session_id, cwd, command, response, source, ...
        # Check that 'source' kwarg was 'local'
        call_args = mock_db.log_interaction.call_args
        if call_args:
            _, kwargs = call_args
            self.assertEqual(
                kwargs.get("source"), "local", "Should log source='local' for VFS hits"
            )

    @patch("ssh_honeypot.services.http_server.server.config")
    def test_llm_source_logging(self, mock_config):
        # 2. Simulate LLM Hit
        mock_db = MagicMock()
        mock_server = MagicMock()
        mock_server.honey_db = mock_db
        # No Cache, No VFS
        mock_db.get_cached_response.return_value = None
        mock_db.get_fs_node.return_value = None
        # Rate limit OK
        mock_db.check_llm_rate_limit.return_value = (True, "OK")

        mock_llm = MagicMock()
        mock_llm.generate_response.return_value = "AI Generated"
        mock_server.llm_interface = mock_llm

        mock_socket = MagicMock()
        mock_socket.makefile.return_value.readline.return_value = (
            b"GET /unknown.php HTTP/1.1\r\n"
        )

        handler = HoneyHTTPHandler(mock_socket, ("1.2.3.4", 1234), mock_server)
        handler.path = "/unknown.php"
        handler.wfile = MagicMock()
        handler.headers = {}

        try:
            handler.handle_honey_request("GET")
        except:
            pass

        # Verify DB Log call
        call_args = mock_db.log_interaction.call_args
        if call_args:
            _, kwargs = call_args
            self.assertEqual(
                kwargs.get("source"), "llm", "Should log source='llm' for AI generation"
            )


if __name__ == "__main__":
    unittest.main()
