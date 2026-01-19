import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler


class TestHTTPRateLimiting(unittest.TestCase):
    @patch("ssh_honeypot.core.database.sqlite3")
    def test_db_rate_limit_checks(self, mock_sqlite):
        """Verify DB logic for RPM/RPD counting."""
        mock_conn = MagicMock()
        mock_sqlite.connect.return_value = mock_conn
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        db = HoneyDB()

        # Scenario 1: Under Limit
        mock_cursor.fetchone.side_effect = [(3,), (5,), (10,)]  # RPM=3, RPH=5, RPD=10
        allowed, reason = db.check_llm_rate_limit(
            "1.2.3.4", rpm_limit=4, rph_limit=60, rpd_limit=20
        )
        self.assertTrue(allowed)

        # Scenario 2: Over RPM
        mock_cursor.fetchone.side_effect = [(5,), (10,)]  # RPM=5!
        allowed, reason = db.check_llm_rate_limit(
            "1.2.3.4", rpm_limit=4, rph_limit=60, rpd_limit=20
        )
        self.assertFalse(allowed)
        self.assertIn("RPM Limit", reason)

    @patch("ssh_honeypot.services.http_server.server.config")
    def test_handler_enforces_limit(self, mock_config):
        """Verify Handler returns 429 when DB says no."""
        # Setup Mocks
        mock_server = MagicMock()
        mock_db = MagicMock()
        mock_server.honey_db = mock_db
        mock_server.llm_interface = MagicMock()

        # Config mocks
        mock_config.get.side_effect = lambda sec, key: 4 if key == "llm_rpm" else 20

        # DB says NO
        mock_db.check_llm_rate_limit.return_value = (False, "RPM Limit Exceeded")
        mock_db.get_cached_response.return_value = None  # Cache miss forcing LLM check

        # Setup Handler
        mock_request = MagicMock()
        # Mock valid HTTP request bytes for parse_request
        mock_request.makefile.return_value.readline.return_value = (
            b"GET /heavy.html HTTP/1.1\r\n"
        )

        with patch("ssh_honeypot.services.http_server.server.log"):
            handler = HoneyHTTPHandler(mock_request, ("1.2.3.4", 1234), mock_server)

            # Setup output buffer mock to capture response code
            handler.wfile = MagicMock()
            handler.send_response = MagicMock()

            # Trigger
            handler.handle_honey_request("GET")

            # Verify
            # Should call check_llm_rate_limit
            mock_db.check_llm_rate_limit.assert_called()
            # Should send 429
            handler.send_response.assert_called_with(429)
            # Should NOT call LLM
            mock_server.llm_interface.generate_response.assert_not_called()


if __name__ == "__main__":
    unittest.main()
