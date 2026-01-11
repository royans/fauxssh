import pytest
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler
from io import BytesIO


@pytest.fixture
def mock_server():
    server = MagicMock()
    server.honey_db = MagicMock()
    server.llm_interface = MagicMock()
    server.config = MagicMock()

    # Setup DB mocks
    server.honey_db.get_cached_response.return_value = None  # Default miss
    server.honey_db.cache_response = MagicMock()
    server.honey_db.start_session = MagicMock()
    server.honey_db.cache_response = MagicMock()
    server.honey_db.start_session = MagicMock()
    server.honey_db.log_interaction = MagicMock()
    server.honey_db.check_llm_rate_limit = MagicMock(return_value=(True, "OK"))
    return server


def create_handler(server, output_buf, path="/index.html", method="GET"):
    handler = HoneyHTTPHandler.__new__(HoneyHTTPHandler)
    handler.server = server
    handler.request = MagicMock()
    handler.client_address = ("127.0.0.1", 8888)
    handler.wfile = output_buf
    handler.path = path
    handler.command = method
    handler.headers = {"User-Agent": "TestAgent"}

    # Attributes required by BaseHTTPRequestHandler.send_response / log_message
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"

    handler.address_string = lambda: "127.0.0.1"

    # Mock log_message to prevent printing to stderr during tests (optional)
    handler.log_message = MagicMock()

    return handler


def test_http_get_cache_miss(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/index.html", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.return_value = "Apache/Fake"

        mock_server.honey_db.get_cached_response.return_value = None
        mock_server.llm_interface.generate_response.return_value = (
            "<html>New Content</html>"
        )

        handler.do_GET()

        # Verify LLM Call
        mock_server.llm_interface.generate_response.assert_called_once()
        args, kwargs = mock_server.llm_interface.generate_response.call_args
        assert "GET" in kwargs["override_prompt"]

        # Verify Cache Set
        mock_server.honey_db.cache_response.assert_called_with(
            "HTTP GET /index.html", "HTTP_ROOT", "<html>New Content</html>"
        )

        # Verify Output
        output = output_buf.getvalue()
        assert b"<html>New Content</html>" in output
        assert b"Server: Apache/Fake" in output
        assert b"200 OK" in output


def test_http_get_cache_hit(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/old.html", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.return_value = "Apache/Fake"

        mock_server.honey_db.get_cached_response.return_value = "CachedContent"

        handler.do_GET()

        # Verify NO LLM Call
        mock_server.llm_interface.generate_response.assert_not_called()

        output = output_buf.getvalue()
        assert b"CachedContent" in output


def test_http_post_login(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/login.php", "POST")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.return_value = "Apache/Fake"

        mock_server.honey_db.get_cached_response.return_value = None
        mock_server.llm_interface.generate_response.return_value = (
            "<form>Bad Creds</form>"
        )

        handler.do_POST()

        # Verify LLM Call includes POST info
        args, kwargs = mock_server.llm_interface.generate_response.call_args
        assert "POST" in kwargs["override_prompt"]
        assert "/login.php" in kwargs["override_prompt"]

        output = output_buf.getvalue()
        assert b"<form>Bad Creds</form>" in output


def test_http_llm_error_fallback(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/error", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.return_value = "Apache/Fake"

        mock_server.honey_db.get_cached_response.return_value = None
        mock_server.llm_interface.generate_response.side_effect = Exception("API Down")

        handler.do_GET()

        output = output_buf.getvalue()
        assert b"500 Internal Server Error" in output
        assert (
            b"200 OK" in output
        )  # We verify that we still return 200 OK but with error body (soft fail)
