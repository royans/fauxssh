import pytest
import os
import json
from unittest.mock import MagicMock, patch, mock_open
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler
from io import BytesIO


@pytest.fixture
def mock_server():
    server = MagicMock()
    server.honey_db = MagicMock()
    server.llm_interface = MagicMock()
    return server


def create_handler(server, output_buf, path="/stats_request.html", method="GET"):
    handler = HoneyHTTPHandler.__new__(HoneyHTTPHandler)
    handler.server = server
    handler.request = MagicMock()
    handler.client_address = ("127.0.0.1", 8888)
    handler.wfile = output_buf
    handler.path = path
    handler.command = method
    handler.headers = {"User-Agent": "TestAgent"}
    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.address_string = lambda: "127.0.0.1"
    handler.log_message = MagicMock()
    return handler


def test_stats_request_enabled(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/stats_request.html", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.side_effect = lambda *args, **kwargs: (
            True if args[0] == "http" and args[1] == "showstats" else None
        )

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            with patch(
                "builtins.open", mock_open(read_data="<html>Infographic</html>")
            ):
                handler.do_GET()

                output = output_buf.getvalue()
                assert b"200 OK" in output
                assert b"<html>Infographic</html>" in output
                assert b"Content-Type: text/html" in output


def test_stats_request_disabled(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/stats_request.html", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        # showstats is False
        mock_conf.get.return_value = False

        # Should fallback to normal request handling (LLM or cache)
        mock_server.honey_db.get_cached_response.return_value = "Normal Content"
        handler.do_GET()

        output = output_buf.getvalue()
        assert b"Normal Content" in output
        assert b"<html>Infographic</html>" not in output


def test_stats_data_json_enabled(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/status_data.json", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.side_effect = lambda *args, **kwargs: (
            True if args[0] == "http" and args[1] == "showstats" else None
        )

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            with patch("builtins.open", mock_open(read_data='{"total_ips": 100}')):
                handler.do_GET()

                output = output_buf.getvalue()
                assert b"200 OK" in output
                assert b'{"total_ips": 100}' in output
                assert b"Content-Type: application/json" in output


def test_stats_data_json_not_found(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/status_data.json", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.side_effect = lambda *args, **kwargs: (
            True if args[0] == "http" and args[1] == "showstats" else None
        )

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False  # File doesn't exist
            handler.do_GET()

            output = output_buf.getvalue()
            assert b"404 Not Found" in output
            assert b'{"error": "Data not generated yet"}' in output
