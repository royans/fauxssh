import pytest
from unittest.mock import MagicMock, patch, mock_open
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler
from io import BytesIO


@pytest.fixture
def mock_server():
    server = MagicMock()
    server.honey_db = MagicMock()
    server.llm_interface = MagicMock()
    server.honey_db.check_llm_rate_limit.return_value = (True, "OK")
    return server


def create_handler(server, output_buf, path="/stats_request.html", method="GET"):
    # Create handler without invoking __init__ which might try to bind sockets
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

    # Mock send_response/send_header to write to wfile buffer for verification
    # But wait, BaseHTTPRequestHandler writes to wfile, so we just need to capture wfile.
    # However, Python's http.server writes headers to wfile too.
    # We need to manually initialize the handler basics if we skip __init__
    handler.close_connection = True
    return handler


def test_stats_v1_no_cache(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/stats_request.html", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        # Enable stats
        mock_conf.get.side_effect = lambda *args, **kwargs: (
            True if args[0] == "http" and args[1] == "showstats" else None
        )

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            with patch("builtins.open", mock_open(read_data="<html>Stats V1</html>")):
                handler.do_GET()

                output = output_buf.getvalue().decode("utf-8", errors="ignore")

                # Check for 200 OK
                assert "200 OK" in output
                # Check content
                assert "<html>Stats V1</html>" in output

                # Check Cache Headers (These should FAIL before the fix)
                assert "Cache-Control: no-cache, no-store, must-revalidate" in output
                assert "Pragma: no-cache" in output
                assert "Expires: 0" in output
                # Check CSP
                assert (
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com"
                    in output
                )


def test_stats_v2_serving_and_no_cache(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/stats_request_v2.html", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        # Enable stats
        mock_conf.get.side_effect = lambda *args, **kwargs: (
            True if args[0] == "http" and args[1] == "showstats" else None
        )

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            with patch("builtins.open", mock_open(read_data="<html>Stats V2</html>")):
                handler.do_GET()

                output = output_buf.getvalue().decode("utf-8", errors="ignore")

                # Check for 200 OK (Might fail if V2 isn't in the whitelist yet)
                assert "200 OK" in output
                # Check content
                assert "<html>Stats V2</html>" in output

                # Check Cache Headers
                assert "Cache-Control: no-cache, no-store, must-revalidate" in output
                assert "Pragma: no-cache" in output
                assert "Expires: 0" in output
                # Check CSP
                assert (
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com"
                    in output
                )
