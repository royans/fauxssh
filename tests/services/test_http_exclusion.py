import pytest
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler, MANAGEMENT_PATHS
from io import BytesIO


@pytest.fixture
def mock_server():
    server = MagicMock()
    server.honey_db = MagicMock()
    server.llm_interface = MagicMock()
    return server


def create_handler(server, path="/status_request.html"):
    handler = HoneyHTTPHandler.__new__(HoneyHTTPHandler)
    handler.server = server
    handler.path = path
    handler.client_address = ("127.0.0.1", 8888)
    handler.headers = {"User-Agent": "TestAgent"}
    return handler


def test_management_path_silenced_in_log_message(mock_server):
    handler = create_handler(mock_server, "/status_request.html")

    with patch("ssh_honeypot.services.http_server.server.log") as mock_log:
        handler.log_message("Request %s", "GET")
        # Should NOT call log.info
        mock_log.info.assert_not_called()


def test_normal_path_logged_in_log_message(mock_server):
    handler = create_handler(mock_server, "/index.html")

    with patch("ssh_honeypot.services.http_server.server.log") as mock_log:
        handler.log_message("Request %s", "GET")
        # Should call log.info
        mock_log.info.assert_called()


def test_management_path_bypasses_clogger(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, "/status_request.html")
    handler.wfile = output_buf
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()

    with (
        patch("ssh_honeypot.services.http_server.server.config") as mock_conf,
        patch("ssh_honeypot.services.http_server.server.clogger") as mock_clogger,
        patch("os.path.exists") as mock_exists,
        patch(
            "builtins.open", MagicMock(side_effect=[MagicMock(read=lambda: "stats")])
        ),
    ):

        mock_conf.get.return_value = True  # showstats
        mock_exists.return_value = True

        handler.handle_honey_request("GET")

        # Verify it served stats
        handler.send_response.assert_called_with(200)

        # Verify NO interaction logged
        mock_clogger.log_event.assert_not_called()


def test_normal_path_logs_interaction(mock_server):
    output_buf = BytesIO()
    handler = create_handler(mock_server, "/malicious.php")
    handler.wfile = output_buf
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.get_client_ip = MagicMock(return_value="1.2.3.4")

    with (
        patch("ssh_honeypot.services.http_server.server.config") as mock_conf,
        patch("ssh_honeypot.services.http_server.server.clogger") as mock_clogger,
        patch("ssh_honeypot.services.http_server.server.dos_protector") as mock_dos,
    ):

        mock_conf.get.side_effect = lambda *args, **kwargs: (
            "/var/www/html"
            if len(args) > 1 and args[1] == "web_root"
            else (
                {}
                if len(args) > 1 and args[1] == "headers"
                else True if len(args) > 1 and args[1] == "showstats" else None
            )
        )
        mock_dos.is_allowed.return_value = True
        mock_server.honey_db.get_fs_node.return_value = None  # No VFS
        mock_server.honey_db.get_cached_response.return_value = "Normal"

        handler.handle_honey_request("GET")

        # Verify interaction WAS logged
        mock_clogger.log_event.assert_called()
