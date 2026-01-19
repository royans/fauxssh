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

    # Setup Logic Mocks (Allow rate limits)
    server.honey_db.check_llm_rate_limit = MagicMock(return_value=(True, "OK"))
    server.honey_db.get_cached_response.return_value = None

    return server


def create_handler(server, output_buf, path="/index.html", method="GET"):
    handler = HoneyHTTPHandler.__new__(HoneyHTTPHandler)
    handler.server = server
    handler.request = MagicMock()
    handler.client_address = ("192.168.1.100", 55555)
    handler.wfile = output_buf
    handler.path = path
    handler.command = method
    handler.headers = {"User-Agent": "TestBrowser"}

    handler.request_version = "HTTP/1.1"
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.address_string = lambda: "192.168.1.100"
    handler.log_message = MagicMock()

    return handler


def test_vfs_file_serving(mock_server):
    # Setup VFS: /var/www/html/style.css
    mock_node = {"type": "file", "content": "body { color: red; }", "metadata": {}}

    def get_fs_node_side_effect(path):
        if path == "/var/www/html/style.css":
            return mock_node
        return None

    mock_server.honey_db.get_fs_node.side_effect = get_fs_node_side_effect

    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/style.css", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        # Config behavior
        mock_conf.get.side_effect = lambda s, k: (
            "/var/www/html" if k == "web_root" else None
        )

        handler.do_GET()

        output = output_buf.getvalue()

        # Verify Content served
        assert b"body { color: red; }" in output
        # Verify Mime Type
        assert b"Content-Type: text/css" in output
        # Verify Status
        assert b"200 OK" in output

        # Verify LLM NOT called
        mock_server.llm_interface.generate_response.assert_not_called()


def test_vfs_index_resolution(mock_server):
    # Setup VFS: /var/www/html (dir) and /var/www/html/index.php (file)
    dir_node = {"type": "directory"}
    index_node = {"type": "file", "content": "<?php echo 'Hello'; ?>"}

    def get_fs_node_side_effect(path):
        if path == "/var/www/html":
            return dir_node
        if path == "/var/www/html/index.php":
            return index_node
        return None

    mock_server.honey_db.get_fs_node.side_effect = get_fs_node_side_effect

    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.side_effect = lambda s, k: (
            "/var/www/html" if k == "web_root" else None
        )

        handler.do_GET()

        output = output_buf.getvalue()

        # Verify Index served
        assert b"<?php echo 'Hello'; ?>" in output
        # Verify Manual PHP Mime Type fallback logic
        assert b"Content-Type: text/html" in output


def test_vfs_fallback_to_llm(mock_server):
    # Setup VFS: Empty
    mock_server.honey_db.get_fs_node.return_value = None

    # Setup LLM response
    mock_server.llm_interface.generate_response.return_value = "LLM Content"

    output_buf = BytesIO()
    handler = create_handler(mock_server, output_buf, "/unknown.html", "GET")

    with patch("ssh_honeypot.services.http_server.server.config") as mock_conf:
        mock_conf.get.side_effect = lambda s, k: (
            "/var/www/html" if k == "web_root" else None
        )

        handler.do_GET()

        output = output_buf.getvalue()

        # Verify LLM content
        assert b"LLM Content" in output
        # Verify LLM WAS called
        mock_server.llm_interface.generate_response.assert_called_once()
