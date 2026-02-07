import pytest
import json
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler


def test_api_v2_anonymity_enforced():
    """Verify that anon=True is passed to engine regardless of query param."""
    server = MagicMock()
    server.honey_db.check_api_rate_limit.return_value = (True, "OK")
    server.analytics_engine.get_recent_sessions.return_value = []

    with (
        patch("ssh_honeypot.services.http_server.server.log") as mock_log,
        patch("ssh_honeypot.services.http_server.server.config") as mock_config,
        patch("ssh_honeypot.services.http_server.server.universal_cache"),
    ):

        # Robust config.get mock
        def config_get(*args, **kwargs):
            if "showstats" in args:
                return True
            if "internal_ips" in args:
                return []
            return True

        mock_config.get.side_effect = config_get

        h = HoneyHTTPHandler.__new__(HoneyHTTPHandler)
        h.server = server
        # Path with query param that we want to override
        h.path = "/api/v2/sessions?anon=false"
        h.headers = MagicMock()
        h.headers.get.return_value = None
        h.wfile = MagicMock()
        h.rfile = MagicMock()
        h.send_response = MagicMock()
        h.send_header = MagicMock()
        h.end_headers = MagicMock()
        h.get_client_ip = MagicMock(return_value="1.1.1.1")

        h.handle_honey_request("GET")

        if not server.analytics_engine.get_recent_sessions.called:
            print("\nDIAGNOSTICS: engine.get_recent_sessions NOT CALLED")
            print(f"Log errors: {mock_log.error.call_args_list}")
            assert False, "Engine method not called!"

        args, kwargs = server.analytics_engine.get_recent_sessions.call_args
        assert kwargs["anon"] is True


def test_api_v2_multi_protocol_params():
    """Verify that multiple protocol/proto params are collected into a list."""
    server = MagicMock()
    server.honey_db.check_api_rate_limit.return_value = (True, "OK")
    server.analytics_engine.get_recent_sessions.return_value = []

    with (
        patch("ssh_honeypot.services.http_server.server.log") as mock_log,
        patch("ssh_honeypot.services.http_server.server.config") as mock_config,
        patch("ssh_honeypot.services.http_server.server.universal_cache"),
    ):

        def config_get(*args, **kwargs):
            if "showstats" in args:
                return True
            if "internal_ips" in args:
                return []
            return True

        mock_config.get.side_effect = config_get

        h = HoneyHTTPHandler.__new__(HoneyHTTPHandler)
        h.server = server
        h.path = "/api/v2/sessions?proto=ssh&proto=telnet"
        h.headers = MagicMock()
        h.headers.get.return_value = None
        h.wfile = MagicMock()
        h.rfile = MagicMock()
        h.send_response = MagicMock()
        h.send_header = MagicMock()
        h.end_headers = MagicMock()
        h.get_client_ip = MagicMock(return_value="127.0.0.1")

        h.handle_honey_request("GET")

        if not server.analytics_engine.get_recent_sessions.called:
            print("\nDIAGNOSTICS: engine.get_recent_sessions NOT CALLED")
            print(f"Log errors: {mock_log.error.call_args_list}")
            assert False, "Engine method not called!"

        args, kwargs = server.analytics_engine.get_recent_sessions.call_args
        assert isinstance(kwargs["protocol_filter"], list)
        assert "ssh" in kwargs["protocol_filter"]
        assert "telnet" in kwargs["protocol_filter"]
