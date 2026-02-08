import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from ssh_honeypot.services.imap.server import start_imap_server
from ssh_honeypot.core.config import config


class TestIMAPStartup:
    @pytest.fixture
    def mock_dependencies(self):
        db = MagicMock()
        llm = MagicMock()
        return db, llm

    @pytest.mark.asyncio
    async def test_imap_socket_binding(self, mock_dependencies):
        """Verify IMAP server binds to the configured port and serves forever."""
        db, llm = mock_dependencies
        port = 15144  # Use a non-standard port for testing

        # Mock get_running_loop
        with patch("asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            mock_get_loop.return_value = mock_loop

            # Mock Server Object with AsyncMock
            mock_server = AsyncMock()

            # Mock create_dual_stack_socket
            with patch(
                "ssh_honeypot.services.imap.server.create_dual_stack_socket"
            ) as mock_create_sock:
                mock_sock = MagicMock()
                mock_create_sock.return_value = mock_sock

                # Configure create_server to return the mock server
                mock_loop.create_server = AsyncMock(return_value=mock_server)

                await start_imap_server(db, llm, port, bind_ip="0.0.0.0")

                # Verify create_dual_stack_socket called
                mock_create_sock.assert_called_with("0.0.0.0", port)

                # Verify create_server called with sock
                mock_loop.create_server.assert_called()
                args, kwargs = mock_loop.create_server.call_args
                assert kwargs.get("sock") == mock_sock

            # Verify serve_forever was awaited
            mock_server.serve_forever.assert_awaited()

    def test_config_defaults(self):
        """Verify IMAP defaults are loaded in config."""
        assert config.get("imap", "enabled") is True
        assert config.get("imap", "port") == 15143
        assert config.get("imap", "ssl_port") == 15993
