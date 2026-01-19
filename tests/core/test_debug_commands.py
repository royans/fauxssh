import pytest
from unittest.mock import MagicMock, patch
import sys
import os

# Ensure path is correct
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB


class TestDebugCommands:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        mock_db = MagicMock()
        # Mock inspect_dir and inspect_path to return strings
        mock_db.inspect_dir.return_value = "DIR REPORT"
        mock_db.inspect_path.return_value = "PATH REPORT"
        return CommandHandler(mock_llm, mock_db)

    @patch("ssh_honeypot.core.command_handler.get_ignored_ips")
    def test_debug_vfs_dir(self, mock_get_ips, handler):
        """Test debug_vfs with no args (cwd dir inspection)."""
        # whitelist IP
        mock_get_ips.return_value = ["1.2.3.4"]

        cmd = "debug_vfs"
        context = {"cwd": "/root", "user": "root", "client_ip": "1.2.3.4"}

        resp, updates, meta = handler.process_command(cmd, context)

        assert "DIR REPORT" in resp
        handler.db.inspect_dir.assert_called_with("1.2.3.4", "root", "/root")

    @patch("ssh_honeypot.core.command_handler.get_ignored_ips")
    def test_debug_vfs_path(self, mock_get_ips, handler):
        """Test debug_vfs with path argument."""
        # whitelist IP
        mock_get_ips.return_value = ["1.2.3.4"]

        cmd = "debug_vfs /etc"
        context = {"cwd": "/root", "user": "root", "client_ip": "1.2.3.4"}

        resp, updates, meta = handler.process_command(cmd, context)

        assert "PATH REPORT" in resp
        # It calls inspect_path for args
        handler.db.inspect_path.assert_called_with("1.2.3.4", "root", "/etc")

    @patch("ssh_honeypot.core.command_handler.get_ignored_ips")
    def test_debug_vfs_robustness(self, mock_get_ips, handler):
        """Test debug_vfs handling if DB returns a list (Regression Fix)."""
        # whitelist IP
        mock_get_ips.return_value = ["1.2.3.4"]

        # Simulate DB returning a list instead of string (The bug reproduction)
        handler.db.inspect_dir.return_value = ["Line 1", "Line 2"]

        cmd = "debug_vfs"
        context = {"cwd": "/root", "user": "root", "client_ip": "1.2.3.4"}

        # This calls process_command which will trigger the robust concatenation logic
        try:
            resp, updates, meta = handler.process_command(cmd, context)
            # The resp should be joined string
            assert "Line 1\nLine 2" in resp
        except TypeError:
            pytest.fail("process_command raised TypeError on list return from DB")

    @patch("ssh_honeypot.core.command_handler.get_ignored_ips")
    def test_debug_vfs_ls(self, mock_get_ips, handler):
        """Test debug_vfs_ls command."""
        # whitelist IP
        mock_get_ips.return_value = ["1.2.3.4"]

        cmd = "debug_vfs_ls /tmp"
        context = {"cwd": "/root", "user": "root", "client_ip": "1.2.3.4"}

        handler.process_command(cmd, context)
        # debug_vfs_ls calls inspect_dir
        handler.db.inspect_dir.assert_called_with("1.2.3.4", "root", "/tmp")

    @patch("ssh_honeypot.core.command_handler.get_ignored_ips")
    def test_debug_unauthorized(self, mock_get_ips, handler):
        """Test that debug commands are hidden from unauthorized IPs."""
        # Authorized IPs do NOT include 1.2.3.4
        mock_get_ips.return_value = ["9.9.9.9"]

        cmd = "debug_vfs"
        context = {"cwd": "/root", "user": "root", "client_ip": "1.2.3.4"}

        # Should fall through to LLM/Not Found.
        # process_command for unknown commands typically returns LLM response or "command not found"
        # Since we mocked LLM via handler fixture (CommandHandler constructor), LLM fallback happens.
        # We can detect this by checking if LLM was called OR if output is different.

        # If fallback:
        # handler.llm.generate_response.return_value = "LLM says hello"
        resp, _, _ = handler.process_command(cmd, context)

        # The specific debug logic should NOT have been called.
        handler.db.inspect_dir.assert_not_called()

        # Now explicitly check for the "command not found" message
        assert "command not found" in resp


if __name__ == "__main__":
    pytest.main([__file__])
