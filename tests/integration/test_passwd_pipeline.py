import pytest
from unittest.mock import MagicMock
from ssh_honeypot.core.command_handler import CommandHandler


class TestPasswdPipelineIntegration:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        mock_db = MagicMock()
        # Mock DB get_fs_node to return None for passwd to avoid "execution simulation" logic
        mock_db.get_fs_node.return_value = None
        return CommandHandler(mock_llm, mock_db)

    def test_complex_passwd_pipeline(self, handler):
        # Case: (echo 'test'; echo 'pass'; echo 'pass') | passwd
        # This tests:
        # 1. Subshell parens stripping
        # 2. Semicolon chain processing
        # 3. Pipe processing (stdin propagation)
        # 4. Passwd handler integration

        context = {
            "user": "root",
            "cwd": "/",
            "client_ip": "1.2.3.4",
            "env": {},
            "history": [],
        }

        cmd = "(echo 'test'; echo 'i7dQx5Xdom?mW81g'; echo 'i7dQx5Xdom?mW81g') | passwd"

        output, updates, meta = handler.process_command(cmd, context)

        # Verify output contains passwd success messages
        assert "Changing password for root" in output
        assert "passwd: password updated successfully" in output
        # Verify it reflects the subshell input (simulated)
        assert "Enter new UNIX password:" in output

        # Verify it didn't just return "echo" output (which would happen if pipe failed)
        assert (
            "i7dQx5Xdom?mW81g" not in output
        )  # Passwd consumes stdin and doesn't echo it back normally in success message

    def test_nested_subshell_pipeline(self, handler):
        # More complex case: (echo a; (echo b; echo c)) | grep b
        context = {
            "user": "root",
            "cwd": "/",
            "client_ip": "1.2.3.4",
            "env": {},
            "history": [],
        }
        cmd = "(echo a; (echo b; echo c)) | grep b"
        output, updates, meta = handler.process_command(cmd, context)

        # 'a\nb\nc\n' | grep b -> 'b\n'
        assert output.strip() == "b"
