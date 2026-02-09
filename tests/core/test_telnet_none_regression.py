import sys
import os
import pytest
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ssh_honeypot.core.command_handler import CommandHandler


class TestTelnetNoneRegression:

    @pytest.fixture
    def handler(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        # Default return value for LLM to avoid crashing on MagicMock in string ops
        self.mock_llm.generate_response.return_value = '{"output": ""}'
        return CommandHandler(self.mock_llm, self.mock_db)

    def test_ls_fallback_handled(self, handler):
        """
        Verify that LSCommand returns a valid tuple even on unmanaged paths,
        preventing TypeError in CommandHandler.
        """
        self.mock_db.is_managed_directory.return_value = False
        self.mock_db.get_user_node.return_value = None
        self.mock_db.get_fs_node.return_value = None

        # This used to return None and cause TypeError in process_command
        res = handler.process_command(
            "ls /tmp/missing", {"cwd": "/", "client_ip": "1.2.3.4"}
        )

        assert isinstance(res, tuple)
        assert len(res) == 3
        # Should have empty output or generic fallback
        assert isinstance(res[0], str)
        assert isinstance(res[1], dict)
        assert isinstance(res[2], dict)

    def test_chaining_with_none_metadata_handled(self, handler):
        """
        Verify that command chaining doesn't crash if a sub-command returns None metadata.
        """
        # Patch process_command to return None for metadata in one of the steps
        # This simulates a bug in a handler or a weird edge case
        original_process = handler.process_command

        def mock_process(cmd, context):
            if cmd == "crash_me":
                return "crashed", {}, None
            return original_process(cmd, context)

        with patch.object(handler, "process_command", side_effect=mock_process):
            # The chaining logic at line 1032 and 1086 used to call m.get("cached")
            # If m is None, it would raise AttributeError
            res = handler.process_command(
                "echo hello ; crash_me", {"cwd": "/", "client_ip": "1.2.3.4", "env": {}}
            )

            assert "crashed" in res[0]
            assert res[2]["source"].startswith("chain")

    def test_assignment_with_none_updates_handled(self, handler):
        """
        Verify that VAR=$(cmd) doesn't crash if cmd returns None updates.
        """
        original_process = handler.process_command

        def mock_process(cmd, context):
            if cmd == "ls":
                return "output", None, {"source": "test"}
            return original_process(cmd, context)

        with patch.object(handler, "process_command", side_effect=mock_process):
            # Assignment logic at line 971 used to call updates.get("file_modifications")
            res = handler.process_command(
                "VAR=$(ls)", {"cwd": "/", "client_ip": "1.2.3.4", "env": {}}
            )

            assert res[0] == ""
            assert res[1]["env"]["VAR"] == "output"
            assert "file_modifications" in res[1]

    def test_handler_returning_invalid_format_handled(self, handler):
        """
        Verify that if a handler returns something completely unexpected,
        CommandHandler returns a safe default.
        """
        # Mock a handler dispatch
        handler.handle_echo = MagicMock(return_value=None)

        # process_command line 1655 onwards handles invalid formats
        res = handler.process_command("echo test", {"cwd": "/", "client_ip": "1.2.3.4"})

        assert res[0] == ""
        # Check that it's a dict and contains some keys (it might have new_cwd=None)
        assert isinstance(res[1], dict)
        assert res[2]["source"] == "llm"  # it falls through to LLM

    def test_none_context_handled(self, handler):
        """Verify process_command with context=None doesn't crash"""
        res = handler.process_command("ls", None)
        assert res is not None
        assert isinstance(res, tuple)

    def test_none_env_handled(self, handler):
        """Verify process_command with env=None in context doesn't crash (User Reported Bug)"""
        context = {"cwd": "/", "env": None}
        res = handler.process_command("ls", context)
        assert res is not None
        assert context["env"] == {}

    def test_none_cwd_handled(self, handler):
        """Verify process_command with cwd=None in context doesn't crash (User Reported Bug)"""
        context = {"cwd": None, "env": {}}
        # This used to trigger TypeError: expected str, bytes or os.PathLike object, not NoneType
        # via resolve_path -> os.path.join(None, "ls")
        res = handler.process_command("ls", context)
        assert res is not None
        assert context["cwd"] == "/"
