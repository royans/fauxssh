import pytest
from unittest.mock import MagicMock
import sys
import os

# Ensure path is correct
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB


class TestComplexTr:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        # Mock LLM to return something specific if called, to distinguish from local handler
        mock_llm.generate_response.return_value = ("LLM_RESPONSE", None)
        mock_db = MagicMock()
        return CommandHandler(mock_llm, mock_db)

    def test_full_substitution_command(self, handler):
        # ls_help=$( (ls --help 2>&1 | tr '\n' ' ') || ls --help 2>&1)
        # This requires the handler to:
        # 1. Detect assignment var=val
        # 2. Detect value is $(...) -> subprocess
        # 3. Inside $(...):
        #    a. Detect (...) -> subshell
        #    b. Inside subshell: ls --help | tr ...
        #    c. Handle pipe: ls output -> tr input
        #    d. Handle tr locally
        # 4. Handle || logic (if first part fails) - but ls should succeed here.
        # 5. Assign result to variable.

        # We first need to check if 'ls' works in this mocked env?
        # CommandHandler delegates 'ls' to 'handle_ls'.
        # We need to ensure 'handle_ls' returns something or mock it.
        # Since we use MagicMock for 'db', handle_ls might fail or return default.
        # Let's mock 'ls_handler' if possible or ensure 'process_command' handles it.

        # Actually, CommandHandler initializes handlers in __init__.
        # We can patch 'handle_ls' on the handler instance.
        handler.ls_handler = MagicMock()
        handler.ls_handler.handle.return_value = ("Usage: ls...\nLine2", {}, {})

        cmd = "ls_help=$( (ls --help 2>&1 | tr '\\n' ' ') || ls --help 2>&1)"
        context = {}

        # Execution
        resp, updates, meta = handler.process_command(cmd, context)

        # Expected behavior:
        # No output (assignment is silent)
        # updates['env'] should contain 'ls_help'

        # If the complex parsing is fully supported:
        assert resp == ""
        assert "env" in updates
        assert "ls_help" in updates["env"]

        val = updates["env"]["ls_help"]
        # 'tr' should have replaced newlines
        assert "Usage: ls... Line2" in val  # assuming tr replaces \n with space
        # And no \n inside
        assert "\n" not in val


if __name__ == "__main__":
    pytest.main([__file__])
