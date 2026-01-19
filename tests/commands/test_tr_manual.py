import pytest
from unittest.mock import MagicMock
import sys
import os

# Ensure path is correct
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB


class TestTrCommand:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        mock_db = MagicMock()
        return CommandHandler(mock_llm, mock_db)

    def test_tr_simple_replace(self, handler):
        # tr 'a' 'b'
        cmd = "tr 'a' 'b'"
        context = {"stdin": "banana"}
        resp, _, _ = handler.process_command(cmd, context)
        assert resp == "bbnbnb"

    def test_tr_newline_replace(self, handler):
        # tr '\n' ' '
        cmd = "tr '\\n' ' '"
        context = {"stdin": "line1\nline2\n"}
        resp, _, _ = handler.process_command(cmd, context)
        assert resp == "line1 line2 "

    def test_tr_delete(self, handler):
        # tr -d 'a'
        cmd = "tr -d 'a'"
        context = {"stdin": "banana"}
        resp, _, _ = handler.process_command(cmd, context)
        assert resp == "bnn"

    def test_complex_substitution_logic(self, handler):
        # ls_help=$( (ls --help 2>&1 | tr '\n' ' ') || ls --help 2>&1)
        # We simulate the pipe and subshell execution flow by testing components

        # 1. Simulate "ls --help"
        # We can't easily mock the full recursive process_command here without setting up specific handlers.
        # But we can test the tr component with expected input from ls --help

        ls_output = "Usage: ls [OPTION]... [FILE]...\nList information about the FILEs (the current directory by default).\n"

        # 2. Test Pipe to tr
        cmd_tr = "tr '\\n' ' '"
        context = {"stdin": ls_output}
        tr_out, _, _ = handler.process_command(cmd_tr, context)

        assert "\n" not in tr_out
        assert "Usage: ls" in tr_out
        assert "by default). " in tr_out


if __name__ == "__main__":
    pytest.main([__file__])
