import pytest
from unittest.mock import MagicMock
import sys
import os

# Ensure path is correct
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB


class TestComplexCatTr:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        mock_db = MagicMock()
        return CommandHandler(mock_llm, mock_db)

    def test_cat_help_substitution(self, handler):
        # cat_help=$( (cat --help 2>&1 | tr '\n' ' ') || cat --help 2>&1)

        # 1. Verify cat --help returns expected content locally
        cat_cmd = "cat --help 2>&1"
        cat_out, _, _ = handler.process_command(cat_cmd, {})
        assert "Usage: cat" in cat_out
        assert "standard output" in cat_out

        # 2. Verify tr substitution checks
        tr_cmd = "tr '\\n' ' '"
        context = {"stdin": "line1\nline2"}
        tr_out, _, _ = handler.process_command(tr_cmd, context)
        assert tr_out == "line1 line2"

        # 3. Full Complex Command
        # This tests assignment, subshell, pipe, || logic, and specific handlers all together
        cmd = "cat_help=$( (cat --help 2>&1 | tr '\\n' ' ') || cat --help 2>&1)"
        context = {}

        resp, updates, meta = handler.process_command(cmd, context)

        # Assignment produces no output
        assert resp == ""

        # Check Env Update
        assert "env" in updates
        assert "cat_help" in updates["env"]

        val = updates["env"]["cat_help"]

        # Validation
        assert "Usage: cat" in val
        # Should be flattened (no newlines)
        assert "\n" not in val
        assert "standard output" in val


if __name__ == "__main__":
    pytest.main([__file__])
