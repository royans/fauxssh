import pytest
from unittest.mock import MagicMock
import sys
import os

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from ssh_honeypot.core.command_handler import CommandHandler


class TestComplexAssignment:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        # The complex command uses many tools (grep, cut, sed, lscpu, awk, dmidecode, uname)
        # Most of these probably fall back to LLM in a test environment unless handlers exist.
        # We set a generic return value for the LLM that simulates a CPU name.
        mock_llm.generate_response.return_value = (
            "Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz"
        )

        mock_db = MagicMock()
        mock_db.get_file.return_value = None  # No real files
        mock_db.get_cached_response.return_value = None

        return CommandHandler(mock_llm, mock_db)

    def test_cpu_model_extraction_chain(self, handler):
        """
        Tests the specific complex command chain reported by the user:
        cpu_model=$( (grep ... | ... ; lscpu ... | ... ; ... ) | awk ... )

        This tests:
        1. Variable assignment VAR=$(...)
        2. Nested subshells ( ... )
        3. Semicolon splitting inside subshells
        4. Pipe handling
        5. Quote handling in arguments (awk scripts, sed regexes)
        """

        cmd = """cpu_model=$( (grep -m1 -E "model name|Hardware" /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//;s/ *$//' ; lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^ +| +$/,"",$2); print $2; exit}' ; dmidecode -s processor-version 2>/dev/null | head -n1 ; uname -p 2>/dev/null) | awk 'NF{print; exit}' )"""

        context = {
            "env": {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            },
            "vfs": {},
            "user": "root",
        }

        # Execute
        out, updates, meta = handler.process_command(cmd, context)

        # Verify
        # The assignment should produce empty output on stdout
        assert out.strip() == ""

        # The 'env' update should contain 'cpu_model'
        new_env = updates.get("env", {})
        assert "cpu_model" in new_env, "cpu_model was not set in environment"

        # The value should match our mock LLM output (or partial processing of it)
        # Since the command ends with `| awk 'NF{print; exit}'`, it filters the output.
        # Our Mock returns "Intel(R) Xeon(R)..." for every calls.
        # The chain essentially runs multiple commands trying to find a model name.
        # It's likely one of them succeeds via LLM mock and pipes to awk.
        # The value should match the output from the local 'lscpu' handler (AMD EPYC)
        # because our new local handlers (grep/lscpu/awk/sed) take precedence over the mock LLM.
        # The chain puts 'grep' output first, then 'lscpu'.
        # If 'grep' fails (no /proc/cpuinfo in mock fs), lscpu output (AMD) is used.
        # This confirms local execution logic works.
        assert "AMD EPYC" in new_env["cpu_model"]

    def test_semicolon_in_quotes(self, handler):
        """
        Verify that semicolons inside quotes are NOT used to split commands.
        e.g. echo "A;B" should be one command, not 'echo "A' and 'B"'
        """
        cmd = 'echo "A;B"'
        # If split incorrectly, it might try to run 'B"' which is invalid.
        # If correct, it runs echo "A;B" -> output "A;B"

        context = {"env": {}}
        out, updates, meta = handler.process_command(cmd, context)

        assert "A;B" in out

    def test_semicolon_in_subshell(self, handler):
        """
        Verify that semicolons inside subshells are handled recursively,
        not by the top-level splitter.
        """
        # (echo A; echo B)
        # Top level sees one command: "(echo A; echo B)"
        # It strips parens -> "echo A; echo B"
        # Then recursively processes matches ";" -> calls echo A, then echo B.

        cmd = "(echo A; echo B)"
        context = {"env": {}}
        out, updates, meta = handler.process_command(cmd, context)

        assert "A" in out
        assert "B" in out
