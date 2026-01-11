import sys
import os
import pytest
from unittest.mock import MagicMock, patch

# Ensure the root directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ssh_honeypot.core.command_handler import CommandHandler


class TestAdvancedHandler:

    @pytest.fixture
    def handler(self):
        self.mock_llm = MagicMock()
        # Mock simple response
        self.mock_llm.generate_response.return_value = "LLM Response\n"

        self.mock_db = MagicMock()
        self.mock_db.get_cached_response.return_value = None
        self.mock_db.list_user_dir.return_value = []
        self.mock_db.get_user_node.return_value = None
        self.mock_db.get_fs_node.return_value = None

        return CommandHandler(self.mock_llm, self.mock_db)

    # 1. Sanitization Tests
    def test_sanitization_stripping(self, handler):
        # 2>/dev/null should be removed
        # Since 'lspci' is a READ_ONLY_COMMAND if registered or generic, and in this setup it might hit generic LLM if not handled
        # But 'lspci' is in READ_ONLY_COMMANDS?
        # Let's check a command that would definitely hit LLM if passed raw,
        # or check what process_command passes to generic handler.

        # We can intercept 'handle_lspci' if it exists or use generic.
        # But easier: We can inspect 'cmd' passed to handlers or LLM if we mock internal methods?
        # Or just checking 'process_command' call signature?
        # process_command modifies 'cmd' locally before dispatching.
        # But we can't easily assert local variable state without debugging.

        # Instead, verify via side effects.
        # For 'echo 2>/dev/null', it should hit 'handle_echo' with '2>/dev/null' removed?
        # handle_echo strips args.

        # Let's rely on a mocked handler method to verify the received cmd string.
        handler.handle_mock = MagicMock(return_value=("output", {}, {}))
        # Monkey patch a command to use this mock
        handler.STATE_COMMANDS.add("test_redirection")
        setattr(handler, "handle_test_redirection", handler.handle_mock)

        ctx = {}
        handler.process_command("test_redirection 2>/dev/null", ctx)

        # Verify handle_mock called with sanitized string
        # Logic replaces 2>/dev/null with space and strips
        # "test_redirection 2>/dev/null" -> "test_redirection"
        handler.handle_mock.assert_called_with("test_redirection", ctx)

    # 2. Variable Tests
    def test_variable_assignment(self, handler):
        ctx = {"env": {}}
        # Mock inner command execution for $(...)
        # We need process_command to recurse. It's the same handler instance.
        # But we need checking result.

        # "VAR=$(echo val)" -> handle_echo returns "val\n" -> strip -> "val"
        # Handler echo is local.
        out, updates, meta = handler.process_command("MYVAR=$(echo val)", ctx)

        assert out == ""
        assert "env" in updates
        assert updates["env"]["MYVAR"] == "val"
        # Context should be updated too via recursion or logic?
        # process_command returns updates['env'].

    def test_variable_substitution(self, handler):
        ctx = {"env": {"TARGET": "World"}}
        out, _, _ = handler.process_command("echo Hello $TARGET", ctx)
        assert out.strip() == "Hello World"

    def test_chained_propagation(self, handler):
        # Test A=1; echo $A
        ctx = {}
        out, updates, _ = handler.process_command("A=1; echo $A", ctx)

        # Output should be from echo
        assert out.strip() == "1"
        assert updates.get("env", {}).get("A") == "1"

    # 3. Text Processing Tests
    def test_tr_pipe(self, handler):
        # echo "Hello" | tr 'H' 'J'
        ctx = {}
        out, _, _ = handler.process_command("echo Hello | tr 'H' 'J'", ctx)
        assert out.strip() == "Jello"

    def test_tr_delete(self, handler):
        ctx = {}
        out, _, _ = handler.process_command("echo Hello | tr -d 'l'", ctx)
        assert out.strip() == "Heo"

    def test_head_basic_stdin(self, handler):
        ctx = {"stdin": "1\n2\n3\n4\n"}
        out, _, _ = handler.process_command("head -n 2", ctx)
        assert out == "1\n2\n"

    def test_tail_basic_stdin(self, handler):
        ctx = {"stdin": "1\n2\n3\n4\n"}
        out, _, _ = handler.process_command("tail -n 2", ctx)
        assert out == "3\n4\n"

    def test_head_legacy_syntax(self, handler):
        ctx = {"stdin": "1\n2\n3\n4\n"}
        out, _, _ = handler.process_command("head -2", ctx)
        assert out == "1\n2\n"

    def test_tail_legacy_syntax(self, handler):
        ctx = {"stdin": "1\n2\n3\n4\n"}
        out, _, _ = handler.process_command("tail -2", ctx)
        assert out == "3\n4\n"

    def test_head_file(self, handler):
        # Mock _generate_or_get_content or the underlying LLM/DB call
        # Since _generate_or_get_content calls self._resolve_path and then checks DB or LLM
        # We can mock _generate_or_get_content directly to avoid complex filesystem mocking

        with patch.object(
            handler.head_handler,
            "_generate_or_get_content",
            return_value=("LineA\nLineB\nLineC\n", "local"),
        ) as mock_get:
            out, _, _ = handler.process_command("head -2 foo.txt", {"cwd": "/"})
            assert out == "LineA\nLineB\n"
            # mock_get.assert_called_with("head", "foo.txt", {'cwd': '/', 'env': {}, 'db': handler.db, 'llm': handler.llm})
            # Context assertion is brittle due to generic context injection in process_command.
            # Just verify it was called.
            assert mock_get.called
            args, _ = mock_get.call_args
            assert args[0] == "head"
            assert args[1] == "foo.txt"

    # 4. Cut Tests
    def test_cut_delimiter_fields(self, handler):
        # input: "root:x:0:0" -> cut -d: -f1 -> "root"
        ctx = {"stdin": "root:x:0:0\nbin:x:1:1\n"}
        out, _, _ = handler.process_command("cut -d: -f1", ctx)
        assert out == "root\nbin\n"

    def test_cut_default_delim(self, handler):
        # default delim TAB
        ctx = {"stdin": "col1\tcol2\tcol3\nval1\tval2\tval3\n"}
        out, _, _ = handler.process_command("cut -f2", ctx)
        assert out == "col2\nval2\n"

    def test_cut_range(self, handler):
        # cut -d: -f1-3
        ctx = {"stdin": "1:2:3:4:5\n"}
        out, _, _ = handler.process_command("cut -d: -f1-3", ctx)
        assert out == "1:2:3\n"

    def test_cut_list(self, handler):
        # cut -d: -f1,3
        ctx = {"stdin": "1:2:3:4:5\n"}
        out, _, _ = handler.process_command("cut -d: -f1,3", ctx)
        assert out == "1:3\n"

    def test_cut_missing_args(self, handler):
        ctx = {"stdin": "data"}
        out, _, _ = handler.process_command("cut", ctx)
        assert "must specify a list" in out

    # 5. Complex Variable Assignment (Bug Repro)
    def test_var_assign_complex(self, handler):
        # uptime=$(cat /proc/uptime 2>/dev/null | cut -d. -f1)
        # Note: 2>/dev/null is stripped by sanitization before matching?
        # Let's mock the inner chain execution flow

        # We need to ensure 'cat' and 'cut' work recursively.
        # But for this unit test, we can trust process_command recursion if regex matches.

        ctx = {"env": {}, "vfs": {}, "cwd": "/"}
        # We need a file /proc/uptime or mock content
        # Mock _generate_or_get_content for cat
        # But 'cat' calls _generate_or_get_content.

        # Let's verify the REGEX match first by using a simpler inner command that is still "complex" string
        # e.g. uptime=$(echo 123 | cut -d. -f1)

        # We need to setup handler to handle 'cut' properly.
        # And pipe logic is inside process_command.

        # Let's try matching the user's exact command structure with trailing space
        cmd = "uptime=$(echo 123.456 2>/dev/null | cut -d. -f1) "

        out, updates, _ = handler.process_command(cmd, ctx)
        assert updates.get("env", {}).get("uptime") == "123"

    # 6. Debug Command Access Control
    def test_debug_commands_access(self, handler):
        # Trusted IP
        with patch(
            "ssh_honeypot.core.command_handler.get_ignored_ips",
            return_value=["1.2.3.4"],
        ):
            ctx = {"client_ip": "1.2.3.4", "env": {"test": "val"}}
            out, _, _ = handler.process_command("debug_env", ctx)
            assert "DEBUG ENV" in out

            # Untrusted IP
            ctx = {"client_ip": "10.0.0.1", "env": {"test": "val"}}
            out, _, _ = handler.process_command("debug_env", ctx)
            # Should fall through (return empty or LLM response mocked)
            # Since LLM is mocked to return "mock_response", we expect that or empty depending on flow
            assert "DEBUG ENV" not in out
