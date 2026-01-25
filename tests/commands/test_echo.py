import pytest
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.handlers.unix.cmd_echo import handle_echo


class TestEchoCommand:
    def test_basic_echo(self):
        cmd = "echo hello world"
        out, updates, meta = handle_echo(cmd, {})
        assert out == "hello world\n"
        assert meta["source"] == "handler"

    def test_echo_flag_e(self):
        # \x61 is 'a'
        cmd = "echo -e '\\x61'"
        out, updates, meta = handle_echo(cmd, {})
        assert out == "a\n"

    def test_echo_flag_e_newline(self):
        cmd = "echo -e 'line1\\nline2'"
        out, updates, meta = handle_echo(cmd, {})
        assert out == "line1\nline2\n"

    def test_echo_flag_n(self):
        cmd = "echo -n no_newline"
        out, updates, meta = handle_echo(cmd, {})
        assert out == "no_newline"

    def test_echo_flag_ne(self):
        cmd = "echo -ne '\\x61'"
        out, updates, meta = handle_echo(cmd, {})
        assert out == "a"

    def test_quotes(self):
        cmd = "echo 'quoted string'"
        out, updates, meta = handle_echo(cmd, {})
        assert out == "quoted string\n"

    def test_complex_hex(self):
        # from screenshot: \x61\x75\x74\x68\x5F\x6F\x6B\x0A
        # auth_ok + newline char (\x0A)
        # 61(a) 75(u) 74(t) 68(h) 5F(_) 6F(o) 6B(k) 0A(\n)
        cmd = 'echo -e "\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A"'
        out, updates, meta = handle_echo(cmd, {})
        # Note: input string has literal backslashes if passed from shell
        # In python string "...", \\x becomes \x literal char.

        # Output should be "auth_ok\n" (from \x0A) + "\n" (from echo default)
        # Wait, echo -e interpreting \x0A adds a newline. Echo itself adds another unless -n.
        assert out == "auth_ok\n\n"
