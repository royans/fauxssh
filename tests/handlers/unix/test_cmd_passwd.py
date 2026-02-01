import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_passwd import PasswdCommand


class TestPasswdCommand:
    @pytest.fixture
    def handler(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        return PasswdCommand(self.mock_db, self.mock_llm)

    def test_passwd_root_piped(self, handler):
        # Scenario from user image
        # (echo 'test'; echo 'pass'; echo 'pass') | passwd
        # command_handler splits this and passes 'test\npass\npass\n' as stdin
        context = {
            "user": "root",
            "stdin": "test\ni7dQx5Xdom?mW81g\ni7dQx5Xdom?mW81g\n",
            "client_ip": "1.2.3.4",
        }
        cmd = "passwd"

        output, updates, meta = handler.handle(cmd, context)

        assert "Changing password for root" in output
        assert "passwd: password updated successfully" in output
        assert "Enter new UNIX password:" in output
        assert "Retype new UNIX password:" in output
        assert "(current) UNIX password:" not in output
        assert updates == {}
        assert meta["source"] == "handler"

    def test_passwd_non_root_piped(self, handler):
        context = {
            "user": "user1",
            "stdin": "current_pass\nnew_pass\nnew_pass\n",
            "client_ip": "1.2.3.4",
        }
        cmd = "passwd"

        output, updates, meta = handler.handle(cmd, context)

        assert "Changing password for user1" in output
        assert "passwd: password updated successfully" in output
        assert "(current) UNIX password:" in output
        assert "Enter new UNIX password:" in output

    def test_passwd_interactive_failure(self, handler):
        # No stdin
        context = {"user": "user1", "stdin": "", "client_ip": "1.2.3.4"}
        cmd = "passwd"

        output, updates, meta = handler.handle(cmd, context)

        assert "Changing password for user1" in output
        assert "passwd: password unchanged" in output

    def test_passwd_root_change_other(self, handler):
        context = {
            "user": "root",
            "stdin": "pass123\npass123\n",
            "client_ip": "1.2.3.4",
        }
        cmd = "passwd victim"

        output, updates, meta = handler.handle(cmd, context)

        assert "Changing password for victim" in output
        assert "password updated successfully" in output
