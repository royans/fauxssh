import sys
import os
import pytest
from unittest.mock import MagicMock, patch

# Ensure the root directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ssh_honeypot.core.command_handler import CommandHandler


class TestCommandHandlerFlavors:

    @pytest.fixture
    def handler(self):
        os.environ["SSHPOT_TEST_MODE"] = "1"
        self.mock_llm = MagicMock()
        self.mock_db = MagicMock()
        self.mock_db.get_cached_response.return_value = None
        self.mock_db.get_user_node.return_value = None
        self.mock_db.get_fs_node.return_value = None
        self.mock_db.list_fs_dir.return_value = []
        self.mock_db.list_user_dir.return_value = []
        h = CommandHandler(self.mock_llm, self.mock_db)
        yield h
        if "SSHPOT_TEST_MODE" in os.environ:
            del os.environ["SSHPOT_TEST_MODE"]

    def test_stdin_redirection(self, handler):
        """bash < script.sh should read script.sh and run as bash stdin"""
        context = {
            "cwd": "/home/user",
            "client_ip": "1.2.3.4",
            "user": "test",
            "history": [],
            "env": {},
        }

        # Mock script.sh existing
        self.mock_db.get_user_node.return_value = {
            "type": "file",
            "content": "echo 'Hello from Pipe'",
        }

        # Mock LLM response for bash execution
        self.mock_llm.generate_response.return_value = '{"output": "Hello from Pipe"}'

        # Run command
        resp, _, meta = handler.process_command("bash < script.sh", context)

        assert "Hello from Pipe" in resp
        # Check if _handle_interpreter was called with stdin
        args, _ = self.mock_llm.generate_response.call_args
        assert "piping the following content into bash (stdin)" in args[0]
        assert "echo 'Hello from Pipe'" in args[0]

    def test_direct_execution_shebang_bash(self, handler):
        """./script.sh with #!/bin/bash shebang"""
        context = {
            "cwd": "/home/user",
            "client_ip": "1.2.3.4",
            "user": "test",
            "history": [],
            "env": {},
        }

        # Mock script.sh with shebang
        # Direct execution checks get_fs_node (global) or get_user_node (per-IP)
        # In process_command line ~1451: node = self.db.get_fs_node(abs_path)
        self.mock_db.get_fs_node.return_value = {
            "type": "file",
            "content": "#!/bin/bash\necho 'Shebang works'",
        }
        self.mock_llm.generate_response.return_value = '{"output": "Shebang works"}'

        resp, _, _ = handler.process_command("./script.sh", context)

        assert "Shebang works" in resp
        args, _ = self.mock_llm.generate_response.call_args
        assert "running the following bash script" in args[0]

    def test_source_command(self, handler):
        """source script.sh should run via bash handler"""
        context = {
            "cwd": "/home/user",
            "client_ip": "1.2.3.4",
            "user": "test",
            "history": [],
            "env": {},
        }

        self.mock_db.get_user_node.return_value = {
            "type": "file",
            "content": "echo 'Sourced'",
        }
        self.mock_llm.generate_response.return_value = '{"output": "Sourced"}'

        resp, _, _ = handler.process_command("source script.sh", context)

        assert "Sourced" in resp
        args, _ = self.mock_llm.generate_response.call_args
        assert "bash" in args[0].lower()

    def test_dot_command(self, handler):
        """. script.sh should run via bash handler"""
        context = {
            "cwd": "/home/user",
            "client_ip": "1.2.3.4",
            "user": "test",
            "history": [],
            "env": {},
        }

        self.mock_db.get_user_node.return_value = {
            "type": "file",
            "content": "echo 'Dotted'",
        }
        self.mock_llm.generate_response.return_value = '{"output": "Dotted"}'

        resp, _, _ = handler.process_command(". script.sh", context)

        assert "Dotted" in resp
