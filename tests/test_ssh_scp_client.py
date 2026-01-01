import pytest
import sys
import os
import json
import time
from unittest.mock import MagicMock, patch
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.command_handler import CommandHandler

@pytest.fixture
def handler():
    mock_llm = MagicMock()
    mock_db = MagicMock()
    # Mock CP logic success
    mock_db.get_user_node.return_value = None # source doesn't exist?
    return CommandHandler(mock_llm, mock_db)

class TestSshScpClient:
    def test_ssh_remote_failure(self, handler):
        start = time.time()
        resp, _ = handler.handle_ssh("ssh user@remote.com", {})
        end = time.time()
        
        assert "ssh: connect to host" in resp or "Could not resolve" in resp
        assert (end - start) >= 0.9

    def test_ssh_localhost_success(self, handler):
        resp, _ = handler.handle_ssh("ssh localhost", {})
        assert "Last login:" in resp
        assert "from 127.0.0.1" in resp

    def test_scp_remote_failure(self, handler):
        # scp local user@remote:/tmp
        start = time.time()
        resp, _ = handler.handle_scp("scp file.txt user@remote:/tmp", {})
        end = time.time()
        
        assert "ssh: connect to host" in resp or "lost connection" in resp
        assert (end - start) >= 0.9

    def test_scp_localhost_simulation(self, handler):
        # scp local user@localhost:/tmp
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'root'}
        
        # We need to mock handle_cp or underlying DB calls?
        # Let's mock handle_cp to verify delegation
        with patch.object(handler, 'handle_cp', return_value=("", {'file_modifications': ['/tmp/file.txt']})) as mock_cp:
            resp, updates = handler.handle_scp("scp file.txt user@localhost:/tmp", context)
            
            # Verify CP was called with transformed args
            assert mock_cp.called
            args = mock_cp.call_args[0]
            cp_cmd = args[0]
            assert "cp file.txt /tmp" in cp_cmd
            
            # Verify output/updates propagated
            assert updates['file_modifications'] == ['/tmp/file.txt']
