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
    mock_db.get_cached_response.return_value = None
    return CommandHandler(mock_llm, mock_db)

class TestNetworkPagers:
    def test_wget_success(self, handler):
        start = time.time()
        # Mock LLM
        handler.llm.generate_response.return_value = "<html>Malware</html>"
        
        resp, _ = handler.handle_wget("wget -O malware.exe http://example.com/malware.exe", {'session_id': '1', 'cwd': '/root'})
        
        # New behavior: Simulated Success + Progress Bar
        assert "200 OK" in resp
        assert "Saving to: 'malware.exe'" in resp
        assert "saved [" in resp

    def test_curl_success(self, handler):
        start = time.time()
        handler.llm.generate_response.return_value = "<html>Malware</html>"
        
        resp, _ = handler.handle_curl("curl http://example.com", {'session_id': '1', 'cwd': '/root'})
        end = time.time()
        
        # Should return content
        assert "<html>Malware</html>" in resp

    def test_more_alias(self, handler):
        # Should behave like cat
        context = {'cwd': '/root'}
        # Mock content retrieval
        # handle_cat calls _generate_or_get_content("cat", ...)
        # handle_more calls handle_cat
        
        # We need to mock _generate_or_get_content behavior.
        # It calls get_user_node then get_fs_node then LLM.
        handler.db.get_user_node.return_value = {'content': 'page 1\npage 2'}
        
        resp, _, _ = handler.handle_more("more file.txt", context)
        assert "page 1\npage 2" in resp

    def test_less_alias(self, handler):
        context = {'cwd': '/root'}
        handler.db.get_user_node.return_value = {'content': 'less content'}
        
        resp, _, _ = handler.handle_less("less file.txt", context)
        assert "less content" in resp
