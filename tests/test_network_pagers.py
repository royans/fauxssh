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
    def test_wget_failure(self, handler):
        start = time.time()
        # Mock datetime to avoid errors if used
        resp, _ = handler.handle_wget("wget http://example.com/malware.exe", {})
        
        assert "unable to resolve" in resp or "failed:" in resp
        assert "malware.exe" in resp

    def test_curl_failure(self, handler):
        start = time.time()
        resp, _ = handler.handle_curl("curl http://example.com", {})
        end = time.time()
        
        assert "curl: (" in resp or "Could not resolve" in resp
        # Check delay (approx 1.0s)
        assert (end - start) >= 0.9

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
