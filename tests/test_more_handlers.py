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
    # default cache miss
    mock_db.get_cached_response.return_value = None
    return CommandHandler(mock_llm, mock_db)

class TestMoreHandlers:
    def test_history(self, handler):
        context = {
            'history': [("ls", "out1"), ("whoami", "root")]
        }
        resp, _ = handler.handle_history("history", context)
        assert " 1  ls" in resp
        assert " 2  whoami" in resp

    def test_su_failure(self, handler):
        start = time.time()
        resp, _ = handler.handle_su("su root", {})
        end = time.time()
        
        assert "Authentication failure" in resp
        # Check simulated delay (approx 1.5s)
        assert (end - start) >= 1.4

    def test_perl(self, handler):
        # perl -> _handle_interpreter
        context = {'cwd': '/root', 'client_ip': '1.2.3', 'user': 'root'}
        
        # Mock script content
        handler.db.get_user_node.return_value = {'content': 'print "hello"'}
        
        # Mock LLM to return execution result
        handler.llm.generate_response.return_value = json.dumps({'output': 'hello'})
        
        resp, _, _ = handler.handle_perl("perl script.pl", context)
        
        assert "hello" in resp
        # Verify LLM prompt contained instructions for perl
        args, _ = handler.llm.generate_response.call_args
        prompt = args[0]
        assert "perl script found at 'script.pl'" in prompt

    def test_awk(self, handler):
        context = {'cwd': '/root', 'client_ip': '1.2.3', 'user': 'root'}
        
        # Case 1: awk 'prog' file
        # Mock file content
        handler.db.get_user_node.return_value = {'content': 'col1 col2\nval1 val2'}
        
        handler.llm.generate_response.return_value = json.dumps({'output': 'val1'})
        
        # Mock cache miss for first call
        handler.db.get_cached_response.return_value = None
        
        cmd = "awk '{print $1}' data.txt"
        resp, _, _ = handler.handle_awk(cmd, context)
        
        assert "val1" in resp
        
        # Verify cache interaction with CONTENT Hash
        # We can't easily check exactly what key was passed to get_cached_response unless we mock content hash?
        # But we can assert cache_response was called with a key containing "data_hash="
        args, _ = handler.db.cache_response.call_args
        cache_key = args[0]
        assert "data_hash=" in cache_key
        assert cmd in cache_key

    def test_awk_complex_args(self, handler):
        # Case: awk -F: '{print}' /etc/passwd
        context = {'cwd': '/root'}
        handler.db.get_user_node.return_value = {'content': 'root:x:0:0...'}
        handler.llm.generate_response.return_value = json.dumps({'output': 'root'})
        
        cmd = "awk -F: '{print $1}' /etc/passwd"
        handler.handle_awk(cmd, context)
        
        # Verify we identified /etc/passwd as file
        # We mocked get_user_node, so if it was called with /etc/passwd, we know logic worked
        # It calls _resolve_path -> assuming /etc/passwd is absolute
        # get_user_node(ip, user, path)
        # Check call args
        call_args_list = handler.db.get_user_node.call_args_list
        # Should be called for /etc/passwd
        found = False
        for call in call_args_list:
            if '/etc/passwd' in call[0]: 
                found = True
                break
        if not found:
             # Try get_fs_node (user node returns None, then fallback to global)
             # Ah, _generate_or_get_content calls get_user_node THEN get_fs_node.
             # handler.db.get_user_node was mocked to return something.
             pass
        
        assert found
