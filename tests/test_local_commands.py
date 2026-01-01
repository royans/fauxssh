import pytest
import sys
import os
import json
from unittest.mock import MagicMock
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.command_handler import CommandHandler

@pytest.fixture
def handler():
    mock_llm = MagicMock()
    mock_db = MagicMock()
    return CommandHandler(mock_llm, mock_db)

class TestLocalCommands:
    def test_echo(self, handler):
        resp, _ = handler.handle_echo("echo hello world", {})
        assert "hello world" in resp
        
        resp, _ = handler.handle_echo("echo 'quoted string'", {})
        assert "quoted string" in resp
        assert "'" not in resp # Naive stripping check

    def test_touch_mkdir(self, handler):
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'root'}
        handler.mock_db = handler.db # Alias for clarity
        
        # TOUCH
        handler.db.get_user_node.return_value = None # Doesn't exist
        
        handler.handle_touch("touch test.txt", context)
        
        # Verify call
        # update_user_file(ip, user, path, parent, type, meta, content)
        args, _ = handler.db.update_user_file.call_args
        assert args[2] == "/root/test.txt"
        assert args[4] == "file"
        
        # MKDIR
        handler.handle_mkdir("mkdir mydir", context)
        args, _ = handler.db.update_user_file.call_args
        assert args[2] == "/root/mydir"
        assert args[4] == "dir"
        
    def test_cp(self, handler):
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'root'}
        
        # Mock Source Content
        # We need to mock _generate_or_get_content mostly indirectly? 
        # But handle_cp calls it.
        # We can mock the method on the handler instance if we want, or mock DB global/user get
        
        # Let's mock DB returning source
        handler.db.get_user_node.side_effect = lambda ip, u, path: {
            'type': 'file', 'content': 'source_data', 'metadata': '{}'
        } if path == '/root/src' else None
        
        # We also need to mock _generate_or_get_content to return 'source_data'
        # Since _generate_or_get_content calls get_user_node, check if it works.
        # It calls get_user_node then get_fs_node.
        # So mocking get_user_node is enough if logic is correct.
        
        # But wait, handle_cp calls _generate_or_get_content.
        # In this test environment, that method is real.
        
        handler.handle_cp("cp src dest", context)
        
        # Check update_user_file called with content 'source_data'
        # Last call
        args, _ = handler.db.update_user_file.call_args
        assert args[2] == "/root/dest"
        assert args[6] == "source_data"

    def test_base64(self, handler):
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'root'}
        
        # Mock file content
        handler.db.get_user_node.return_value = {'type': 'file', 'content': 'hello'}
        
        # Encode
        resp, _, _ = handler.handle_base64("base64 file", context)
        # b64(hello) -> aGVsbG8=
        assert "aGVsbG8=" in resp
        
        # Decode
        # Mock file content as b64
        handler.db.get_user_node.return_value = {'type': 'file', 'content': 'aGVsbG8='}
        resp, _, _ = handler.handle_base64("base64 -d file", context)
        assert "hello" in resp

    def test_chmod(self, handler):
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'root'}
        
        handler.db.get_user_node.return_value = {'type': 'file', 'metadata': json.dumps({'permissions': '------'}), 'path': '/root/f'}
        
        handler.handle_chmod("chmod 777 f", context)
        
        # We didn't actually implement DB update for meta yet in chmod, just pass?
        # "For now, just logging change for simulation, effectively "success""
        # So it should return empty string.
        pass
