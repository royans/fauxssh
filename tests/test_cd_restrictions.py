import pytest
from unittest.mock import MagicMock
from ssh_honeypot.command_handler import CommandHandler

class TestCDRepro:
    @pytest.fixture
    def mock_db(self):
        db = MagicMock()
        # Mock get_fs_node for FILE
        def get_node_side_effect(path):
            if path == "/home/user/testfile":
                return {'type': 'file', 'content': 'data'}
            if path == "/home/user":
                return {'type': 'directory'}
            return None
        
        db.get_fs_node.side_effect = get_node_side_effect
        
        # Mock user node as well for consistency
        def get_user_node_side_effect(ip, user, path):
             if path == "/home/user/testfile":
                 return {'type': 'file', 'content': 'data'}
             return None
        db.get_user_node.side_effect = get_user_node_side_effect
        
        return db

    @pytest.fixture
    def mock_llm(self):
        llm = MagicMock()
        # LLM would normally say "success", returning new_cwd
        # We simulate the buggy behavior where LLM allows it
        llm.generate_response.return_value = '{"new_cwd": "/home/user/testfile", "output": ""}'
        return llm

    @pytest.fixture
    def handler(self, mock_llm, mock_db):
        return CommandHandler(mock_llm, mock_db)

    def test_cd_into_file_repro(self, handler):
        # Setup context
        context = {
            'cwd': '/home/user',
            'user': 'user',
            'client_ip': '1.2.3.4'
        }
        
        # Action: cd testfile
        # "testfile" exists as a file in mock_db
        resp, updates = handler.handle_cd("cd testfile", context)
        
        # Expectation (for BUG): It succeeds (new_cwd is set)
        # Expectation (for FIX): It fails (Not a directory)
        
        # Currently asserting FAILURE of this test to prove the bug exists?
        # Or asserting expected CORRECT behavior and watching it fail?
        # I'll assert CORRECT behavior.
        
        # If bug exists, this assertion will FAIL.
        assert "Not a directory" in resp
        assert 'new_cwd' not in updates
