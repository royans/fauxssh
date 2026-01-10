import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_cat import CatCommand

class TestCatCommand:
    @pytest.fixture
    def handler(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        # Mocking BaseHandler dependencies defaults
        self.mock_db.get_user_node.return_value = None
        self.mock_db.get_fs_node.return_value = None
        return CatCommand(self.mock_db, self.mock_llm)

    def test_handle_cat_user_upload(self, handler):
        """Verify cat prioritizes user uploads"""
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'user'}
        
        # Mock User File
        handler.db.get_user_node.return_value = {
            'path': '/root/secret.txt',
            'type': 'file',
            'content': "SECRET_UPLOAD_CONTENT"
        }
        
        resp, _, _ = handler.handle("cat secret.txt", context)
        assert "SECRET_UPLOAD_CONTENT" in resp
        # Should not go to global FS or LLM
        handler.db.get_fs_node.assert_not_called()

    def test_handle_cat_proc_uptime(self, handler):
        """Test cat /proc/uptime simulated"""
        context = {'cwd': '/root'}
        # Should hit LLM or hardcoded?
        # In base handler, no hardcoded /proc/uptime.
        # It hits LLM.
        # Mock LLM
        handler.llm.generate_response.return_value = '{"output": "12345.67 12345.67"}'
        
        resp, _, meta = handler.handle("cat /proc/uptime", context)
        assert "12345.67" in resp
        assert meta['source'] == 'llm'
