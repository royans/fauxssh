import unittest
from unittest.mock import MagicMock
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.command_handler import CommandHandler

class TestPermissions(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        self.handler = CommandHandler(self.mock_llm, self.mock_db)
        
        # Default context
        self.context = {
            'cwd': '/home/test',
            'client_ip': '1.2.3.4',
            'user': 'testuser'
        }
        
    def test_touch_permissions(self):
        # 1. Blocked: /etc/test
        out, updates = self.handler.handle_touch("touch /etc/test", self.context)
        self.assertIn("Permission denied", out)
        self.assertDictEqual(updates, {})

        # 2. Allowed: /tmp/test
        # Mock get_user_node to return None (file doesn't exist)
        self.mock_db.get_user_node.return_value = None
        out, updates = self.handler.handle_touch("touch /tmp/test", self.context)
        self.assertEqual(out, "")
        self.assertTrue(len(updates.get('file_modifications', [])) > 0)
        
        # 3. Allowed: /home/test/foo
        out, updates = self.handler.handle_touch("touch foo", self.context) # in cwd /home/test
        self.assertEqual(out, "")
        self.assertTrue(len(updates.get('file_modifications', [])) > 0)

    def test_mkdir_permissions(self):
        out, updates = self.handler.handle_mkdir("mkdir /boot/newdir", self.context)
        self.assertIn("Permission denied", out)
        
        # /root/ should now be allowed (root's home)
        self.mock_db.get_user_node.return_value = None
        out, updates = self.handler.handle_mkdir("mkdir /root/newdir", self.context)
        self.assertEqual(out, "")
        
        self.mock_db.get_user_node.return_value = None
        out, updates = self.handler.handle_mkdir("mkdir /tmp/newdir", self.context)
        self.assertEqual(out, "")

    def test_cp_permissions(self):
        # cp source /etc/
        # Need source content logic to pass
        self.handler._generate_or_get_content = MagicMock(return_value=('src_content', 'local'))
        
        out, updates = self.handler.handle_cp("cp src /etc/dest", self.context)
        self.assertIn("Permission denied", out)

    def test_mv_permissions(self):
        # mv source /etc/
        # Mock handle_cp to return failed permission
        self.handler.handle_cp = MagicMock(return_value=('cp: Permission denied', {}))
        
        out, updates = self.handler.handle_mv("mv src /etc/dest", self.context)
        self.assertIn("Permission denied", out)

    def test_redirection_permissions(self):
        # process_command -> echo "x" > /etc/foo
        
        # We need to ensure logic reaches redirection block
        # Mocking resolve check if needed, but resolve handles paths nicely
        
        cmd = 'echo "fail" > /etc/foo'
        out, updates, meta = self.handler.process_command(cmd, self.context)
        
        self.assertIn("Permission denied", out)
        self.assertNotIn('file_modifications', updates)
        
        # Allowed case
        self.mock_db.get_user_node.return_value = None # for append check if any
        cmd = 'echo "ok" > /tmp/ok'
        out, updates, meta = self.handler.process_command(cmd, self.context)
        self.assertEqual(out, "")
        # Check updates for modifications
        self.assertIn('file_modifications', updates)

if __name__ == '__main__':
    unittest.main()
