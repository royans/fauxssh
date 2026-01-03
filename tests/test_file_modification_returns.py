import unittest
from unittest.mock import MagicMock
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.command_handler import CommandHandler

class TestFileModificationReturns(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        self.handler = CommandHandler(self.mock_llm, self.mock_db)
        self.context = {
            'cwd': '/home/test',
            'client_ip': '1.2.3.4',
            'user': 'testuser'
        }

    def test_handle_touch_returns_dict_in_list(self):
        self.mock_db.get_user_node.return_value = None # Does not exist
        
        output, meta = self.handler.handle_touch("touch newfile.txt", self.context)
        
        mods = meta.get('file_modifications')
        self.assertIsNotNone(mods)
        self.assertIsInstance(mods, list)
        self.assertTrue(len(mods) > 0)
        self.assertIsInstance(mods[0], dict, "file_modifications items must be dicts, not strings")
        self.assertEqual(mods[0]['action'], 'create')
        self.assertEqual(mods[0]['path'], '/home/test/newfile.txt')

    def test_handle_mkdir_returns_dict_in_list(self):
        self.assertIs(self.handler.db, self.mock_db)
        self.mock_db.get_user_node.return_value = None
        
        output, meta = self.handler.handle_mkdir("mkdir newdir", self.context)
        
        mods = meta.get('file_modifications')
        self.assertIsInstance(mods[0], dict)
        self.assertEqual(mods[0]['action'], 'create')

    def test_handle_rmdir_returns_dict_in_list(self):
        # exists, is dir, empty
        self.mock_db.get_user_node.return_value = {'type': 'dir'}
        self.mock_db.list_user_dir.return_value = [] 
        
        output, meta = self.handler.handle_rmdir("rmdir olddir", self.context)
        
        mods = meta.get('file_modifications')
        self.assertIsInstance(mods[0], dict)
        self.assertEqual(mods[0]['action'], 'delete')

    def test_handle_rm_returns_dict_in_list(self):
        # exists
        self.mock_db.get_user_node.return_value = {'type': 'file'}
        
        output, meta = self.handler.handle_rm("rm oldfile", self.context)
        
        mods = meta.get('file_modifications')
        self.assertIsInstance(mods[0], dict)
        self.assertEqual(mods[0]['action'], 'delete')

    def test_handle_cp_returns_dict_in_list(self):
        # Mock generate content
        self.handler._generate_or_get_content = MagicMock(return_value=("content", "local"))
        
        output, meta = self.handler.handle_cp("cp src dest", self.context)
        
        mods = meta.get('file_modifications')
        self.assertIsInstance(mods[0], dict)
        self.assertEqual(mods[0]['action'], 'create')
        
if __name__ == '__main__':
    unittest.main()
