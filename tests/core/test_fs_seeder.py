
import unittest
import os
import shutil
import tempfile
import json
from unittest.mock import patch, MagicMock
import sys

# Add project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from ssh_honeypot.core.fs_seeder import get_skeleton_data, load_overlay_nodes

class TestFSSeeder(unittest.TestCase):
    def setUp(self):
        # Create a temp directory structure to mock project root
        self.test_dir = tempfile.mkdtemp()
        self.personas_dir = os.path.join(self.test_dir, 'personas')
        self.common_fs_dir = os.path.join(self.personas_dir, 'common_fs')
        
        os.makedirs(self.common_fs_dir)
        
        # Create a fake common file
        self.common_file = os.path.join(self.common_fs_dir, 'test_bait.txt')
        with open(self.common_file, 'w') as f:
            f.write("fake_creds")
            
        # Mock config to point to this temp dir? 
        # Actually fs_seeder calculates paths relative to itself.
        # We might need to patch `os.path.join` or `ssh_honeypot.core.fs_seeder.base_dir`?
        # get_skeleton_data uses `os.path.dirname` traversal from `__file__`.
        # It's easier to mock `load_overlay_nodes` or patch the path detection logic if possible.
        # But `common_fs_path` is resolved inside the function.
        pass

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    @patch('ssh_honeypot.core.fs_seeder.os.path.exists')
    @patch('ssh_honeypot.core.fs_seeder.load_overlay_nodes')
    def test_common_fs_merging(self, mock_load, mock_exists):
        """
        Verify that if common_fs exists, its nodes are merged into the result.
        """
        # 1. Setup Logic
        # Mock project root path check
        def side_effect_exists(path):
            if 'common_fs' in path:
                return True
            return False # Ignore base_fs.json for this test to keep it simple
            
        mock_exists.side_effect = side_effect_exists
        
        # Mock the nodes returned by common_fs
        common_nodes = [
            {'path': '/home/user/bait.txt', 'type': 'file', 'content': 'secret'},
            {'path': '/etc/passwd', 'type': 'file', 'content': 'root:x:0:0'} # Should override if exists
        ]
        mock_load.return_value = common_nodes
        
        # 2. Call Function
        # We patch config to avoid needing real persona config
        with patch('ssh_honeypot.core.fs_seeder.config') as mock_config:
            mock_config.get.return_value = None # No persona overlay
            
            nodes = get_skeleton_data(json_path="dummy_path")
            
        # 3. Verify
        # Check if common nodes are present
        paths = [n['path'] for n in nodes]
        self.assertIn('/home/user/bait.txt', paths)
        self.assertIn('/etc/passwd', paths)
        
        # Check if load_overlay was called with a path ending in 'common_fs'
        args, _ = mock_load.call_args
        self.assertTrue(args[0].endswith('common_fs'))

if __name__ == '__main__':
    unittest.main()
