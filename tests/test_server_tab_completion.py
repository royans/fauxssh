import unittest
from unittest.mock import MagicMock
import sys
import os

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.server import handle_tab_completion

class TestTabCompletion(unittest.TestCase):

    def test_no_matches(self):
        # Setup
        chan = MagicMock()
        buffer = "testfile"
        vfs = {'/': ['otherfile', 'another']}
        cwd = '/'
        prompt = "$ "
        
        # Action
        new_buffer = handle_tab_completion(chan, buffer, vfs, cwd, prompt)
        
        # Assert: No change, no sends
        self.assertEqual(new_buffer, "testfile")
        chan.send.assert_not_called()

    def test_single_match_completion(self):
        # Setup
        chan = MagicMock()
        buffer = "sys"
        vfs = {'/': ['system.log', 'other']}
        cwd = '/'
        prompt = "$ "
        
        # Action
        new_buffer = handle_tab_completion(chan, buffer, vfs, cwd, prompt)
        
        # Assert: Completed to "system.log"
        self.assertEqual(new_buffer, "system.log")
        # Verify "tem.log" was sent
        chan.send.assert_called_with("tem.log")

    def test_single_match_middle_of_sentence(self):
        # Setup
        chan = MagicMock()
        buffer = "ls sys"
        vfs = {'/': ['system.log', 'other']}
        cwd = '/'
        prompt = "$ "
        
        # Action
        new_buffer = handle_tab_completion(chan, buffer, vfs, cwd, prompt)
        
        # Assert: Completed last word
        self.assertEqual(new_buffer, "ls system.log")
        chan.send.assert_called_with("tem.log")

    def test_multiple_matches_listing(self):
        # Setup
        chan = MagicMock()
        buffer = "te"
        vfs = {'/': ['test1', 'test2', 'other']}
        cwd = '/'
        prompt = "$ "
        
        # Action
        new_buffer = handle_tab_completion(chan, buffer, vfs, cwd, prompt)
        
        # Assert: Buffer unchanged
        self.assertEqual(new_buffer, "te")
        
        # Verify listing calls
        # We expect \r\n, list, \r\n, prompt, buffer
        calls = [c[0][0] for c in chan.send.call_args_list]
        self.assertIn(b'\r\n', calls)
        self.assertIn("test1  test2", calls) # Joined by double space
        self.assertIn(prompt, calls)
        self.assertIn(buffer, calls)

    def test_empty_buffer(self):
         # If buffer empty, we decided to handle it gracefully (maybe list all? current logic: prefix="")
         # prefix="" means matches ALL files
         chan = MagicMock()
         buffer = ""
         vfs = {'/': ['a', 'b']}
         cwd = '/'
         prompt = "$ "
         
         handle_tab_completion(chan, buffer, vfs, cwd, prompt)
         
         # Expect listing of 'a  b'
         calls = [c[0][0] for c in chan.send.call_args_list]
         self.assertIn("a  b", calls)

if __name__ == '__main__':
    unittest.main()
