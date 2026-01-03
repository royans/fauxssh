import unittest
from unittest.mock import MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.command_handler import CommandHandler

class TestEchoRedirect(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        self.handler = CommandHandler(self.mock_llm, self.mock_db)
        self.context = {
            'cwd': '/home/test',
            'client_ip': '1.2.3.4',
            'user': 'testuser'
        }

    def test_echo_redirect(self):
        # Current bad behavior: returns "hello > file"
        # Desired behavior: returns "", updates file
        cmd = 'echo "hello" > outfile.txt'
        out, updates, meta = self.handler.process_command(cmd, self.context)
        
        print(f"DEBUG OUTPUT: '{out}'")
        print(f"DEBUG UPDATES: {updates}")
        
        # If redirection works, out should be empty (or newline) and file_modifications should exist
        # If it fails (current state), out will contain "> outfile.txt"
        
        if "> outfile.txt" in out:
            print("FAIL: output contains redirection usage, means it was echoed literally.")
        else:
            print("SUCCESS: output does NOT contain redirection usage.")

        # Test 2: Cat Empty File
        # Now verify that cat returns empty string without calling LLM (mock llm should not be called if logic is correct)
        # Reset mock
        self.mock_llm.generate_response.reset_mock()
        
        # We need to simulate that the file exists in DB (Process command redirection should have added it, 
        # but since we use mocked DB in test, process_command calls mocked db.update_user_file).
        # We need to ensure subsequent handle_cat calls db.get_user_node and finds it.
        
        # Mocking get_user_node to return the file we just 'created'
        self.mock_db.get_user_node.return_value = {'type': 'file', 'content': '', 'size': 0}
        
        out_cat, updates_cat, meta_cat = self.handler.process_command("cat outfile.txt", self.context)
        
        if out_cat.strip() == "":
             print("SUCCESS: cat returned empty string.")
        else:
             print(f"FAIL: cat returned '{out_cat}'")
             
        # Verify LLM was NOT called
        if self.mock_llm.generate_response.called:
             print("FAIL: LLM was called for empty file.")
        else:
             print("SUCCESS: LLM was NOT called.")

if __name__ == '__main__':
    unittest.main()
