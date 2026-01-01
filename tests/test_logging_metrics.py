
import unittest
from unittest.mock import MagicMock, patch
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.honey_db import HoneyDB

class TestLoggingMetrics(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_metrics.sqlite"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.json_path = "test_metrics.json.log"
        if os.path.exists(self.json_path):
            os.remove(self.json_path)
            
        self.db = HoneyDB(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        if os.path.exists(self.json_path):
            os.remove(self.json_path)

    def test_log_interaction_includes_metrics(self):
        # Log an interaction with metrics
        self.db.log_interaction(
            session_id="sess123",
            cwd="/root",
            command="ls -la",
            response="total 0",
            duration_ms=123.45,
            request_md5="deadbeef"
        )
        
        # Verify JSON content
        with open(self.json_path, 'r') as f:
            line = f.readline()
            data = json.loads(line)
            
        self.assertEqual(data["response_time_ms"], 123.45)
        self.assertEqual(data["request_md5"], "deadbeef")
        self.assertEqual(data["command"], "ls -la")

if __name__ == "__main__":
    unittest.main()
