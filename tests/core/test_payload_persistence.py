import unittest
import os
import shutil
import tempfile
import sqlite3
from ssh_honeypot.core.database import SQLiteBackend
from ssh_honeypot.core.payload_manager import PayloadManager


class TestPayloadPersistence(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_db.sqlite")
        self.db = SQLiteBackend(self.db_path)
        self.pm = PayloadManager(self.db)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_queue_payload_persistence(self):
        url = "http://evil.com/test.sh"
        session_id = "test_session_123"
        ip = "1.2.3.4"

        # Queue payload
        self.pm.queue_payload(url, session_id, ip)

        # Verify in DB directly
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "SELECT status, url FROM malicious_payloads WHERE session_id=?",
            (session_id,),
        )
        row = c.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "pending")
        self.assertEqual(row[1], url)

    def test_duplicate_payload_ignored(self):
        url = "http://evil.com/dup.sh"
        self.pm.queue_payload(url, "s1", "1.1.1.1")
        # Try queue same URL again
        self.pm.queue_payload(url, "s2", "2.2.2.2")

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM malicious_payloads WHERE url=?", (url,))
        count = c.fetchone()[0]
        conn.close()

        # Should strictly be 1 because url_hash is unique
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
