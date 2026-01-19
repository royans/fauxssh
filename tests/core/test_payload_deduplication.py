import unittest
import tempfile
import shutil
import os
import sqlite3
from ssh_honeypot.core.database import SQLiteBackend
from ssh_honeypot.core.payload_manager import PayloadManager


class TestPayloadDeduplication(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_db.sqlite")
        self.db = SQLiteBackend(self.db_path)
        self.pm = PayloadManager(self.db)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_deduplication_queued_status(self):
        url = "http://bad.com/malware.exe"

        # 1. Queue first time
        self.pm.queue_payload(url, "session1", "1.1.1.1")

        # Check count
        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM malicious_payloads").fetchone()[0]
        self.assertEqual(count, 1, "Should have 1 record")

        # 2. Queue second time
        self.pm.queue_payload(url, "session2", "2.2.2.2")

        count = conn.execute("SELECT COUNT(*) FROM malicious_payloads").fetchone()[0]
        self.assertEqual(count, 1, "Should still have 1 record (deduplicated)")
        conn.close()

    def test_deduplication_downloading_status(self):
        url = "http://bad.com/active.exe"
        self.pm.queue_payload(url, "session1", "1.1.1.1")

        # Manually set status to downloading to simulate active process
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE malicious_payloads SET status='downloading' WHERE url=?", (url,)
        )
        conn.commit()
        conn.close()

        # Try queue again
        self.pm.queue_payload(url, "session3", "3.3.3.3")

        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM malicious_payloads").fetchone()[0]
        self.assertEqual(count, 1, "Should not add new record even if downloading")

        # Verify status wasn't reset
        status = conn.execute(
            "SELECT status FROM malicious_payloads WHERE url=?", (url,)
        ).fetchone()[0]
        self.assertEqual(status, "downloading")
        conn.close()


if __name__ == "__main__":
    unittest.main()
