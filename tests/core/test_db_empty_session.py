import unittest
import os
import shutil
import tempfile
from ssh_honeypot.core.database import HoneyDB


class TestDBEmptySession(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test.sqlite")
        self.db = HoneyDB(self.db_path)
        # Default behavior: log_empty = false
        if "FAUXSSH_LOG_EMPTY_SESSIONS" in os.environ:
            del os.environ["FAUXSSH_LOG_EMPTY_SESSIONS"]

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_delete_empty_session(self):
        sid = "sess_empty_123"
        self.db.start_session(sid, "1.2.3.4", "root", "toor", "SSH-2.0-Test")
        # No interactions
        self.db.end_session(sid)

        # Verify deletion
        conn = self.db._get_conn()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sessions WHERE session_id = ?", (sid,))
        count = c.fetchone()[0]
        conn.close()
        self.assertEqual(count, 0, "Empty session should be deleted")

    def test_keep_active_session(self):
        sid = "sess_active_123"
        self.db.start_session(sid, "1.2.3.4", "root", "toor", "SSH-2.0-Test")
        # Add interaction
        self.db.log_interaction(sid, "/root", "ls", "file.txt")
        self.db.end_session(sid)

        # Verify retention
        conn = self.db._get_conn()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sessions WHERE session_id = ?", (sid,))
        count = c.fetchone()[0]
        conn.close()
        self.assertEqual(count, 1, "Active session should be kept")

    def test_keep_empty_if_config_set(self):
        os.environ["FAUXSSH_LOG_EMPTY_SESSIONS"] = "true"
        sid = "sess_keep_empty"
        self.db.start_session(sid, "1.2.3.4", "root", "toor", "SSH-2.0-Test")
        self.db.end_session(sid)

        conn = self.db._get_conn()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM sessions WHERE session_id = ?", (sid,))
        count = c.fetchone()[0]
        conn.close()
        self.assertEqual(count, 1, "Empty session should be kept if config is true")


if __name__ == "__main__":
    unittest.main()
