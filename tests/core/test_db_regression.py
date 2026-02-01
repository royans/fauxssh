import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.database import HoneyDB


class TestDBSafetyRegression(unittest.TestCase):
    @patch("ssh_honeypot.core.database.HoneyDB._init_db")
    @patch("ssh_honeypot.core.database.sqlite3.connect")
    def test_log_auth_event_closes_connection_on_error(self, mock_connect, mock_init):
        """
        Regression Test: Ensure conn.close() is called even if execute raises an error.
        Fixes 'database is locked' zombie connections.
        """
        # Setup Mock
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        # Force an error during execution
        mock_cursor.execute.side_effect = Exception("DB Error Simulation")

        db = HoneyDB()
        # Suppress error log
        with patch("ssh_honeypot.core.database.log"):
            db.log_auth_event("1.2.3.4", "root", "password", "123456", False, "SSH-2.0")

        # Verification
        mock_conn.close.assert_called_once()

    @patch("ssh_honeypot.core.database.HoneyDB._init_db")
    @patch("ssh_honeypot.core.database.HoneyDB._get_conn")
    def test_start_session_closes_connection_on_error(self, mock_get_conn, mock_init):
        """
        Regression Test: Ensure conn.close() is called in start_session on error.
        """
        mock_conn = MagicMock()
        mock_get_conn.return_value = mock_conn

        # Force an error
        mock_conn.execute.side_effect = Exception("Insert Error")

        db = HoneyDB()
        with patch("ssh_honeypot.core.database.log"):
            db.start_session("sess1", "1.2.3.4", "root", "pass", "client")

        mock_conn.close.assert_called_once()

    @patch("ssh_honeypot.core.database.sqlite3")
    def test_wal_optimizations_applied(self, mock_sqlite):
        """
        Regression Test: Ensure PRAGMA synchronous = NORMAL and busy_timeout are set.
        """
        mock_conn = MagicMock()
        mock_sqlite.connect.return_value = mock_conn

        db = HoneyDB()

        # Check for specific calls
        # We expect: journal_mode=WAL, synchronous=NORMAL, busy_timeout=30000
        # The order might vary, but they should be called.

        calls = [tuple(c[0]) for c in mock_conn.execute.call_args_list]
        statements = [str(c[0]) for c in calls if len(c) > 0]

        journal_wal = any("PRAGMA journal_mode=WAL" in s for s in statements)
        sync_normal = any("PRAGMA synchronous = NORMAL" in s for s in statements)
        busy_timeout = any("PRAGMA busy_timeout = 30000" in s for s in statements)

        self.assertTrue(journal_wal, "Must enable WAL mode")
        self.assertTrue(sync_normal, "Must set synchronous=NORMAL for perf")
        self.assertTrue(busy_timeout, "Must set busy_timeout for concurrency")

    @patch("ssh_honeypot.core.database.sqlite3.connect")
    def test_get_max_interaction_id(self, mock_connect):
        """
        Regression Test: Ensure get_max_interaction_id works and handles None.
        Fixes AttributeError in background tasks.
        """
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor

        db = HoneyDB()

        # Case 1: Database returns a value (e.g. 42)
        mock_cursor.fetchone.return_value = (42,)
        self.assertEqual(db.get_max_interaction_id(), 42)

        # Case 2: Database returns None (empty table)
        mock_cursor.fetchone.return_value = (None,)
        self.assertEqual(db.get_max_interaction_id(), 0)

        # Case 3: Exception handling (should return 0)
        mock_cursor.execute.side_effect = Exception("DB Error")
        self.assertEqual(db.get_max_interaction_id(), 0)


if __name__ == "__main__":
    unittest.main()
