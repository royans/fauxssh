import unittest
import os
import sqlite3
import json
from datetime import datetime, timedelta
from ssh_honeypot.core.database import SQLiteBackend


class TestStatsInfographic(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_stats_infographic.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.db = SQLiteBackend(self.db_path)
        self._populate_data()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _populate_data(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Insert intelligence for one IP
        c.execute(
            "INSERT INTO ip_intelligence (ip, country, isp, org, enriched) VALUES (?, ?, ?, ?, ?)",
            ("1.2.3.4", "USA", "TestISP", "TestORG", 1),
        )

        # Insert sessions
        # 1. Recent session (Bot)
        c.execute(
            "INSERT INTO sessions (session_id, remote_ip, start_time, end_time, protocol, summary) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "s1",
                "1.2.3.4",
                (datetime.now() - timedelta(hours=1)).isoformat(),
                (datetime.now() - timedelta(minutes=50)).isoformat(),
                "ssh",
                "Automated bot session",
            ),
        )
        c.execute(
            "INSERT INTO interactions (session_id, command, timestamp) VALUES (?, ?, ?)",
            ("s1", "ls", (datetime.now() - timedelta(minutes=55)).isoformat()),
        )

        # 2. Recent session (Manual)
        c.execute(
            "INSERT INTO sessions (session_id, remote_ip, start_time, end_time, protocol, summary) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "s2",
                "5.6.7.8",
                (datetime.now() - timedelta(hours=2)).isoformat(),
                (datetime.now() - timedelta(minutes=10)).isoformat(),
                "http",
                "Manual operator detected",
            ),
        )
        for i in range(15):
            c.execute(
                "INSERT INTO interactions (session_id, command, timestamp) VALUES (?, ?, ?)",
                (
                    "s2",
                    f"cmd_{i}",
                    (datetime.now() - timedelta(minutes=100 - i)).isoformat(),
                ),
            )

        # 3. Old session (ignored by 24h filter)
        c.execute(
            "INSERT INTO sessions (session_id, remote_ip, start_time, end_time, protocol) VALUES (?, ?, ?, ?, ?)",
            (
                "s3",
                "9.9.9.9",
                (datetime.now() - timedelta(days=2)).isoformat(),
                (datetime.now() - timedelta(days=2, hours=1)).isoformat(),
                "ssh",
            ),
        )

        conn.commit()
        conn.close()

    def test_get_infographic_stats(self):
        stats = self.db.get_infographic_stats(hours=24)

        self.assertEqual(stats["total_ips"], 2)  # 1.2.3.4 and 5.6.7.8
        self.assertEqual(stats["total_sessions"], 2)  # s1 and s2
        self.assertEqual(stats["total_requests"], 16)  # 1 from s1, 15 from s2

        self.assertEqual(
            stats["manual_vs_bot"]["manual"], 1
        )  # s2 (15 commands + manual summary)
        self.assertEqual(stats["manual_vs_bot"]["bot"], 1)  # s1

        self.assertTrue(
            any(item["country"] == "USA" for item in stats["top_countries"])
        )
        self.assertTrue(any(item["isp"] == "TestORG" for item in stats["top_isps"]))

        # Unique command check
        self.assertIn("ls", stats["recent_unique_commands"])


if __name__ == "__main__":
    unittest.main()
