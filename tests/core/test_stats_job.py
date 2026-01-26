import unittest
import os
import json
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.background_tasks import run_stats_generation_job


class TestStatsJob(unittest.TestCase):
    def setUp(self):
        from ssh_honeypot.core.utils import PROJECT_ROOT

        self.data_dir = os.path.join(PROJECT_ROOT, "data")
        self.data_path = os.path.join(self.data_dir, "status_data.json")
        if os.path.exists(self.data_path):
            os.remove(self.data_path)

    def tearDown(self):
        if os.path.exists(self.data_path):
            os.remove(self.data_path)

    @patch("ssh_honeypot.core.background_tasks.config")
    def test_run_stats_generation_job(self, mock_config):
        # Mock config to enable stats
        mock_config.get.side_effect = lambda *args, **kwargs: (
            True if args[0] == "http" and args[1] == "showstats" else "/var/www/html"
        )

        # Mock DB instance
        mock_db = MagicMock()
        mock_stats = {
            "total_ips": 10,
            "total_requests": 100,
            "total_sessions": 50,
            "top_ips": [{"ip": "1.2.3.4", "count": 5}],
            "top_requests": [],
            "top_countries": [],
            "top_isps": [],
            "service_dist": [],
            "longest_sessions": [],
            "manual_vs_bot": {"manual": 5, "bot": 45},
            "recent_unique_commands": ["ls", "whoami"],
        }
        mock_db.get_infographic_stats.return_value = mock_stats
        mock_db.get_daily_session_counts.return_value = [
            {"label": "Jan 21", "count": 10}
        ]
        mock_db.get_hourly_session_counts.return_value = [
            {"label": "12:00", "count": 5}
        ]

        # Run job
        run_stats_generation_job(mock_db)

        # Verify file creation
        self.assertTrue(
            os.path.exists(self.data_path), f"File should exist at {self.data_path}"
        )

        # Verify content
        with open(self.data_path, "r") as f:
            content = json.load(f)
            self.assertIn("windows", content)
            self.assertIn("1H", content["windows"])
            self.assertIn("1D", content["windows"])
            self.assertIn("1W", content["windows"])
            self.assertEqual(content["windows"]["1D"]["total_ips"], 10)
            self.assertEqual(content["windows"]["1D"]["manual_vs_bot"]["manual"], 5)
            self.assertIn("ls", content["windows"]["1D"]["recent_unique_commands"])
            self.assertIn("graphs", content)
            self.assertIn("hourly_24h", content["graphs"])
            self.assertIn("daily_7d", content["graphs"])
            self.assertIn("daily_21d", content["graphs"])

    @patch("ssh_honeypot.core.background_tasks.config")
    def test_run_stats_generation_job_disabled(self, mock_config):
        # Mock config to disable stats
        mock_config.get.return_value = False

        mock_db = MagicMock()
        run_stats_generation_job(mock_db)

        # Verify file NOT created
        self.assertFalse(os.path.exists(self.data_path))


if __name__ == "__main__":
    unittest.main()
