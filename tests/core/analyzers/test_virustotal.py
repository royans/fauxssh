import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
import time
import json
from ssh_honeypot.core.analyzers.virustotal import VirusTotalAnalyzer


class TestVirusTotalAnalyzer(unittest.TestCase):
    def setUp(self):
        self.config_patcher = patch("ssh_honeypot.core.analyzers.virustotal.config")
        self.mock_config = self.config_patcher.start()
        self.mock_config.get.return_value = "dummy_key"

        self.vt_patcher = patch("ssh_honeypot.core.analyzers.virustotal.vt.Client")
        self.mock_client_cls = self.vt_patcher.start()
        self.mock_client = self.mock_client_cls.return_value

    def tearDown(self):
        self.config_patcher.stop()
        self.vt_patcher.stop()
        # Clean up usage file
        usage_file = os.path.join(os.getcwd(), "test_vt_usage.json")
        if os.path.exists(usage_file):
            os.remove(usage_file)

    @patch("ssh_honeypot.core.analyzers.virustotal.get_data_dir")
    def test_startup_check_success(self, mock_get_data_dir):
        mock_get_data_dir.return_value = os.getcwd()
        # Ensure separate usage file for test
        with patch.object(VirusTotalAnalyzer, "_load_usage") as mock_load:
            # We want to use real load usage logic but redirected path,
            # but modifying __init__ is hard.
            # Instead, we just let it use the mocked get_data_dir which points to cwd.
            pass

        analyzer = VirusTotalAnalyzer()
        analyzer.usage_file = "test_vt_usage.json"
        # Reset usage data
        analyzer.usage_data = {"date": "2024-01-01", "count": 0}

        # Mock the result stats
        mock_file_obj = MagicMock()
        mock_file_obj.last_analysis_stats = {"malicious": 1, "harmless": 20}
        self.mock_client.get_object.return_value = mock_file_obj

        self.assertTrue(analyzer.verify_auth_at_startup())
        self.mock_client.get_object.assert_called_once()
        # Should increment count
        self.assertEqual(analyzer.usage_data["count"], 1)

    @patch("ssh_honeypot.core.analyzers.virustotal.get_data_dir")
    def test_daily_limit(self, mock_get_data_dir):
        mock_get_data_dir.return_value = os.getcwd()
        analyzer = VirusTotalAnalyzer()
        analyzer.usage_file = "test_vt_usage.json"

        # Simulate limit reached
        import datetime

        analyzer.usage_data = {"date": str(datetime.date.today()), "count": 450}

        # Verification should fail due to limit
        self.assertFalse(analyzer.verify_auth_at_startup())

        # Scan should fail
        self.assertIsNone(analyzer.scan_file("foo"))

    @patch("ssh_honeypot.core.analyzers.virustotal.get_data_dir")
    def test_rate_limit_wait(self, mock_get_data_dir):
        mock_get_data_dir.return_value = os.getcwd()
        analyzer = VirusTotalAnalyzer()
        analyzer.usage_file = "test_vt_usage.json"
        analyzer.min_delay = 0.5  # Shorten for test

        start = time.time()
        analyzer._wait_for_rate_limit()  # First call immediate
        self.assertTrue(time.time() - start < 0.1)

        # Simulate recent request by manually setting last time
        analyzer.last_request_time = time.time()
        start = time.time()
        analyzer._wait_for_rate_limit()
        elapsed = time.time() - start
        self.assertTrue(elapsed >= 0.45, f"Should wait approx 0.5s, waited {elapsed}s")


if __name__ == "__main__":
    unittest.main()
