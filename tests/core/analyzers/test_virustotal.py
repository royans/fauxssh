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

    @patch("ssh_honeypot.core.database.get_db_backend")
    def test_startup_check_success(self, mock_db_getter):
        mock_db = MagicMock()
        mock_db.check_api_rate_limit.return_value = (True, "")
        mock_db_getter.return_value = mock_db

        analyzer = VirusTotalAnalyzer()

        # Mock the result stats
        mock_file_obj = MagicMock()
        mock_file_obj.last_analysis_stats = {"malicious": 1, "harmless": 20}
        self.mock_client.get_object.return_value = mock_file_obj

        self.assertTrue(analyzer.verify_auth_at_startup())
        self.mock_client.get_object.assert_called_once()
        mock_db.record_api_usage.assert_called_with("virustotal", "GLOBAL")

    @patch("ssh_honeypot.core.database.get_db_backend")
    def test_daily_limit(self, mock_db_getter):
        mock_db = MagicMock()
        mock_db.check_api_rate_limit.return_value = (False, "Daily limit reached")
        mock_db_getter.return_value = mock_db

        analyzer = VirusTotalAnalyzer()

        # Verification should fail due to limit
        self.assertFalse(analyzer.verify_auth_at_startup())

        # Scan should fail
        self.assertIsNone(analyzer.scan_file("foo"))

    def test_rate_limit_wait(self):
        analyzer = VirusTotalAnalyzer()
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

    @patch("ssh_honeypot.core.database.get_db_backend")
    def test_default_rpm_and_cleanup(self, mock_db_getter):
        mock_db = MagicMock()
        mock_db.check_api_rate_limit.return_value = (True, "")
        mock_db_getter.return_value = mock_db

        analyzer = VirusTotalAnalyzer()
        # Verify default is 15.0 (4 RPM)
        self.assertEqual(analyzer.min_delay, 15.0)

        # Verify verify_auth_at_startup updates last_request_time
        mock_file_obj = MagicMock()
        mock_file_obj.last_analysis_stats = {"malicious": 0, "harmless": 0}
        self.mock_client.get_object.return_value = mock_file_obj

        initial_time = analyzer.last_request_time
        analyzer.verify_auth_at_startup()
        self.assertNotEqual(analyzer.last_request_time, initial_time)
        self.assertAlmostEqual(analyzer.last_request_time, time.time(), delta=1.0)

        # Verify close()
        self.assertIsNotNone(analyzer.client)
        analyzer.close()
        self.assertIsNone(analyzer.client)


if __name__ == "__main__":
    unittest.main()
