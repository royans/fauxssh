import os
import json
import time
import unittest
import pytest
from unittest.mock import patch, MagicMock
from ssh_honeypot.core.dos_protection import DoSProtector


class TestDoSProtectionIgnored(unittest.TestCase):
    def setUp(self):
        self.ban_file = "banned_ips.json"  # Use the actual file name used by DoSProtector with mock_dir="."
        if os.path.exists(self.ban_file):
            os.remove(self.ban_file)
        if os.path.exists("test_banned_ips.json"):
            os.remove("test_banned_ips.json")

        # Clear leaked environment variables
        if "ANALYTICS_IGNORE_IPS" in os.environ:
            del os.environ["ANALYTICS_IGNORE_IPS"]

    def tearDown(self):
        if os.path.exists(self.ban_file):
            os.remove(self.ban_file)
        if os.path.exists("test_banned_ips.json"):
            os.remove("test_banned_ips.json")
        if "ANALYTICS_IGNORE_IPS" in os.environ:
            del os.environ["ANALYTICS_IGNORE_IPS"]

    @patch("ssh_honeypot.core.dos_protection.get_data_dir")
    @patch("ssh_honeypot.core.utils.get_ignored_ips")
    def test_ignored_ip_not_banned(self, mock_get_ignores, mock_get_data_dir):
        # Mock the utility function directly to return the IP
        # AND set env var as backup/verification
        mock_get_ignores.return_value = ["1.2.3.4"]
        os.environ["ANALYTICS_IGNORE_IPS"] = "1.2.3.4"

        mock_get_data_dir.return_value = "."

        try:
            protector = DoSProtector(limit_rpm=2)

            # 1.2.3.4 should NEVER be banned
            for _ in range(10):
                self.assertTrue(
                    protector.is_allowed("1.2.3.4"), "Ignored IP 1.2.3.4 was banned!"
                )

            # 5.6.7.8 SHOULD be banned
            self.assertTrue(protector.is_allowed("5.6.7.8"))
            self.assertTrue(protector.is_allowed("5.6.7.8"))
            self.assertFalse(protector.is_allowed("5.6.7.8"))
        finally:
            pass

    @patch("ssh_honeypot.core.dos_protection.get_data_dir")
    @patch("ssh_honeypot.core.utils.get_ignored_ips")
    def test_startup_pruning(self, mock_get_ignores, mock_get_data_dir):
        # 1. Setup
        mock_get_ignores.return_value = ["1.2.3.4"]
        mock_get_data_dir.return_value = "."

        # 2. Pre-create a ban file with 1.2.3.4 banned
        ban_data = {"1.2.3.4": time.time() + 3600, "5.6.7.8": time.time() + 3600}
        with open("banned_ips.json", "w") as f:
            json.dump(ban_data, f)

        try:
            # 3. New protector should prune 1.2.3.4
            protector = DoSProtector(limit_rpm=10)

            # 1.2.3.4 should be allowed despite being in file
            self.assertTrue(protector.is_allowed("1.2.3.4"))

            # 5.6.7.8 should still be banned
            self.assertFalse(protector.is_allowed("5.6.7.8"))

            # Verify file was updated (pruned)
            with open("banned_ips.json", "r") as f:
                new_data = json.load(f)
                self.assertNotIn("1.2.3.4", new_data)
                self.assertIn("5.6.7.8", new_data)

        finally:
            if os.path.exists("banned_ips.json"):
                os.remove("banned_ips.json")


if __name__ == "__main__":
    unittest.main()
