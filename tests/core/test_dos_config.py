import unittest
import os
from unittest.mock import patch, MagicMock
from ssh_honeypot.core.dos_protection import DoSProtector


class TestDoSConfigIntegration(unittest.TestCase):
    def test_dos_protector_uses_default_limit(self):
        """
        Verify that DoSProtector currently uses the hardcoded default (1000)
        instead of the config value (60), confirming the bug.
        """
        # Initialize without arguments, should use default=1000
        protector = DoSProtector()
        self.assertEqual(
            protector.limit_rpm, 1000, "DoSProtector should default to 1000 RPM"
        )

    @patch("ssh_honeypot.core.config.config.get")
    def test_dos_protector_ignores_config(self, mock_get):
        """
        Demonstrate that even if config is available, the global instance
        (instantiated at import time usually) or new instances don't check config
        unless explicitly passed, or we fix the class.
        """
        # Current behavior: It doesn't look at config inside __init__
        # It expects args.
        protector = DoSProtector()
        # This test passes if it ignores config (current buggy state)
        self.assertEqual(protector.limit_rpm, 1000)


if __name__ == "__main__":
    unittest.main()
