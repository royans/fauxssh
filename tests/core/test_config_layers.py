import unittest
import os
from unittest.mock import patch
from ssh_honeypot.core.config import config, ConfigManager


class TestConfigLayers(unittest.TestCase):
    def setUp(self):
        # Reset config to a known state or use a fresh instance logic if possible
        # Config is a singleton instance, so we rely on mocking 'get' or internal dict
        pass

    def test_default_values(self):
        """Test fallback to hardcoded defaults when no config is present."""
        # Mock get to return None (missing config)
        with patch.object(config, "get", return_value=None):
            # Default LLM RPM is 5 (from config.py fallback)
            val = config.get_rate_limit("ssh", "llm", "rpm")
            self.assertEqual(val, 5, "Should use Default (5)")

    def test_global_override(self):
        """Test that global throttling section overrides default."""

        def mock_get_side_effect(*args):
            # Return Global Throttling value
            if args == ("throttling", "llm", "rpm"):
                return 50
            return None

        with patch.object(config, "get", side_effect=mock_get_side_effect):
            val = config.get_rate_limit("ssh", "llm", "rpm")
            self.assertEqual(val, 50, "Should use Global Override (50)")

    def test_service_override(self):
        """Test that service-specific config overrides global and default."""

        def mock_get_side_effect(*args):
            # Service specific: get_rate_limit calls self.get(service, "throttling")
            # It expects a dict back to then do .get("llm_rpm")
            if args == ("ssh", "throttling"):
                return {"llm_rpm": 999}

            # Global: calls self.get("throttling", type, metric)
            if args == ("throttling", "llm", "rpm"):
                return 50
            return None

        with patch.object(config, "get", side_effect=mock_get_side_effect):
            val = config.get_rate_limit("ssh", "llm", "rpm")
            # Note: get_rate_limit looks for service specific key: e.g. "ssh.throttling.llm_rpm"
            # actually logic in config.py is: self.get(service, "throttling", f"{type_}_{metric}")
            self.assertEqual(val, 999, "Should use Service Override (999)")


if __name__ == "__main__":
    unittest.main()
