
import unittest
import os
import sys
# Ensure we can import the module from root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from unittest.mock import patch, MagicMock
from ssh_honeypot.core.config import ConfigManager

class TestConfigRateLimits(unittest.TestCase):
    def test_default_rate_limits(self):
        """Verify default RPM/RPD values are loaded when no config/env exists."""
        # Mock os.path.exists to ignore config.yaml
        with patch('os.path.exists', return_value=False):
            # Clean init without env vars
            with patch.dict(os.environ, {}, clear=True):
                cfg = ConfigManager(config_path="nonexistent.yaml")
                self.assertEqual(cfg.get('http', 'llm_rpm'), 4)
                self.assertEqual(cfg.get('http', 'llm_rpd'), 20)

    def test_env_override_rate_limits(self):
        """Verify ENV vars override defaults correctly."""
        env_vars = {
            'HTTP_LLM_RPM': '10',
            'HTTP_LLM_RPD': '100'
        }
        with patch.dict(os.environ, env_vars):
            # We don't care about file loading for this test, ENV overrides everything
            cfg = ConfigManager()
            self.assertEqual(cfg.get('http', 'llm_rpm'), 10)
            self.assertEqual(cfg.get('http', 'llm_rpd'), 100)

if __name__ == '__main__':
    unittest.main()
