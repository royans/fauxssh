import unittest
import os
from unittest.mock import patch
from ssh_honeypot.core.config import ConfigManager, DEFAULT_CONFIG_DICT


class TestConfigEnv(unittest.TestCase):
    def setUp(self):
        # Reset environment
        self.patcher = patch.dict(os.environ, {}, clear=True)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_recursive_env_override(self):
        """Test that ENV_VAR overrides section.key"""
        # Set Env Vars
        os.environ["LLM_MODEL_NAME"] = "env-override-model"
        os.environ["HTTP_PORT"] = "9999"  # Int
        os.environ["VIRUSTOTAL_ENABLED"] = "true"  # Bool
        os.environ["ANALYTICS_IGNORE_IPS"] = "1.1.1.1, 2.2.2.2"  # List

        # Initialize Config (mocking load_config_file to not read disk)
        with (
            patch.object(ConfigManager, "load_config_file"),
            patch.object(ConfigManager, "_load_env"),
        ):
            # We also need to mock _read_persona_file or it might fail if defaults used
            with patch.object(ConfigManager, "load_persona"):
                cfg = ConfigManager()

        # Check Overrides
        # 1. String
        self.assertEqual(cfg.get("llm", "model_name"), "env-override-model")

        # 2. Integer (Auto-cast)
        self.assertEqual(cfg.get("http", "port"), 9999)
        self.assertIsInstance(cfg.get("http", "port"), int)

        # 3. Boolean
        self.assertTrue(cfg.get("virustotal", "enabled"))

        # 4. List
        expected_ips = ["1.1.1.1", "2.2.2.2"]
        self.assertEqual(cfg.get("analytics", "ignore_ips"), expected_ips)

    def test_legacy_mapping(self):
        """Test backward compatibility mappings"""
        os.environ["GOOGLE_API_KEY"] = "legacy_key"

        with (
            patch.object(ConfigManager, "load_config_file"),
            patch.object(ConfigManager, "load_persona"),
            patch.object(ConfigManager, "_load_env"),
        ):
            cfg = ConfigManager()

        self.assertEqual(cfg.get("llm", "api_key"), "legacy_key")

    def test_nested_throttling(self):
        """Test THROTTLING_DOS_RPM maps to throttling.dos.rpm"""
        os.environ["THROTTLING_DOS_RPM"] = "555"

        with (
            patch.object(ConfigManager, "load_config_file"),
            patch.object(ConfigManager, "load_persona"),
            patch.object(ConfigManager, "_load_env"),
        ):
            cfg = ConfigManager()

        self.assertEqual(cfg.get("throttling", "dos", "rpm"), 555)


if __name__ == "__main__":
    unittest.main()
