import os
import unittest
from unittest.mock import patch, MagicMock
from ssh_honeypot.core.config import ConfigManager


class TestConfigLoading(unittest.TestCase):

    def test_fallback_to_project_root(self):
        """
        Test that ConfigManager looks in PROJECT_ROOT if config.yaml is missing in CWD.
        """

        # Define mock side effects
        def exists_side_effect(path):
            if path == "config.yaml":
                return False
            if path == "/mock/project/root/config.yaml":
                return True
            return False

        # Use context managers to strictly control mock scope and naming
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("ssh_honeypot.core.config.load_dotenv") as mock_dotenv,
            patch("ssh_honeypot.core.config.PROJECT_ROOT", "/mock/project/root"),
            patch(
                "ssh_honeypot.core.config.os.path.exists",
                side_effect=exists_side_effect,
            ) as mock_exists,
            patch(
                "ssh_honeypot.core.config.yaml.safe_load",
                return_value={"database": {"type": "yaml_db"}},
            ) as mock_yaml,
            patch(
                "ssh_honeypot.core.config.open",
                new_callable=unittest.mock.mock_open,
                read_data="database:\n  type: yaml_db",
            ) as mock_open,
        ):

            # Action
            cm = ConfigManager()

            # Assertions
            # It should have tried to open the fallback path
            mock_open.assert_any_call("/mock/project/root/config.yaml", "r")

            # The config should reflect what was loaded
            self.assertEqual(cm.get("database", "type"), "yaml_db")

    def test_default_config_has_database(self):
        """
        Test that DEFAULT_CONFIG_DICT includes database section so env overrides work
        even if NO config file is found.
        """
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("ssh_honeypot.core.config.load_dotenv"),
            patch("ssh_honeypot.core.config.PROJECT_ROOT", "/mock/project/root"),
            patch(
                "ssh_honeypot.core.config.os.path.exists", return_value=False
            ) as mock_exists,
        ):

            cm = ConfigManager()

            # Should default to sqlite
            self.assertEqual(cm.get("database", "type"), "sqlite")

            # And structure should exist to support overrides
            self.assertIn("postgres", cm.get("database"))

    @patch.dict(
        os.environ, {"DATABASE_TYPE": "postgres", "DATABASE_POSTGRES_HOST": "10.0.0.1"}
    )
    def test_env_override_priority(self):
        """
        Test that Environment variables override loaded config.
        """
        # Even with no file (using defaults), Env var should win
        cm = ConfigManager()

        self.assertEqual(cm.get("database", "type"), "postgres")
        self.assertEqual(cm.get("database", "postgres", "host"), "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
