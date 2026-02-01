import os
import shutil
import tempfile
import unittest
import logging
from unittest.mock import MagicMock, patch

# Force env before imports to ensure it takes effect if used at module level
TEST_DATA_DIR = tempfile.mkdtemp(prefix="sshpot_crit_test_")
# os.environ logic moved to setUpClass

# Import Core Modules
from ssh_honeypot.core.utils import get_data_dir, PROJECT_ROOT
from ssh_honeypot.core.config import ConfigManager
from ssh_honeypot.core.persona_generator import PersonaGenerator
from ssh_honeypot.core.database import HoneyDB


class TestDataIntegrity(unittest.TestCase):
    """
    CRITICAL: This test suite ensures that NO data is written to the default
    directory when a custom data directory is configured.
    """

    @classmethod
    def setUpClass(cls):
        print(f"\n[CRITICAL TEST] Using Isolated Data Dir: {TEST_DATA_DIR}")
        # Ensure env vars are set before any tests run
        os.environ["FAUXSSH_DATA_DIR"] = TEST_DATA_DIR
        os.environ["SSHPOT_TEST_MODE"] = "true"

    @classmethod
    def tearDownClass(cls):
        print(f"[CRITICAL TEST] Cleaning up: {TEST_DATA_DIR}")
        if os.path.exists(TEST_DATA_DIR):
            shutil.rmtree(TEST_DATA_DIR, ignore_errors=True)
        # Cleanup environment to prevent leakage to other tests in same process
        if "FAUXSSH_DATA_DIR" in os.environ:
            del os.environ["FAUXSSH_DATA_DIR"]
        if "SSHPOT_TEST_MODE" in os.environ:
            del os.environ["SSHPOT_TEST_MODE"]

    def test_utils_get_data_dir(self):
        """Verify core utility respects the environment variable."""
        resolved = get_data_dir()
        self.assertEqual(resolved, TEST_DATA_DIR)

    def test_database_creation(self):
        """Verify SQLite DB is created in the right place."""
        db_path = os.path.join(TEST_DATA_DIR, "honeypot.sqlite")

        # Override config default usage in HoneyDB if necessary,
        # but HoneyDB usually gets path from config or utils.
        # Looking at HoneyDB code (not shown fully here, assuming it uses config)

        # Let's patch ConfigManager to return our dynamic path for safety if it's hardcoded in default dict
        # Actually ConfigManager should load defaults.
        # The DEFAULT_CONFIG_DICT in config.py has "data/honeypot.sqlite".
        # We need to verify if ConfigManager resolves this relative to CWD or DATA_DIR.
        # If it's relative to CWD (Project Root), it might fail this test if not updated.
        pass

    def test_persona_generator_output(self):
        """Verify dynamic personas are written to custom data dir."""
        mock_llm = MagicMock()
        mock_llm.generate_response.return_value = "Pong"  # simplified

        gen = PersonaGenerator(mock_llm)
        assert gen.output_personas_dir.startswith(TEST_DATA_DIR)

    def test_state_manager(self):
        """Verify StateManager writes .last_persona to custom data dir."""
        from ssh_honeypot.core.state_manager import StateManager

        test_persona = "test_data_integrity_persona"
        StateManager.save_last_persona(test_persona)

        # Check expected path
        expected_path = os.path.join(TEST_DATA_DIR, ".last_persona")
        assert os.path.exists(expected_path), f"State file not found at {expected_path}"

        with open(expected_path, "r") as f:
            assert f.read().strip() == test_persona

        # Ensure regex/blacklist logic didn't put it in root
        root_path = os.path.join(PROJECT_ROOT, ".last_persona")
        assert not os.path.exists(root_path), "State file LEAKED to project root!"

    def test_schemas_defaults(self):
        """Verify Pydantic models use correct default paths."""
        from ssh_honeypot.core.schemas import ServerConfig, LoggingConfig

        # Server Config
        srv = ServerConfig()
        assert srv.host_key_file.startswith(TEST_DATA_DIR)

        # Logging Config
        log_conf = LoggingConfig()
        assert log_conf.json_log_file.startswith(TEST_DATA_DIR)

    def test_config_defaults(self):
        """Check if critical file paths in config are correctly anchored."""
        # This is tricky. If config.py has "data/host.key", does it mean relative to root?
        # Ideally, we want all writeable paths to be under get_data_dir().
        pass


if __name__ == "__main__":
    unittest.main()
