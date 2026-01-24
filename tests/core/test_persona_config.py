import pytest
from unittest.mock import MagicMock, patch
import os
from ssh_honeypot.core.config import ConfigManager


class TestPersonaConfig:

    @pytest.fixture
    def config_mgr(self):
        # We need to initialize ConfigManager without triggering real loads
        # Using patch to prevent __init__ side effects if needed,
        # but ConfigManager.__init__ does real work.
        # Ideally we test load_persona in isolation.

        # Backup env
        old_env = os.environ.get("SSH_PERSONA")
        if old_env:
            del os.environ["SSH_PERSONA"]

        yield ConfigManager()

        # Restore env
        if old_env:
            os.environ["SSH_PERSONA"] = old_env
        else:
            if "SSH_PERSONA" in os.environ:
                del os.environ["SSH_PERSONA"]

    def test_load_persona_default(self, config_mgr):
        # Ensure StateManager returns None
        with patch(
            "ssh_honeypot.core.state_manager.StateManager.get_last_persona",
            return_value=None,
        ):
            with patch.object(config_mgr, "_read_persona_file") as mock_read:
                # Mock base read
                mock_read.side_effect = lambda name, _: (
                    {"name": name} if name == "CentOS7_Legacy_Compute" else None
                )

                config_mgr.load_persona(None)

                # Should hit base
                assert config_mgr.get("persona", "name") == "CentOS7_Legacy_Compute"

    def test_load_persona_override(self, config_mgr):
        # 1. Override > Env > State
        with patch(
            "ssh_honeypot.core.state_manager.StateManager.get_last_persona",
            return_value="state_p",
        ):
            os.environ["SSH_PERSONA"] = "env_p"

            with patch.object(config_mgr, "_read_persona_file") as mock_read:
                # Setup mocks for all potential personas
                mock_read.side_effect = lambda name, _: {"name": name}

                # explicit override
                config_mgr.load_persona("cli_override")

                assert config_mgr.get("persona", "name") == "cli_override"

    def test_load_persona_env(self, config_mgr):
        # 2. Env > State
        with patch(
            "ssh_honeypot.core.state_manager.StateManager.get_last_persona",
            return_value="state_p",
        ):
            os.environ["SSH_PERSONA"] = "env_p"

            with patch.object(config_mgr, "_read_persona_file") as mock_read:
                mock_read.side_effect = lambda name, _: {"name": name}

                config_mgr.load_persona(None)

                assert config_mgr.get("persona", "name") == "env_p"

    def test_load_persona_state(self, config_mgr):
        # 3. State > Default
        with patch(
            "ssh_honeypot.core.state_manager.StateManager.get_last_persona",
            return_value="state_p",
        ):
            # Ensure env is empty
            if "SSH_PERSONA" in os.environ:
                del os.environ["SSH_PERSONA"]

            with patch.object(config_mgr, "_read_persona_file") as mock_read:
                mock_read.side_effect = lambda name, _: {"name": name}

                config_mgr.load_persona(None)

                assert config_mgr.get("persona", "name") == "state_p"

    def test_read_persona_file_paths(self, config_mgr):
        # Test the multi-path lookup logic in _read_persona_file
        # We need to mock os.path.exists and open/yaml.load

        with (
            patch("os.path.exists") as mock_exists,
            patch("builtins.open", new_callable=MagicMock) as mock_open,
            patch("yaml.safe_load") as mock_yaml,
        ):

            # Setup
            mock_yaml.return_value = {"system": {"hostname": "found"}}

            # Scenario 1: Found in source/personas (Base)
            # search_dirs = [personas, data/personas]
            # check: personas/MyBase/persona.yaml -> True

            def side_effect_exists(path):
                if "personas/MyBase/persona.yaml" in path and "data" not in path:
                    return True
                return False

            mock_exists.side_effect = side_effect_exists

            result = config_mgr._read_persona_file("MyBase")
            assert result is not None
            assert result["system"]["hostname"] == "found"

            # Scenario 2: Found in data/personas (Dynamic)
            def side_effect_exists_data(path):
                # Match the component regardless of absolute prefix
                if "personas/MyDynamic/persona.yaml" in path:
                    return True
                return False

            mock_exists.side_effect = side_effect_exists_data

            result = config_mgr._read_persona_file("MyDynamic")
            assert result is not None
            # Check suffix to be robust
            assert result["_fs_path"].endswith("personas/MyDynamic/fs")

            # Scenario 3: Not found
            mock_exists.return_value = False
            result = config_mgr._read_persona_file("Ghost")
            assert result is None
