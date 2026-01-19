import pytest
from unittest.mock import MagicMock, patch
import os
import shutil
import yaml
from ssh_honeypot.core.persona_generator import PersonaGenerator
from ssh_honeypot.core.state_manager import StateManager
from ssh_honeypot.core.utils import PROJECT_ROOT, get_data_dir


class TestPersonaGenerator:

    @pytest.fixture
    def setup_generator(self):
        self.mock_llm = MagicMock()
        self.generator = PersonaGenerator(self.mock_llm)
        self.generated_personas = []

        # Ensure base persona mock existence if needed, but integration relies on real files.
        # Assuming CentOS7 exists. If not, this test assumes valid env.

        yield

        # Teardown
        for p in self.generated_personas:
            p_path = os.path.join(get_data_dir(), "personas", p)
            if os.path.exists(p_path) and "dynamic_" in p:
                shutil.rmtree(p_path)

        if os.path.exists(".last_persona"):
            os.remove(".last_persona")

    def test_generate_persona_success(self, setup_generator):
        desc = "A secure vault for Area 51"

        # Mocks
        # Mocks
        analysis_json = """{
            "system": {
                 "hostname": "area51-gateway",
                 "distro_name": "Ubuntu",
                 "distro_version": "22.04"
            },
            "network": {
                 "ssh_banner": "SSH-2.0-OpenSSH_New",
                 "interfaces": {"eth0": "10.0.0.100"}
            },
            "hardware": {
                 "cpu_info": "4 vCPU",
                 "memory": "16GB",
                 "swap": "0",
                 "disk_info": "500GB SSD"
            },
            "services": {
                 "running_processes": ["nginx", "mysqld"],
                 "patch_status": "Critical CVE-2024-9999 unpatched"
            },
            "prompt_context": "You are a classified gateway server.",
            "suggested_files": [
                {"path": "/opt/secrets.txt", "type": "file", "description": "secrets"}
            ]
        }"""

        # LLM Side Effects: 1. Ping->Pong, 2. Analysis->JSON, 3. File->Content
        self.mock_llm.generate_response.side_effect = [
            "Pong",
            analysis_json,
            "TOP SECRET DATA",
        ]

        # Action
        new_persona = self.generator.generate_persona(desc)
        self.generated_personas.append(new_persona)

        # Assertions
        assert new_persona.startswith("dynamic_")

        # 1. Check Directory
        p_path = os.path.join(get_data_dir(), "personas", new_persona)
        assert os.path.exists(p_path)

        # 2. Check YAML Config
        yaml_path = os.path.join(p_path, "persona.yaml")
        with open(yaml_path, "r") as f:
            config = yaml.safe_load(f)

        assert config["system"]["hostname"] == "area51-gateway"
        assert "Dynamic: " + desc in config["description"]
        assert "DYNAMIC IDENTITY" in config["prompts"]["system_prompt"]
        assert "HARDWARE" in config["prompts"]["system_prompt"]
        assert "16GB" in config["prompts"]["system_prompt"]
        assert "500GB SSD" in config["prompts"]["system_prompt"]
        assert "RUNNING SERVICES" in config["prompts"]["system_prompt"]
        assert "security posture" in config["prompts"]["system_prompt"].lower()

        assert config["network"]["interfaces"]["eth0"] == "10.0.0.100"

        # 3. Check Generated File
        file_path = os.path.join(p_path, "fs", "opt/secrets.txt")
        assert os.path.exists(file_path)
        with open(file_path, "r") as f:
            assert f.read() == "TOP SECRET DATA"

        # 4. Check State Manager
        assert StateManager.get_last_persona() == new_persona

        # 5. Check Filesystem Config Enforcement (USER mapping)
        assert config["filesystem"]["user_home_mapping"] is True
        assert config["filesystem"]["default_home_owner"] is True

    def test_generate_persona_llm_failure(self, setup_generator):
        # Simulate LLM Failure on Ping
        self.mock_llm.generate_response.side_effect = Exception("API Error")

        with pytest.raises(Exception):
            self.generator.generate_persona("Fail this")

        # Ensure no junk directory created (or at least check handled)
        # The implementation currently relies on shutil.copytree before analysis but raises exception.
        # Ideally it should cleanup or not matter.

    def test_banner_sanitization(self, setup_generator):
        """Test that malformed SSH banners are sanitized."""
        desc = "Dirty Banner Test"

        # Mock Analysis with dirty banner
        analysis_json = """{
            "network": {
                 "ssh_banner": "  OpenSSH_Dirty\\n " 
            }
        }"""

        self.mock_llm.generate_response.side_effect = ["Pong", analysis_json, ""]

        new_persona = self.generator.generate_persona(desc)
        self.generated_personas.append(new_persona)

        p_path = os.path.join(get_data_dir(), "personas", new_persona)
        with open(os.path.join(p_path, "persona.yaml"), "r") as f:
            config = yaml.safe_load(f)

        # Expect trimmed whitespace + SSH-2.0- prefix
        assert config["network"]["ssh_banner"] == "SSH-2.0-OpenSSH_Dirty"

    def test_json_parsing_resilience(self, setup_generator):
        # Test if LLM returns markdown wrapped JSON
        desc = "Markdown JSON test"

        valid_json = '{"system": {"hostname": "md-host"}}'
        wrapped_json = f"```json\n{valid_json}\n```"

        self.mock_llm.generate_response.side_effect = [
            "Pong",
            wrapped_json,
            "",  # no files
        ]

        new_persona = self.generator.generate_persona(desc)
        self.generated_personas.append(new_persona)

        p_path = os.path.join(get_data_dir(), "personas", new_persona)
        with open(os.path.join(p_path, "persona.yaml"), "r") as f:
            config = yaml.safe_load(f)

        assert config["system"]["hostname"] == "md-host"
