import unittest
from unittest.mock import MagicMock
import os
import shutil
import yaml
import sys

# Path Setup
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ssh_honeypot.core.persona_generator import PersonaGenerator
from ssh_honeypot.core.state_manager import StateManager
from ssh_honeypot.core.utils import PROJECT_ROOT, get_data_dir


class TestPersonaGenerator(unittest.TestCase):
    def setUp(self):
        self.mock_llm = MagicMock()
        self.generator = PersonaGenerator(self.mock_llm)
        self.created_personas = []

    def tearDown(self):
        # Cleanup
        for p in self.created_personas:
            p_path = os.path.join(get_data_dir(), "personas", p)
            if os.path.exists(p_path):
                shutil.rmtree(p_path)
                print(f"Cleaned up {p}")

        if os.path.exists(".last_persona"):
            os.remove(".last_persona")

    def test_generate_persona(self):
        desc = "A secret server for Area 51"

        # Mock Analysis Response
        # Mock Analysis Response
        analysis_json = """{
            "system": {
                 "hostname": "area51-gateway",
                 "distro_name": "Ubuntu",
                 "distro_version": "22.04"
            },
            "network": {
                 "ssh_banner": "OpenSSH_Dirty\\n",
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
            "prompt_context": "You are a classified gateway server for Area 51.",
            "suggested_files": [
                {"path": "/opt/secrets/aliens.txt", "type": "file", "description": "List of aliens"}
            ]
        }"""

        # Mock Generation Response (for file content)
        file_content = "Grey, Green, Tall White"

        # Configure Mock
        # Side effect for generate_response:
        # 1. Ping -> "Pong"
        # 2. Analysis -> JSON
        # 3. File Gen -> Content
        self.mock_llm.generate_response.side_effect = [
            "Pong",
            analysis_json,
            file_content,
        ]

        # Run
        new_persona_name = self.generator.generate_persona(desc)
        self.created_personas.append(new_persona_name)

        print(f"Generated Persona: {new_persona_name}")

        # Verification
        # 1. Verify Directory Exists
        p_path = os.path.join(get_data_dir(), "personas", new_persona_name)
        self.assertTrue(os.path.exists(p_path))

        # 2. Verify persona.yaml
        yaml_path = os.path.join(p_path, "persona.yaml")
        with open(yaml_path, "r") as f:
            config = yaml.safe_load(f)

        self.assertEqual(config["system"]["hostname"], "area51-gateway")
        self.assertIn("Dynamic: " + desc, config["description"])

        # Verify Context Injection
        self.assertIn("DYNAMIC IDENTITY", config["prompts"]["system_prompt"])
        self.assertIn("classified gateway", config["prompts"]["system_prompt"])
        self.assertIn("500GB SSD", config["prompts"]["system_prompt"])
        self.assertIn("SECURITY POSTURE", config["prompts"]["system_prompt"])

        # 3. Verify File Generation
        file_path = os.path.join(p_path, "fs", "opt/secrets/aliens.txt")
        self.assertTrue(os.path.exists(file_path))
        with open(file_path, "r") as f:
            content = f.read()
            self.assertEqual(content, file_content)

        # Verify sanitized banner
        self.assertEqual(config["network"]["ssh_banner"], "SSH-2.0-OpenSSH_Dirty")
        last = StateManager.get_last_persona()
        self.assertEqual(last, new_persona_name)


if __name__ == "__main__":
    unittest.main()
