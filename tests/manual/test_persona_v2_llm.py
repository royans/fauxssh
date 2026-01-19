import pytest
import os
import yaml
import shutil
from ssh_honeypot.core.persona_generator import PersonaGenerator
from ssh_honeypot.core.llm import LLMInterface
from ssh_honeypot.core.utils import get_data_dir


@pytest.mark.skip(reason="User requested skip for deployment stability")
class TestPersonaGenLLM:
    def test_finance_persona_generation(self):
        """
        End-to-end test with Real LLM to generate a 'Finance Server' persona.
        Verifies: Hostname, WebRoot detection, and File Generation.
        """
        print("[*] Initializing Real LLM...")
        llm = LLMInterface()
        if not llm.api_key:
            pytest.skip("No API Key found for LLM.")

        gen = PersonaGenerator(llm)

        description = (
            "This is a Finance server running Kali linux with 12 CPUs, 24 GB Ram. "
            "There are 4 GPUs on this. Local network is 10.5.5.0/24 , the router is on 10.5.5.1, "
            "the self IP is 10.5.5.2. Hostname is finance.blogofy.com. "
            "Its running nginx http server and has the company page about finance services the company provides. "
            "The file system has some csv files for tax returns from some of the clients."
        )

        print(f"[*] Generating Persona for: {description}")
        persona_name = gen.generate_persona(description)
        print(f"[+] Persona Created: {persona_name}")

        # Verify Results
        persona_dir = os.path.join(get_data_dir(), "personas", persona_name)
        yaml_path = os.path.join(persona_dir, "persona.yaml")
        fs_root = os.path.join(persona_dir, "fs")

        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)

            # Verify System Config
            assert data["system"].get("hostname") == "finance.blogofy.com"
            assert "Kali" in data["system"].get("distro_name", "") or "Kali" in data[
                "system"
            ].get("distro_pretty_name", "")

            # Verify HTTP Config
            http = data.get("http", {})
            assert "nginx" in http.get("server_header", "").lower()
            expected_root = http.get("web_root")
            assert expected_root is not None
            assert (
                "html" in expected_root
            )  # Simplistic check for /var/www/html or /usr/share/nginx/html

            # Verify Files
            # Check for index file in the detected webroot
            # We need to strip leading slash to join with fs_root
            rel_web_root = expected_root.lstrip("/")
            index_path_html = os.path.join(fs_root, rel_web_root, "index.html")
            index_path_php = os.path.join(fs_root, rel_web_root, "index.php")

            assert os.path.exists(index_path_html) or os.path.exists(
                index_path_php
            ), f"Index file NOT found in {expected_root}"

            # Check for csv files
            csv_found = False
            for root, dirs, files in os.walk(fs_root):
                for file in files:
                    if file.endswith(".csv"):
                        csv_found = True
                        break
            assert csv_found, "No CSV files generated."

        finally:
            # Cleanup
            if os.path.exists(persona_dir):
                shutil.rmtree(persona_dir)
