import os
import uuid
import shutil
import yaml
import json
import logging
from typing import Dict, Any, List
from ssh_honeypot.core.utils import PROJECT_ROOT, get_data_dir
from ssh_honeypot.core.state_manager import StateManager

log = logging.getLogger("sshpot")


class PersonaGenerator:
    """
    Generates dynamic personas based on a natural language description.
    """

    BASE_PERSONA = "CentOS7_Legacy_Compute"

    def __init__(self, llm_interface):
        self.llm = llm_interface
        # Source of truth for base personas
        self.source_personas_dir = os.path.join(PROJECT_ROOT, "personas")
        # Destination for dynamic personas (user data)
        self.output_personas_dir = os.path.join(get_data_dir(), "personas")

        # Ensure output dir exists
        os.makedirs(self.output_personas_dir, exist_ok=True)

    def generate_persona(self, description: str) -> str:
        """
        Creates a new persona from the description.
        Returns the name of the new persona.
        """
        if not self.llm:
            raise ValueError("LLM Interface is not initialized.")

        # 1. Pre-flight Check (Simple ping prompt)
        log.info("Checking LLM connectivity...")
        try:
            # Just a quick check to ensure keys are valid before we clone
            self.llm.generate_response(
                "echo test", "/", [], [], [], override_prompt="Ping. Return 'Pong'."
            )
        except Exception as e:
            log.error(f"LLM Pre-flight check failed: {e}")
            raise

        # 2. Setup New Directory
        short_id = uuid.uuid4().hex[:8]
        new_persona_name = f"dynamic_{short_id}"
        new_persona_path = os.path.join(self.output_personas_dir, new_persona_name)
        base_persona_path = os.path.join(self.source_personas_dir, self.BASE_PERSONA)

        log.info(
            f"Cloning base persona '{self.BASE_PERSONA}' to '{new_persona_name}'..."
        )
        if not os.path.exists(base_persona_path):
            raise FileNotFoundError(f"Base persona not found at {base_persona_path}")

        shutil.copytree(base_persona_path, new_persona_path)

        try:
            # 3. Analyze Description
            log.info("Analyzing persona description with LLM...")
            metadata = self._analyze_description(description)

            # 4. Configure System (persona.yaml)
            log.info("Configuring system parameters...")
            self._configure_persona_yaml(new_persona_path, metadata, description)

            # 5. Generate Files
            # Support both old 'suggested_files' and new 'files' keys
            files_to_gen = metadata.get("files") or metadata.get("suggested_files")
            if files_to_gen:
                log.info(f"Generating filesystem artifacts ({len(files_to_gen)})...")
                self._generate_artifacts(new_persona_path, files_to_gen)

            # 6. Validate
            self._validate_generated_persona(new_persona_path)

            # 7. Save State
            StateManager.save_last_persona(new_persona_name)

            log.info(f"Successfully created persona: {new_persona_name}")
            return new_persona_name

        except Exception as e:
            log.error(f"Failed to generate persona: {e}")
            # Cleanup on failure? Maybe keep for debugging if requested, but for now cleanup to avoid junk
            # shutil.rmtree(new_persona_path)
            raise e

    def _analyze_description(self, description: str) -> Dict[str, Any]:
        """
        Asks LLM to parse the description into structured data.
        """
        prompt = f"""
        You are configuring a cybersecurity honeypot based on this user description:
        "{description}"
        
        Analyze this description and return a JSON object with the following fields to fully customize the server:
        
        1. system: An object containing:
           - hostname: (Extract the most specific FQDN or hostname found)
           - os_name: "GNU/Linux"
           - distro_name: (e.g. Debian, CentOS, Ubuntu, Kali)
           - distro_version: (e.g. 11, 7.9, 22.04)
           - distro_pretty_name: (Full string from /etc/os-release)
           - kernel_release: (e.g. 5.10.0-21-cloud-amd64)
           - users: (A list of 2-4 realistic usernames that would exist on this system, e.g. [ "admin", "db_manager" ])
           - processor_version: (Specific CPU model if mentioned, otherwise realistic default)
           
        2. hardware: An object containing (for context injection):
           - cpu_info: (e.g. "2 vCPU", "AMD EPYC")
           - memory: (e.g. "256GB")
           - swap: (e.g. "0", "8GB")
           - disk_info: (e.g. "2TB NVMe SSD", "500GB RAID1")
           - gpu_info: (e.g. "6x NVIDIA A100", "Integrated")
           
        3. services: An object containing:
           - running_processes: A list of key services expected to be seen in 'ps aux' (e.g. ["nginx", "mysqld", "python3 model.py"])
           - patch_status: A description of the security posture (e.g. "Critical CVE-2023-1234 unpatched", "Fully updated")
           
        4. network: An object containing:
           - ssh_banner: (A realistic SSH banner)
           - network_type: (e.g. "Enterprise LAN", "Home Network", "Cloud VPC", "Industrial Control System")
           - subnet_cidr: (The main subnet, e.g. "10.14.1.0/24")
           - default_gateway: (The router IP, e.g. "10.14.1.1")
           - dns_servers: (List of DNS IPs, e.g. ["8.8.8.8", "10.14.1.1"])
           - interfaces: A dictionary of "interface": "ip" mappings (e.g. {{"eth0": "10.14.1.50"}}). logic: If user specifies a network CIDR (10.14.1.X/24), pick a random realistic IP in that range.
           - open_ports: A list of integer ports exposed by this server (e.g. [22, 80, 443]). Ensure these match the services described.
           
        5. http: An object containing web server details (if applicable, else defaults):
           - server_header: (e.g. "Apache/2.4.6 (CentOS)", "nginx/1.18.0")
           - web_root: (e.g. "/var/www/html", "/usr/share/nginx/html", "/opt/tomcat/webapps"). Choose based on the server software (Apache vs Nginx vs Tomcat).
           - headers: A dictionary of default HTTP headers (e.g. {{"X-Powered-By": "PHP/5.6", "Server": "Apache/2.4.6"}})
           
        6. access_control: An object containing:
           - allow_root: (Boolean, true/false)
           - max_auth_tries_per_ip: (Integer, e.g. 3)

        7. prompt_context: A 2-3 sentence summary of the server's role and identity.
        
        8. files: A list of objects representing CRITICAL and PERSONALIZED files found on this specific system.
           Format: {{ "path": "/absolute/path/to/file", "type": "file", "description": "Detailed description of content." }}
           MANDATORY FILES TO GENERATE:
             - /etc/hostname (Must match the hostname chosen above)
             - /etc/resolv.conf (Realistic nameservers for the network type)
             - An 'index.html' (or index.php) placed in the 'web_root' you selected above. It should reflect the company/role described.
             - At least 3-5 other files specific to the persona.
             - IMPORTANT: For user-specific files (documents, downloads, secrets), place them in '/home/USER/' (literal string 'USER'). Do not use random info like '/home/alice'. Example: '/home/USER/salary_data.csv'.
             - Do NOT generate generic linux files like /bin/ls. Focus on user data and app configs.
        """

        # We misuse generate_response slightly as it expects cmd/cwd.
        # We pass override_prompt to bypass standard template.
        resp = self.llm.generate_response(
            "ANALYSIS", "/", [], [], [], override_prompt=prompt
        )

        # Extract JSON
        try:
            start = resp.find("{")
            end = resp.rfind("}")
            if start != -1 and end != -1:
                return json.loads(resp[start : end + 1])
        except Exception as e:
            log.warning(f"Failed to parse JSON from LLM analysis: {e}")

        return {}

    def _configure_persona_yaml(
        self, persona_path: str, metadata: Dict, original_desc: str
    ):
        yaml_path = os.path.join(persona_path, "persona.yaml")

        with open(yaml_path, "r") as f:
            config = yaml.safe_load(f)

        # 1. Update Description
        config["description"] = f"Dynamic: {original_desc}"

        # 2. Update System Fields (Deep Merge)
        if metadata.get("system"):
            for k, v in metadata["system"].items():
                if v:
                    config["system"][k] = v

        # 3. Update Network Fields
        if metadata.get("network"):
            if "network" not in config:
                config["network"] = {}

            # Handle open_ports list specifically
            if "open_ports" in metadata["network"]:
                config["network"]["open_ports"] = metadata["network"]["open_ports"]

            # Handle nested interfaces carefully
            if "interfaces" in metadata["network"]:
                config["network"]["interfaces"] = metadata["network"]["interfaces"]

            # Copy other network keys (banner, etc)
            for k, v in metadata["network"].items():
                if k == "ssh_banner":
                    # Sanitize Banner to prevent protocol errors
                    val = str(v).strip()
                    if not val.startswith("SSH-2.0-"):
                        val = f"SSH-2.0-{val}"
                    # Remove newlines which break the handshake
                    val = val.replace("\n", "").replace("\r", "")

                    config["network"][k] = val
                elif k in ["interfaces", "open_ports"]:
                    # Handled above explicitly
                    pass
                elif v:
                    # Generic copy for new fields (network_type, subnet_cidr, default_gateway, dns_servers)
                    config["network"][k] = v

        # 4. Update HTTP Settings
        if metadata.get("http"):
            if "http" not in config:
                config["http"] = {}
            for k, v in metadata["http"].items():
                if v:
                    config["http"][k] = v

            # Explicitly set web_root if provided by LLM
            if "web_root" in metadata["http"]:
                config["http"]["web_root"] = metadata["http"]["web_root"]

        # 5. Update Access Control
        if metadata.get("access_control"):
            if "access_control" not in config:
                config["access_control"] = {}
            for k, v in metadata["access_control"].items():
                # Allow boolean False to be set (so check is not None)
                if v is not None:
                    config["access_control"][k] = v

        # 6. Update Filesystem Config (Enforce USER mapping)
        if "filesystem" not in config:
            config["filesystem"] = {}
        config["filesystem"]["user_home_mapping"] = True
        config["filesystem"]["default_home_owner"] = True

        # 7. Update System Prompt (Intelligent Merge)
        log.info("Integrating persona description into system prompt...")
        base_prompt = config["prompts"]["system_prompt"]

        prompt = f"""
        You are an AI specializing in honeypot persona design.
        I have a BASE system prompt for a honeypot, and a NEW persona description.
        
        BASE PROMPT:
        {base_prompt}
        
        NEW PERSONA DESCRIPTION:
        "{original_desc}"
        
        METADATA FROM ANALYSIS:
        {json.dumps(metadata, indent=2)}
        
        INSTRUCTION:
        Integrate the NEW PERSONA identity into the BASE PROMPT.
        - The resulting prompt MUST maintain ALL the "BEHAVIOR RULES" and "CRITICAL" rules from the BASE PROMPT.
        - It should adopt the TONE, ROLE, and IDENTITY of the NEW PERSONA.
        - Update any hardcoded hostname or OS references to match the METADATA.
        - Return ONLY the final integrated system prompt text. Do not include markdown blocks or explanations.
        """

        try:
            integrated_prompt = self.llm.generate_response(
                "MERGE_PROMPT", "/", [], [], [], override_prompt=prompt
            )
            # Clean markdown
            integrated_prompt = self._clean_llm_markdown(integrated_prompt)

            if integrated_prompt and len(integrated_prompt) > 100:
                config["prompts"]["system_prompt"] = integrated_prompt
            else:
                log.warning(
                    "Integrated prompt was too short or empty. Falling back to injection method."
                )
                config["prompts"][
                    "system_prompt"
                ] += f"\n\n# Dynamic Context\n{metadata.get('prompt_context', '')}"
        except Exception as e:
            log.error(f"Failed to merge system prompt: {e}")
            config["prompts"][
                "system_prompt"
            ] += f"\n\n# Dynamic Context\n{metadata.get('prompt_context', '')}"

        with open(yaml_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

    def _generate_artifacts(self, persona_path: str, files: List[Dict]):
        fs_root = os.path.join(persona_path, "fs")
        if not os.path.exists(fs_root):
            os.makedirs(fs_root)

        for item in files:
            path = item.get("path")
            if not path:
                continue

            # Validate Path (security check - no traversal)
            if ".." in path or path.startswith("/../"):
                continue

            # Remove leading slash for os.path.join relative logic
            rel_path = path.lstrip("/")
            full_path = os.path.join(fs_root, rel_path)

            # Create Dirs
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            # Generate Content
            desc = item.get("description", "A realistic file")
            prompt = f"Generate realistic content for file '{path}'. Context: {desc}. Return ONLY the content."

            content = self.llm.generate_response(
                "GENERATE", "/", [], [], [], override_prompt=prompt
            )

            # Clean content (remove markdown blocks if present)
            content = self._clean_llm_markdown(content)

            with open(full_path, "w") as f:
                f.write(content)

    def _clean_llm_markdown(self, text: str) -> str:
        # Simple stripper for ```code``` blocks if LLM wraps it
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            return "\n".join(lines)
        return text

    def _validate_generated_persona(self, persona_path: str):
        """Sanity check the generated YAML."""
        yaml_path = os.path.join(persona_path, "persona.yaml")
        if not os.path.exists(yaml_path):
            raise ValueError("persona.yaml missing in generated persona.")

        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)

        if "system" not in data or "prompts" not in data:
            raise ValueError(
                "Generated persona.yaml is invalid (missing required sections)."
            )
