
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
             self.llm.generate_response("echo test", "/", [], [], [], override_prompt="Ping. Return 'Pong'.")
        except Exception as e:
             log.error(f"LLM Pre-flight check failed: {e}")
             raise

        # 2. Setup New Directory
        short_id = uuid.uuid4().hex[:8]
        new_persona_name = f"dynamic_{short_id}"
        new_persona_path = os.path.join(self.output_personas_dir, new_persona_name)
        base_persona_path = os.path.join(self.source_personas_dir, self.BASE_PERSONA)

        log.info(f"Cloning base persona '{self.BASE_PERSONA}' to '{new_persona_name}'...")
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
             if metadata.get('suggested_files'):
                  log.info(f"Generating filesystem artifacts ({len(metadata['suggested_files'])})...")
                  self._generate_artifacts(new_persona_path, metadata['suggested_files'])
             
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
           - hostname: (Extract the most specific FQDN, e.g. 'web.abc.com')
           - os_name: "GNU/Linux"
           - distro_name: (e.g. "Kali GNU/Linux", "CentOS")
           - distro_version: (e.g. "2023.4", "7")
           - distro_pretty_name: (e.g. "Kali GNU/Linux Rolling")
           - kernel_release: (e.g. "6.5.0-kali3-amd64")
           - processor_version: (Specific CPU model if mentioned, else realistic default)
           
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
           
        5. prompt_context: A 2-3 sentence summary of the server's role and identity.
        
        6. suggested_files: A list of objects {{ "path": "/path...", "type": "file", "description": "..." }} for 3-5 critical files.
        """
        
        # We misuse generate_response slightly as it expects cmd/cwd. 
        # We pass override_prompt to bypass standard template.
        resp = self.llm.generate_response(
             "ANALYSIS", "/", [], [], [], 
             override_prompt=prompt
        )
        
        # Extract JSON
        try:
             start = resp.find('{')
             end = resp.rfind('}')
             if start != -1 and end != -1:
                  return json.loads(resp[start:end+1])
        except:
             log.warning("Failed to parse JSON from LLM analysis. Using defaults.")
        
        return {}

    def _configure_persona_yaml(self, persona_path: str, metadata: Dict, original_desc: str):
        yaml_path = os.path.join(persona_path, "persona.yaml")
        
        with open(yaml_path, 'r') as f:
             config = yaml.safe_load(f)
        
        # 1. Update Description
        config['description'] = f"Dynamic: {original_desc}"

        # 2. Update System Fields (Deep Merge)
        if metadata.get('system'):
             for k, v in metadata['system'].items():
                  if v: config['system'][k] = v
                  
        # 3. Update Network Fields
        if metadata.get('network'):
             if 'network' not in config: config['network'] = {}
             
             # Handle nested interfaces carefully
             if 'interfaces' in metadata['network']:
                 config['network']['interfaces'] = metadata['network']['interfaces']
                 
             # Copy other network keys (banner, etc)
             for k, v in metadata['network'].items():
                 if k == 'ssh_banner':
                     # Sanitize Banner to prevent protocol errors
                     val = str(v).strip()
                     if not val.startswith('SSH-2.0-'):
                         val = f"SSH-2.0-{val}"
                     # Remove newlines which break the handshake
                     val = val.replace('\n', '').replace('\r', '')
                     
                     config['network'][k] = val
                     config['network'][k] = val
                 elif k == 'interfaces':
                     # Handled above explicitly if needed, but the loop logic might skip or double process.
                     # The original code had specific 'interfaces' handling check at line 164.
                     # We should ensure we don't overwrite it if handled there, OR just handle everything here.
                     pass 
                 elif v:
                      # Generic copy for new fields (network_type, subnet_cidr, default_gateway, dns_servers)
                      config['network'][k] = v
        
        # 4. Update System Prompt (Inject Context & Hardware Identity)
        current_prompt = config['prompts']['system_prompt']
        
        sys_meta = metadata.get('system', {})
        hw_meta = metadata.get('hardware', {})
        svc_meta = metadata.get('services', {})
        
        os_identity = f"You are a **{sys_meta.get('distro_pretty_name', 'Linux Server')}**."
        
        # Construct Hardware Context
        hw_context = []
        if hw_meta.get('cpu_info'): hw_context.append(f"CPU: {hw_meta['cpu_info']}")
        if hw_meta.get('memory'): hw_context.append(f"RAM: {hw_meta['memory']}")
        if hw_meta.get('swap'): hw_context.append(f"Swap: {hw_meta['swap']}")
        if hw_meta.get('disk_info'): hw_context.append(f"Disk: {hw_meta['disk_info']}")
        if hw_meta.get('gpu_info'): hw_context.append(f"GPU: {hw_meta['gpu_info']}")
        
        hw_str = ", ".join(hw_context) if hw_context else "Hardware: Default Container"
        
        # Construct Service/Security Context
        svc_str = ""
        if svc_meta.get('running_processes'):
             procs = ", ".join(svc_meta['running_processes'])
             svc_str += f"\n      - **RUNNING SERVICES**: Should appear in 'ps aux': {procs}."
        
        if svc_meta.get('patch_status'):
             svc_str += f"\n      - **SECURITY POSTURE**: {svc_meta['patch_status']}."
        
        context_Role = metadata.get('prompt_context', 'You are a generic server.')
        
        injection = f"""
      - **DYNAMIC IDENTITY**: {os_identity} {context_Role}
      - **HARDWARE**: {hw_str} (Use this for 'free', 'lscpu', 'df -h', 'nvidia-smi').
      - **OS OVERRIDE**: Act exactly like {sys_meta.get('distro_name', 'Linux')} {sys_meta.get('distro_version', '')}.{svc_str}
"""
        
        if "BEHAVIOR RULES:" in current_prompt:
             config['prompts']['system_prompt'] = current_prompt.replace("BEHAVIOR RULES:", f"BEHAVIOR RULES:{injection}")
        else:
             config['prompts']['system_prompt'] += injection

        with open(yaml_path, 'w') as f:
             yaml.dump(config, f, default_flow_style=False)

    def _generate_artifacts(self, persona_path: str, files: List[Dict]):
        fs_root = os.path.join(persona_path, "fs")
        if not os.path.exists(fs_root):
             os.makedirs(fs_root)
             
        for item in files:
             path = item.get('path')
             if not path: continue
             
             # Validate Path (security check - no traversal)
             if ".." in path or path.startswith("/../"): continue
             
             # Remove leading slash for os.path.join relative logic
             rel_path = path.lstrip('/')
             full_path = os.path.join(fs_root, rel_path)
             
             # Create Dirs
             os.makedirs(os.path.dirname(full_path), exist_ok=True)
             
             # Generate Content
             desc = item.get('description', 'A realistic file')
             prompt = f"Generate realistic content for file '{path}'. Context: {desc}. Return ONLY the content."
             
             content = self.llm.generate_response("GENERATE", "/", [], [], [], override_prompt=prompt)
             
             # Clean content (remove markdown blocks if present)
             content = self._clean_llm_markdown(content)
             
             with open(full_path, 'w') as f:
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
        
        with open(yaml_path, 'r') as f:
             data = yaml.safe_load(f)
             
        if 'system' not in data or 'prompts' not in data:
             raise ValueError("Generated persona.yaml is invalid (missing required sections).")
