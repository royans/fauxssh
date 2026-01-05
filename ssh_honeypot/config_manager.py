# config_manager.py
import yaml
import os

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Robust .env loading
try:
    from dotenv import load_dotenv
    
    # 1. Search specific paths relevant to deployment structure
    candidate_paths = [
        # Explicit locations
        os.path.join(PROJECT_ROOT, '.env'),                 # ./sshpot/.env (Clone root)
        os.path.join(os.path.dirname(PROJECT_ROOT), '.env') # ../.env (User deploy root, e.g. ~/c/.env)
    ]
    
    # 2. Try implicit search
    try:
        from dotenv import find_dotenv
        found = find_dotenv(usecwd=True)
        if found:
            candidate_paths.append(found)
    except ImportError: pass

    env_loaded = False
    for p in candidate_paths:
        if os.path.exists(p):
            load_dotenv(p)
            env_loaded = True
            # Don't break; load all found in hierarchy (child overrides parent usually, but load_dotenv does NOT override by default)
            # So we should actually load CHILD first if we wanted override, but typically we want the "closest" one.
            # load_dotenv priority: The first value set "wins".
            # So if we load specific paths first, they win.
            
except ImportError:
    # Fail silently if dotenv missing, simply relying on OS environment
    pass

def get_data_dir():
    """
    Returns the absolute path to the data directory.
    Priority:
    1. FAUXSSH_DATA_DIR environment variable (absolute or relative to CWD)
    2. Default: PROJECT_ROOT/data
    """
    env_path = os.getenv('FAUXSSH_DATA_DIR')
    if env_path:
        # Resolve path (handles relative paths from CWD)
        data_dir = os.path.abspath(env_path)
    else:
        data_dir = os.path.join(PROJECT_ROOT, 'data')
    
    # Auto-create if missing
    if not os.path.exists(data_dir):
        try:
            os.makedirs(data_dir, exist_ok=True)
        except Exception as e:
            print(f"[!] Critical: Could not create data directory at {data_dir}: {e}")
            
    return data_dir

def get_version():
    """Reads version from pyproject.toml to avoid hardcoding drift."""
    try:
        import tomllib
        import os
        # Assuming run from root or finding root relative to this file
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(base_dir, "pyproject.toml"), "rb") as f:
            data = tomllib.load(f)
            return data["project"]["version"]
    except Exception as e:
        # Fallback or log error
        return "0.0.0-unknown"

def get_ignored_ips():
    """
    Returns a list of IPs to ignore in analytics, parsed from ANALYTICS_IGNORE_IPS.
    """
    raw = os.getenv('ANALYTICS_IGNORE_IPS', '')
    if not raw:
        return []
    
    ips = [ip.strip() for ip in raw.split(',') if ip.strip()]
    expanded_ips = []
    
    for ip in ips:
        expanded_ips.append(ip)
        # If it looks like an IPv4 address, also ignore the IPv6-mapped version
        if '.' in ip and ':' not in ip:
            expanded_ips.append(f"::ffff:{ip}")
            
    return expanded_ips

DEFAULT_CONFIG = {
    "server": {
        "host_key_file": "data/host.key",
        "port": 2222,
        "bind_ip": "0.0.0.0",
        "hostname": "web.blogofy.com"
    },
    "llm": {
        "model_name": "gemma-3-27b-it",
        "max_tokens": 2048,
        "temperature": 1.0,
        "timeout": 60
    },
    "logging": {
        "json_log_file": "data/honeypot.json.log",
        "enable_session_replay": False
    },
    "upload": {
        "max_file_size": 1048576, # 1MB
        "max_quota_per_ip": 1048576, # 1MB
        "cleanup_days": 30
    },
    "alerting": {
        "webhook_url": None,
        "notify_threshold": 6,
        "session_threshold": 7, 
        "ip_threshold": 9,
        "keywords": []
    },
    "persona": {
        # Minimal Fallback if persona file load fails
        "system": {
            "hostname": "fallback-system"
        },
        "prompts": {
             "system_prompt": "Error: Persona failed to load."
        }
    }
}

class ConfigManager:
    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        self._config = DEFAULT_CONFIG.copy()
        
        # 1. Load User Config (config.yaml) - Server/LLM settings
        self.load_config_file()
        
        # 2. Load Defaults/Environment Overrides for Server/LLM
        self.load_env_overrides()

        # 3. Load Persona (Default + Override)
        # This will merge persona data INTO self._config['persona']
        self.load_persona()

    def load_config_file(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        self._deep_merge(self._config, user_config)
            except Exception as e:
                # print(f"[!] Error loading config: {e}")
                pass

    def load_env_overrides(self):
        # Environment Override (Priority over config.yaml)
        if os.getenv("WEBHOOK_URL"):
            if 'alerting' not in self._config: self._config['alerting'] = {}
            self._config['alerting']['webhook_url'] = os.getenv("WEBHOOK_URL")
        
        if os.getenv("ALERT_THRESHOLD_NOTIFY"):
             try: self._config['alerting']['notify_threshold'] = int(os.getenv("ALERT_THRESHOLD_NOTIFY"))
             except ValueError: pass

        if os.getenv("ALERT_THRESHOLD_SESSION"):
             try: self._config['alerting']['session_threshold'] = int(os.getenv("ALERT_THRESHOLD_SESSION"))
             except ValueError: pass

        if os.getenv("ALERT_THRESHOLD_IP"):
             try: self._config['alerting']['ip_threshold'] = int(os.getenv("ALERT_THRESHOLD_IP"))
             except ValueError: pass

        if os.getenv("ALERT_KEYWORDS"):
             self._config['alerting']['keywords'] = [k.strip() for k in os.getenv("ALERT_KEYWORDS").split('|') if k.strip()]

    def load_persona(self, override_name=None):
        """
        Loads the active persona.
        Strategy:
        1. Load 'Debian12_GPU_8GB' (The fixed Base)
        2. Check ENV 'SSH_PERSONA' or Arg 'override_name'
        3. If override exists, load it and MERGE on top of Base.
        """
        base_name = "Debian12_GPU_8GB"
        # Migration: Personas are now in the project root, not in data/
        personas_dir = os.path.join(PROJECT_ROOT, "personas")
        
        # 1. Load Base
        base_config = self._read_persona_file(base_name, personas_dir)
        if base_config:
            # We treat the root of persona.yaml as the source for config['persona']
            # However, persona.yaml has keys like 'system', 'network', 'prompts'
            # We want these to map to config['persona']... OR we might want to lift them?
            # Current usage: config.get('persona', 'distro_name') -> config['persona']['distro_name']
            
            # The new schema separates 'system', 'network', 'prompts'.
            # To maintain backward compat where possible, we can flatten 'system' into 'persona'
            # OR better: we start migrating code to use config.get('persona', 'system', 'hostname')
            
            # Let's trust the new strict schema and merge it under 'persona' key
            # But wait, config.get('persona', 'kernel_name') implies direct access.
            # We should probably flatten 'system' into 'persona' for compat if we don't want to refactor everything at once.
            
            # Decision: Put the whole loaded yaml into config['persona'].
            # BUT we also need to flattening 'system' keys to 'persona' root for backward compatibility?
            #   config.get('persona', 'kernel_name') -> config['persona']['kernel_name']
            #   New schema: config['persona']['system']['kernel_name']
            
            # Migration Helper: Flatten 'system'
            if 'system' in base_config:
                for k, v in base_config['system'].items():
                     base_config[k] = v
            
            self._config['persona'] = base_config
        else:
             print(f"[!] CRITICAL: Failed to load base persona '{base_name}'. Check /tmp/sshpot_boot.log.")
             # We cannot continue without a persona. It results in LLM hallucinations.
             import sys
             sys.exit(1)
        
        # 2. Determine Override
        target = override_name or os.getenv("SSH_PERSONA")
        
        if target and target != base_name:
            print(f"[*] Loading Persona Override: {target}")
            override_config = self._read_persona_file(target, personas_dir)
            if override_config:
                # Merge logic
                if 'system' in override_config:
                    for k, v in override_config['system'].items():
                        override_config[k] = v
                
                self._deep_merge(self._config['persona'], override_config)
            else:
                 print(f"[!] Warning: Persona '{target}' not found. Using default.")

    def _read_persona_file(self, name_or_path, personas_dir):
        # DEBUG: Log to /tmp/sshpot_boot.log to diagnose startup issues
        debug_log = "/tmp/sshpot_boot.log"
        try:
             with open(debug_log, "a") as df:
                 df.write(f"[DEBUG] _read_persona_file: {name_or_path} in {personas_dir}\n")
                 df.write(f"        CWD: {os.getcwd()}\n")
        except: pass

        # 1. Try absolute path
        if os.path.exists(name_or_path) and (name_or_path.endswith('.yaml') or os.path.isdir(name_or_path)):
             # If dir, look for persona.yaml
             if os.path.isdir(name_or_path):
                 fpath = os.path.join(name_or_path, 'persona.yaml')
             else:
                 fpath = name_or_path
        else:
            # 2. Try name in personas_dir
            fpath = os.path.join(personas_dir, name_or_path, 'persona.yaml')
            
        try:
             with open(debug_log, "a") as df:
                 df.write(f"        Resolved Path: {fpath} (Exists: {os.path.exists(fpath)})\n")
        except: pass
        
        # Explicit Console Debugging (Requested by User)
        print(f"[DEBUG] Validating Persona Path: {fpath}")
        if not os.path.exists(fpath):
            print(f"[DEBUG] FAILED: Path does not exist!")
            print(f"[DEBUG] Current CWD: {os.getcwd()}")
            print(f"[DEBUG] personas_dir: {personas_dir}")

        if os.path.exists(fpath):
            try:
                with open(fpath, 'r') as f:
                    data = yaml.safe_load(f)
                    # Inject path for fs_seeder to find fs/ dir
                    data['_fs_path'] = os.path.join(os.path.dirname(fpath), 'fs')
                    return data
            except Exception as e:
                err_msg = f"[!] Error loading persona {name_or_path}: {e}"
                print(err_msg)
                try: 
                    with open(debug_log, "a") as df: df.write(f"{err_msg}\n")
                except: pass
                return None
        
        # Path not found
        try: 
            with open(debug_log, "a") as df: df.write(f"[!] Path not found: {fpath}\n")
        except: pass
        return None

    def _deep_merge(self, base, update):
        for k, v in update.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v

    def get(self, *keys):
        val = self._config
        for k in keys:
            val = val.get(k)
            if val is None: return None
        return val

# Global instance
config = ConfigManager()

