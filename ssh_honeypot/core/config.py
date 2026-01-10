# config.py
import yaml
import yaml
import os
from ssh_honeypot.core.utils import PROJECT_ROOT, BASE_DIR, get_data_dir, get_version, get_ignored_ips
try:
    from ssh_honeypot.core.schemas import AppConfig
except ImportError:
    # Bootstrap
    pass

DEFAULT_CONFIG_DICT = {
    "server": {
        "host_key_file": "data/host.key",
        "port": 2222,
        "bind_ip": "0.0.0.0",
        "hostname": "web.blogofy.com"
    },
    "http": {
        "port": 8080,
        "enabled": True,
        "server_header": "Apache/2.4.52 (Ubuntu)",
        "llm_rpm": 4,
        "llm_rpd": 20
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
        "max_file_size": 1048576,
        "max_quota_per_ip": 1048576,
        "cleanup_days": 30
    },
    "alerting": {
        "webhook_url": None,
        "notify_threshold": 6,
        "session_threshold": 7, 
        "ip_threshold": 9,
        "keywords": []
    },
    "mcp": {
        "max_llm_calls": 20,
        "throttle_delay": 2.0
    },
    "security": {
        "max_input_length": 50000,
        "max_input_tokens": 4000,
        "max_rpm": 60
    },
    "persona": {
        "system": { "hostname": "fallback-system" },
        "prompts": { "system_prompt": "Error: Persona failed to load." }
    }
}

class ConfigManager:
    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        # Start with defaults as a simple dict
        self._raw_config = DEFAULT_CONFIG_DICT.copy()
        
        # 1. Load User Config (config.yaml)
        self.load_config_file()
        
        # 2. Load Defaults/Environment Overrides
        self.load_env_overrides()

        # 3. Load Persona (Default + Override)
        self.load_persona()

        # 4. Validate with Pydantic
        try:
            self.model = AppConfig(**self._raw_config)
            # Dump back to dict to maintain existing get() behavior easily
            # excluding defaults to keep any extra persona keys? 
            # AppConfig allows extra in persona, so model_dump() is safe.
            self._config = self.model.model_dump()
        except Exception as e:
            print(f"[!] CRITICAL CONFIG VALIDATION ERROR: {e}")
            print("Using Unvalidated Config as fallback to prevent crash (risky).")
            self._config = self._raw_config

    def load_config_file(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        self._deep_merge(self._raw_config, user_config)
            except Exception as e:
                print(f"[!] Error loading config yaml: {e}")

    def load_env_overrides(self):
        if os.getenv("WEBHOOK_URL"):
            if 'alerting' not in self._raw_config: self._raw_config['alerting'] = {}
            self._raw_config['alerting']['webhook_url'] = os.getenv("WEBHOOK_URL")
        
        # Integers
        for env_key, conf_sec, conf_key in [
            ("ALERT_THRESHOLD_NOTIFY", "alerting", "notify_threshold"),
            ("ALERT_THRESHOLD_SESSION", "alerting", "session_threshold"),
            ("ALERT_THRESHOLD_IP", "alerting", "ip_threshold"),
            ("SSHPOT_MCP_PORT", "mcp", "port"),
            ("SSHPOT_HTTP_PORT", "http", "port"), 
            ("HTTP_LLM_RPM", "http", "llm_rpm"),
            ("HTTP_LLM_RPD", "http", "llm_rpd"), 
        ]:
            val = os.getenv(env_key)
            if val:
                try: 
                    if conf_sec not in self._raw_config: self._raw_config[conf_sec] = {}
                    self._raw_config[conf_sec][conf_key] = int(val)
                except: pass

        if os.getenv("ALERT_KEYWORDS"):
             self._raw_config['alerting']['keywords'] = [k.strip() for k in os.getenv("ALERT_KEYWORDS").split('|') if k.strip()]

    def load_persona(self, override_name=None):
        base_name = "CentOS7_Legacy_Compute"
        personas_dir = os.path.join(PROJECT_ROOT, "personas")
        
        # Base
        base_config = self._read_persona_file(base_name, personas_dir)
        if base_config:
            # Flatten 'system' if needed for backward compatibility
            if 'system' in base_config:
                 for k, v in base_config['system'].items():
                      base_config[k] = v
            
            self._raw_config['persona'] = base_config
        
        # Override
        target = override_name or os.getenv("SSH_PERSONA")
        if target and target != base_name:
            print(f"[*] Loading Persona Override: {target}")
            override_config = self._read_persona_file(target, personas_dir)
            if override_config:
                self._deep_merge(self._raw_config['persona'], override_config)

    def _read_persona_file(self, name_or_path, personas_dir):
        # ... Reuse logic ...
        # Simplified for brevity in replace
        fpath = None
        if os.path.exists(name_or_path) and (name_or_path.endswith('.yaml') or os.path.isdir(name_or_path)):
             fpath = os.path.join(name_or_path, 'persona.yaml') if os.path.isdir(name_or_path) else name_or_path
        else:
             fpath = os.path.join(personas_dir, name_or_path, 'persona.yaml')
            
        if os.path.exists(fpath):
            try:
                with open(fpath, 'r') as f:
                    data = yaml.safe_load(f)
                    data['_fs_path'] = os.path.join(os.path.dirname(fpath), 'fs')
                    return data
            except: return None
        return None

    def get_persona_by_name(self, persona_name):
        """
        Loads a specific persona configuration by name.
        Does NOT modify the global configuration.
        Returns a dict.
        """
        personas_dir = os.path.join(PROJECT_ROOT, "personas")
        
        # 1. Load Base (Optional, but good for fallbacks)
        base_name = "CentOS7_Legacy_Compute"
        base_config = self._read_persona_file(base_name, personas_dir) or {}
        if 'system' in base_config:
             for k, v in base_config['system'].items():
                  base_config[k] = v

        # 2. Load Target
        target_config = self._read_persona_file(persona_name, personas_dir)
        
        if not target_config:
            return base_config # Fallback to base if target not found
            
        # 3. Merge
        self._deep_merge(base_config, target_config)
        return base_config

    def _deep_merge(self, base, update):
        for k, v in update.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v

    def get(self, *keys):
        val = self._config
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return None # Obj access?
            if val is None: return None
        return val

config = ConfigManager()

