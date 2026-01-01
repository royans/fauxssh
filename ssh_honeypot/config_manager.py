import yaml
import os

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
        "temperature": 1.0
    },
    "logging": {
        "json_log_file": "data/honeypot.json.log"
    },
    "upload": {
        "max_file_size": 1048576, # 1MB
        "max_quota_per_ip": 1048576, # 1MB
        "cleanup_days": 30
    }
}

class ConfigManager:
    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        self._config = DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        self._merge(self._config, user_config)
                print(f"[*] Loaded configuration from {self.config_path}")
            except Exception as e:
                print(f"[!] Error loading config: {e}")
        else:
            print("[*] No config.yaml found, using defaults.")

    def _merge(self, defaults, overrides):
        for k, v in overrides.items():
            if isinstance(v, dict) and k in defaults:
                self._merge(defaults[k], v)
            else:
                defaults[k] = v

    def get(self, *keys):
        val = self._config
        for k in keys:
            val = val.get(k)
            if val is None: return None
        return val

# Global instance
config = ConfigManager()
