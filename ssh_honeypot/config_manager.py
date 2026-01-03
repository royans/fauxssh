# config_manager.py
import yaml
import os
from dotenv import load_dotenv, find_dotenv

# Load environment variables from .env file (searching parent directories)
load_dotenv(find_dotenv(usecwd=True))

# Base directory relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

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
        "json_log_file": "data/honeypot.json.log"
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
        "kernel_name": "Linux",
        "kernel_release": "5.10.0-21-cloud-amd64",
        "kernel_version": "#1 SMP Debian 5.10.162-1 (2023-01-21)",
        "machine": "x86_64",
        "processor": "x86_64",
        "hardware_platform": "x86_64",
        "os_name": "GNU/Linux",
        "distro_name": "Debian GNU/Linux",
        "distro_version": "11 (bullseye)",
        "distro_id": "debian",
        "distro_version_id": "11",
        "distro_pretty_name": "Debian GNU/Linux 11 (bullseye)",
        "processor_version": "Intel(R) Xeon(R) Platinum 8480+"
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

        # Environment Override (Priority over config.yaml)
        if os.getenv("WEBHOOK_URL"):
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
