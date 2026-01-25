# config.py
import yaml
import os
import copy
from ssh_honeypot.core.utils import (
    PROJECT_ROOT,
    BASE_DIR,
    get_data_dir,
    get_version,
    get_ignored_ips,
)

try:
    from ssh_honeypot.core.schemas import AppConfig
except ImportError:
    # Bootstrap or missing dependencies
    AppConfig = None

try:
    from dotenv import load_dotenv
except ImportError:

    def load_dotenv(*args, **kwargs):
        pass


DEFAULT_CONFIG_DICT = {
    "server": {
        "host_key_file": os.path.join(get_data_dir(), "host.key"),
        "port": 2222,
        "bind_ip": "0.0.0.0",
        "hostname": "web.blogofy.com",
    },
    "http": {
        "port": 8080,
        "enabled": True,
        "server_header": "Apache/2.4.52 (Ubuntu)",
        "web_root": "/var/www/html",
        "showstats": True,
        "llm_rpm": 4,
        "llm_rpd": 20,
        "headers": {"X-Content-Type-Options": "nosniff"},
    },
    "llm": {
        "model_name": "gemma-3-27b-it",
        "api_key": "",
        "max_tokens": 2048,
        "temperature": 1.0,
        "timeout": 60,
    },
    "virustotal": {
        "enabled": False,
        "api_key": "",
        "upload_files": True,
        "min_file_size": 500,
    },
    "analytics": {"ignore_ips": [], "show_empty_sessions": False},
    "alerting": {
        "webhook_url": "",
        "notify_threshold": 60,
        "session_threshold": 70,
        "ip_threshold": 90,
        "keywords": [],
    },
    "telnet": {"enabled": True, "port": 2323},
    "redis": {"enabled": True, "port": 6379},
    "mysql": {
        "enabled": True,
        "port": 3306,
        "auth": {
            "allow_any": False,
            "allow_any_rate": 0.5,
            "weak_passwords": ["root:root", "admin:admin", "test:test"],
        },
    },
    "mcp": {
        "enabled": True,
        "port": 8000,
        "max_llm_calls": 20,
        "throttle_delay": 2.0,
    },
    "logging": {
        "level": "INFO",
        "file": os.path.join(get_data_dir(), "fauxssh.log"),
        "json_log_file": os.path.join(get_data_dir(), "events.json.log"),
        "enable_session_replay": False,
        "modules": {},
        "centralized": {
            "enabled": True,
            "mode": "local",  # [local, remote, both]
            "server_name": "hp-default",
            "remote_url": "",
            "api_key": "",
            "batch_size": 50,
            "batch_timeout": 10,
            "compression": True,
        },
        "disable_batching": False,
    },
    "upload": {
        "max_file_size": 1048576,
        "max_quota_per_ip": 1048576,
        "cleanup_days": 30,
    },
    "security": {"max_input_length": 50000, "max_input_tokens": 4000, "max_rpm": 60},
    "persona": {
        "system": {"hostname": "fallback-system"},
        "prompts": {"system_prompt": "Error: Persona failed to load."},
    },
    "throttling": {
        "dos": {"rpm": 120, "rph": 3600, "rpd": 20000},
        "llm": {"rpm": 5, "rph": 60, "rpd": 200},
    },
    "database": {
        "type": "sqlite",
        "postgres": {
            "host": "localhost",
            "port": 5432,
            "user": "honeypot",
            "password": "",
            "dbname": "logs",
        },
    },
}


class ConfigManager:
    def __init__(self, config_path="config.yaml"):
        self.config_path = config_path
        # Use deepcopy to ensure we don't mutate the global default
        self._raw_config = copy.deepcopy(DEFAULT_CONFIG_DICT)
        self._persona_cache = {}  # Cache for loaded persona YAMLs

        # 0. Load .env (Project Root or Parent)
        self._load_env()

        # 1. Load User Config (config.yaml)
        self.load_config_file()

        # 2. Load Defaults/Environment Overrides
        self.load_env_overrides()

        # 3. Load Persona (Default + Override)
        self.load_persona()

        # 4. Validate with Pydantic (Initial)
        self._validate_and_refresh()

    def _validate_and_refresh(self):
        if AppConfig is None:
            # Avoid crashing if dependencies are missing (e.g. pydantic)
            print(
                "[!] Warning: AppConfig schema not available (missing dependencies?). Validation skipped."
            )
            self._config = self._raw_config
            return

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
        # 1. Try provided path (relative to CWD)
        if os.path.exists(self.config_path):
            pass
        # 2. Try Project Root (if CWD is different)
        elif os.path.exists(os.path.join(PROJECT_ROOT, self.config_path)):
            self.config_path = os.path.join(PROJECT_ROOT, self.config_path)

        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        self._deep_merge(self._raw_config, user_config)
            except Exception as e:
                print(f"[!] Error loading config yaml: {e}")
            except Exception as e:
                print(f"[!] Error loading config yaml: {e}")

    def _load_env(self):
        """Robustly load .env from project root or parent."""
        env_files = [
            os.path.join(PROJECT_ROOT, ".env"),
            os.path.join(os.path.dirname(PROJECT_ROOT), ".env"),
        ]
        for env_path in env_files:
            if os.path.exists(env_path):
                load_dotenv(env_path)

    def load_env_overrides(self):
        """
        Recursively overrides config values with environment variables.
        Schema: SECTION_SUB_KEY -> section.sub.key (e.g. LLM_MODEL_NAME -> llm.model_name)
        """
        self._apply_env_recursive(self._raw_config)

        # Legacy / Special Mappings (Backward Compatibility)
        if os.getenv("WEBHOOK_URL") and not os.getenv("ALERTING_WEBHOOK_URL"):
            self._raw_config["alerting"]["webhook_url"] = os.getenv("WEBHOOK_URL")

        if os.getenv("FAUXSSH_VIRUSTOTAL_API_KEY") and not os.getenv(
            "VIRUSTOTAL_API_KEY"
        ):
            self._raw_config["virustotal"]["api_key"] = os.getenv(
                "FAUXSSH_VIRUSTOTAL_API_KEY"
            )
            self._raw_config["virustotal"]["enabled"] = True

        if os.getenv("GOOGLE_API_KEY") and not os.getenv("LLM_API_KEY"):
            self._raw_config["llm"]["api_key"] = os.getenv("GOOGLE_API_KEY")

        # Config Lists from Strings
        # ALERT_KEYWORDS -> alerting.keywords
        if os.getenv("ALERT_KEYWORDS") and not os.getenv("ALERTING_KEYWORDS"):
            self._raw_config["alerting"]["keywords"] = [
                k.strip() for k in os.getenv("ALERT_KEYWORDS").split("|") if k.strip()
            ]

        # Service-Specific Risk Thresholds (Format: "ssh:50,70,90;http:60,80,95")
        if os.getenv("FAUXSSH_RISK_THRESHOLDS"):
            service_thresholds = {}
            raw_str = os.getenv("FAUXSSH_RISK_THRESHOLDS", "")
            pairs = raw_str.split(";")
            for pair in pairs:
                if ":" in pair:
                    svc, vals = pair.split(":", 1)
                    svc = svc.strip().lower()
                    try:
                        thresholds = [int(x.strip()) for x in vals.split(",")]
                        if len(thresholds) == 3:
                            service_thresholds[svc] = {
                                "notify_threshold": thresholds[0],
                                "session_threshold": thresholds[1],
                                "ip_threshold": thresholds[2],
                            }
                    except Exception as e:
                        print(
                            f"[!] config: Failed to parse risk threshold for '{svc}': {e}"
                        )

            if service_thresholds:
                self._raw_config["alerting"]["service_thresholds"] = service_thresholds

        # Final Pass: Auto-enable services based on presence of secrets
        # specific to VirusTotal (as per test_config_sanity requirements)
        vt = self._raw_config.get("virustotal")
        if vt and vt.get("api_key") and len(vt.get("api_key")) > 5:
            if not self._raw_config.get("virustotal"):
                self._raw_config["virustotal"] = {}
            self._raw_config["virustotal"]["enabled"] = True

    def _apply_env_recursive(self, current_dict, prefix=""):
        for key, value in current_dict.items():
            # Calculate Env Var Name
            # e.g. prefix="LLM", key="model_name" -> LLM_MODEL_NAME
            # e.g. prefix="", key="server" -> SERVER
            env_key = f"{prefix}_{key}".upper() if prefix else key.upper()

            if isinstance(value, dict):
                self._apply_env_recursive(value, prefix=env_key)
            else:
                # Leaf Node - Check Env
                env_val = os.getenv(env_key)
                if env_val is not None:
                    try:
                        # Type Casting
                        if isinstance(value, bool):
                            current_dict[key] = str(env_val).lower() in (
                                "true",
                                "1",
                                "yes",
                                "on",
                            )
                        elif isinstance(value, int):
                            current_dict[key] = int(env_val)
                        elif isinstance(value, float):
                            current_dict[key] = float(env_val)
                        elif isinstance(value, list):
                            # Comma separated list
                            current_dict[key] = [
                                x.strip() for x in env_val.split(",") if x.strip()
                            ]
                        else:
                            current_dict[key] = str(env_val)
                    except Exception as e:
                        print(
                            f"[!] Config: Error casting env var {env_key}='{env_val}': {e}"
                        )

    def load_persona(self, override_name=None):
        base_name = "CentOS7_Legacy_Compute"
        personas_dir = os.path.join(PROJECT_ROOT, "personas")

        # 1. Start with Base Config (CentOS 7) always as foundation
        # This ensures we have a valid structure even if target is partial
        base_config = self._read_persona_file(base_name, personas_dir)
        if base_config:
            # Flatten 'system' for backward compatibility if needed
            if "system" in base_config:
                for k, v in base_config["system"].items():
                    base_config[k] = v
            self._raw_config["persona"] = base_config

        # 2. Determine Target Persona
        # Precedence: Explicit Override (CLI) > Env Var > Last Used State > Default
        target = override_name

        if not target:
            target = os.getenv("SSH_PERSONA")

        if not target:
            try:
                from ssh_honeypot.core.state_manager import StateManager

                target = StateManager.get_last_persona()
            except ImportError:
                pass

        if not target:
            target = base_name

        # 3. Load Target (if different from base)
        if target and target != base_name:
            print(f"[*] Loading Persona: {target}")
            override_config = self._read_persona_file(target, personas_dir)
            if override_config:
                self._deep_merge(self._raw_config["persona"], override_config)
            else:
                print(
                    f"[!] Warning: Persona '{target}' not found. Falling back to {base_name}."
                )

        # 4. Refresh derived config
        self._validate_and_refresh()

    def _read_persona_file(self, name_or_path, personas_dir_ignored=None):
        # We ignore the passed personas_dir arg in favor of our multi-path logic
        # But keep signature compatible just in case

        # Candidate Directories
        search_dirs = [
            os.path.join(PROJECT_ROOT, "personas"),  # Code-based (Base)
            os.path.join(get_data_dir(), "personas"),  # Data-based (Dynamic)
        ]

        # 1. Direct Path check
        if os.path.exists(name_or_path):
            if os.path.isdir(name_or_path):
                return self._load_yaml_fs(os.path.join(name_or_path, "persona.yaml"))
            elif name_or_path.endswith(".yaml"):
                return self._load_yaml_fs(name_or_path)

        # 2. Search in initialized directories
        for p_dir in search_dirs:
            candidate = os.path.join(p_dir, name_or_path, "persona.yaml")
            if os.path.exists(candidate):
                # Check cache first
                if candidate in self._persona_cache:
                    return copy.deepcopy(self._persona_cache[candidate])

                data = self._load_yaml_fs(candidate)
                if data:
                    self._persona_cache[candidate] = copy.deepcopy(data)
                return data

        return None

    def _load_yaml_fs(self, yaml_path):
        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)
                # FS path is sibling to yaml typically
                data["_fs_path"] = os.path.join(os.path.dirname(yaml_path), "fs")
                return data
        except Exception as e:
            print(f"Error loading persona yaml {yaml_path}: {e}")
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
        if "system" in base_config:
            for k, v in base_config["system"].items():
                base_config[k] = v

        # 2. Load Target
        target_config = self._read_persona_file(persona_name, personas_dir)

        if not target_config:
            return base_config  # Fallback to base if target not found

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
                return None  # Obj access?
            if val is None:
                return None
        return val

    def get_rate_limit(self, service, type_, metric):
        """
        Resolves rate limit with layered precedence:
        1. Service Override (e.g. ssh.throttling.llm_rpm OR ssh.throttling.llm.rpm)
        2. Global Throttling (e.g. throttling.llm.rpm)
        3. Hardcoded Default fallback
        """
        metric = metric.lower()
        type_ = type_.lower()

        # 1. Service Override
        # Check flat key first (e.g. ssh.throttling.llm_rpm)
        svc_config = self.get(service, "throttling")
        if svc_config:
            # Try flat key "llm_rpm"
            val = svc_config.get(f"{type_}_{metric}")
            if val is not None:
                return int(val)
            # Try nested key "llm" -> "rpm"
            if type_ in svc_config and isinstance(svc_config[type_], dict):
                val = svc_config[type_].get(metric)
                if val is not None:
                    return int(val)

        # 2. Global Throttling
        val = self.get("throttling", type_, metric)
        if val is not None:
            return int(val)

        # 3. Fallback (Safe Defaults if config is borked)
        defaults = {
            "dos": {"rpm": 120, "rph": 3600, "rpd": 20000},
            "llm": {"rpm": 5, "rph": 60, "rpd": 200},
        }
        return defaults.get(type_, {}).get(metric, 100)


config = ConfigManager()
