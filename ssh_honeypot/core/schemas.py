from pydantic import BaseModel, Field, validator, ConfigDict
from typing import List, Optional, Dict, Any
import os
from ssh_honeypot.core.utils import get_data_dir


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    # Use Field(default_factory=...) to evaluate at runtime
    host_key_file: str = Field(
        default_factory=lambda: os.path.join(get_data_dir(), "host.key")
    )
    port: int = 2222
    bind_ip: str = "0.0.0.0"
    hostname: str = "web.blogofy.com"
    banner_default: Optional[str] = None


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    model_name: str = "gemini-pro"
    api_key: str = ""
    max_tokens: int = 2048
    temperature: float = 1.0
    timeout: int = 60


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    level: str = "INFO"
    file: str = Field(
        default_factory=lambda: os.path.join(get_data_dir(), "fauxssh.log")
    )
    json_log_file: str = Field(
        default_factory=lambda: os.path.join(get_data_dir(), "events.json.log")
    )
    enable_session_replay: bool = False
    modules: Dict[str, str] = Field(default_factory=dict)


class UploadConfig(BaseModel):
    max_file_size: int = 1048576  # 1MB
    max_quota_per_ip: int = 1048576  # 1MB
    cleanup_days: int = 30


class AlertingConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    webhook_url: Optional[str] = None
    # ...


class MCPConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    enabled: bool = True
    port: int = 8000
    max_llm_calls: int = 20
    throttle_delay: float = 2.0


class RealismConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    latency: Dict[str, Any] = Field(
        default_factory=lambda: {"enabled": True, "min_ms": 20, "max_ms": 300}
    )


class SecurityConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    max_input_length: int = 50000  # Raw chars
    max_input_tokens: int = 4000  # Approx token limit (4 chars/token heuristic)
    max_rpm: int = 60  # Rate Limit Requests Per Minute
    virustotal: Optional[Dict[str, Any]] = None


class VirusTotalConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    enabled: bool = False
    api_key: Optional[str] = None
    upload_files: bool = True
    min_file_size: int = 500


class PersonaSystemConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    hostname: str = "fallback-system"


class PersonaPromptsConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    system_prompt: str = "Error: Persona failed to load."
    generate_content: Optional[str] = None
    analysis: Optional[str] = None


class PersonaConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    system: PersonaSystemConfig = Field(default_factory=PersonaSystemConfig)
    prompts: PersonaPromptsConfig = Field(default_factory=PersonaPromptsConfig)


class HttpConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    port: int = 8080
    enabled: bool = True
    server_header: str = "Apache/2.4.52 (Ubuntu)"
    web_root: str = "/var/www/html"
    llm_rpm: int = 4
    llm_rpd: int = 20
    headers: Dict[str, str] = Field(
        default_factory=lambda: {"X-Content-Type-Options": "nosniff"}
    )


class AnalyticsConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    ignore_ips: List[str] = Field(default_factory=list)
    show_empty_sessions: bool = False


class TelnetConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    port: int = 2323


class RedisConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    enabled: bool = True
    port: int = 6379


class MySqlAuthConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    allow_any: bool = False
    allow_any_rate: float = 0.5
    weak_passwords: List[str] = Field(
        default_factory=lambda: ["root:root", "admin:admin", "test:test"]
    )


class MySqlConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    enabled: bool = True
    port: int = 3306
    auth: MySqlAuthConfig = Field(default_factory=MySqlAuthConfig)


class ThrottlingDosConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    rpm: int = 120
    rph: int = 3600
    rpd: int = 20000


class ThrottlingLLMConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    rpm: int = 5
    rph: int = 60
    rpd: int = 200


class ThrottlingConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    dos: ThrottlingDosConfig = Field(default_factory=ThrottlingDosConfig)
    llm: ThrottlingLLMConfig = Field(default_factory=ThrottlingLLMConfig)


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    upload: UploadConfig = Field(default_factory=UploadConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    realism: RealismConfig = Field(default_factory=RealismConfig)
    virustotal: VirusTotalConfig = Field(default_factory=VirusTotalConfig)
    persona: PersonaConfig = Field(default_factory=PersonaConfig)
    analytics: AnalyticsConfig = Field(default_factory=AnalyticsConfig)
    telnet: TelnetConfig = Field(default_factory=TelnetConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)


class PostgresConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    host: str = "localhost"
    port: int = 5432
    user: str = "honeypot"
    password: str = ""
    dbname: str = "logs"


class DatabaseConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str = "sqlite"  # sqlite, postgres
    postgres: PostgresConfig = Field(default_factory=PostgresConfig)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    server: ServerConfig = Field(default_factory=ServerConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    upload: UploadConfig = Field(default_factory=UploadConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    realism: RealismConfig = Field(default_factory=RealismConfig)
    virustotal: VirusTotalConfig = Field(default_factory=VirusTotalConfig)
    persona: PersonaConfig = Field(default_factory=PersonaConfig)
    analytics: AnalyticsConfig = Field(default_factory=AnalyticsConfig)
    telnet: TelnetConfig = Field(default_factory=TelnetConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    mysql: MySqlConfig = Field(default_factory=MySqlConfig)
    throttling: ThrottlingConfig = Field(default_factory=ThrottlingConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
