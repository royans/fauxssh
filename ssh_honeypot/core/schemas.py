from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import os
from ssh_honeypot.core.utils import get_data_dir


class ServerConfig(BaseModel):
    # Use Field(default_factory=...) to evaluate at runtime
    host_key_file: str = Field(
        default_factory=lambda: os.path.join(get_data_dir(), "host.key")
    )
    port: int = 2222
    bind_ip: str = "0.0.0.0"
    hostname: str = "web.blogofy.com"
    banner_default: Optional[str] = None


class LLMConfig(BaseModel):
    model_name: str = "gemini-pro"
    api_key: str = ""
    max_tokens: int = 2048
    temperature: float = 1.0
    timeout: int = 60


class LoggingConfig(BaseModel):
    json_log_file: str = Field(
        default_factory=lambda: os.path.join(get_data_dir(), "honeypot.json.log")
    )
    enable_session_replay: bool = False


class UploadConfig(BaseModel):
    max_file_size: int = 1048576  # 1MB
    max_quota_per_ip: int = 1048576  # 1MB
    cleanup_days: int = 30


class AlertingConfig(BaseModel):
    webhook_url: Optional[str] = None
    notify_threshold: int = 6
    session_threshold: int = 7
    ip_threshold: int = 9
    keywords: List[str] = Field(default_factory=list)
    service_thresholds: Dict[str, Dict[str, int]] = Field(default_factory=dict)


class MCPConfig(BaseModel):
    enabled: bool = True
    port: int = 8000
    max_llm_calls: int = 20
    throttle_delay: float = 2.0


class RealismConfig(BaseModel):
    latency: Dict[str, Any] = Field(
        default_factory=lambda: {"enabled": True, "min_ms": 20, "max_ms": 300}
    )


class SecurityConfig(BaseModel):
    max_input_length: int = 50000  # Raw chars
    max_input_tokens: int = 4000  # Approx token limit (4 chars/token heuristic)
    max_rpm: int = 60  # Rate Limit Requests Per Minute
    virustotal: Optional[Dict[str, Any]] = None


class VirusTotalConfig(BaseModel):
    enabled: bool = False
    api_key: Optional[str] = None
    upload_files: bool = True
    min_file_size: int = 500


class PersonaSystemConfig(BaseModel):
    hostname: str = "fallback-system"

    # Allow extra fields for backward compat
    class Config:
        extra = "allow"


class PersonaPromptsConfig(BaseModel):
    system_prompt: str = "Error: Persona failed to load."
    generate_content: Optional[str] = None
    analysis: Optional[str] = None


class PersonaConfig(BaseModel):
    system: PersonaSystemConfig = Field(default_factory=PersonaSystemConfig)
    prompts: PersonaPromptsConfig = Field(default_factory=PersonaPromptsConfig)

    # Allow arbitrary keys like 'network', 'files' etc
    class Config:
        extra = "allow"


class HttpConfig(BaseModel):
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
    ignore_ips: List[str] = Field(default_factory=list)
    show_empty_sessions: bool = False


class TelnetConfig(BaseModel):
    enabled: bool = True
    port: int = 2323


class RedisConfig(BaseModel):
    enabled: bool = True
    port: int = 6379


class ThrottlingDosConfig(BaseModel):
    rpm: int = 120
    rph: int = 3600
    rpd: int = 20000


class ThrottlingLLMConfig(BaseModel):
    rpm: int = 5
    rph: int = 60
    rpd: int = 200


class ThrottlingConfig(BaseModel):
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
    host: str = "localhost"
    port: int = 5432
    user: str = "honeypot"
    password: str = ""
    dbname: str = "logs"


class DatabaseConfig(BaseModel):
    type: str = "sqlite"  # sqlite, postgres
    postgres: PostgresConfig = Field(default_factory=PostgresConfig)


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
    throttling: ThrottlingConfig = Field(default_factory=ThrottlingConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
