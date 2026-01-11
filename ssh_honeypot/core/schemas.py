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


class MCPConfig(BaseModel):
    # Enabled/Port are env vars, but we can store them here for completeness if we accepted them from yaml
    # But usually Main reads ENV. We'll leave them out or optional.
    max_llm_calls: int = 20
    throttle_delay: float = 2.0


class RealismConfig(BaseModel):
    latency: Dict[str, Any] = Field(
        default_factory=lambda: {"enabled": True, "min_ms": 20, "max_ms": 300}
    )
    # We could use a nested model but Dict is flexible for now


class SecurityConfig(BaseModel):
    max_input_length: int = 50000  # Raw chars
    max_input_tokens: int = 4000  # Approx token limit (4 chars/token heuristic)
    max_rpm: int = 60  # Rate limit per IP


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
    llm_rpm: int = 4
    llm_rpd: int = 20


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
    persona: PersonaConfig = Field(default_factory=PersonaConfig)
