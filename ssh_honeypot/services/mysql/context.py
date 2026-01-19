from contextvars import ContextVar

client_ip_ctx = ContextVar("client_ip", default="0.0.0.0")
