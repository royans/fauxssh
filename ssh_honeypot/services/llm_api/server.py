import http.server
import socketserver
import threading
import socket
import os
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from .ollama_handler import OllamaHandler
from .openai_handler import OpenAIHandler


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_llm_api_service(db, llm_interface):
    """Starts the LLM API listeners (Ollama/OpenAI) based on config."""

    # 1. Start Ollama Listener
    if config.get("llm_api", "ollama", "enabled"):
        port = config.get("llm_api", "ollama", "port") or 11434
        t = threading.Thread(
            target=_run_server, args=(port, OllamaHandler, "Ollama"), daemon=True
        )
        t.start()
        log.info(f"[LLM-API] Started Ollama listener on port {port}")

    # 2. Start OpenAI Listener
    if config.get("llm_api", "openai", "enabled"):
        port = config.get("llm_api", "openai", "port") or 8000
        t = threading.Thread(
            target=_run_server, args=(port, OpenAIHandler, "OpenAI"), daemon=True
        )
        t.start()


def _run_server(port, handler_class, name):
    try:
        bind_ip = (
            os.getenv("FAUXSSH_BIND_IP") or config.get("server", "bind_ip") or "0.0.0.0"
        )

        # Address Family Detection
        original_family = ThreadingHTTPServer.address_family
        if ":" in bind_ip or bind_ip == "::":
            ThreadingHTTPServer.address_family = socket.AF_INET6
        else:
            ThreadingHTTPServer.address_family = socket.AF_INET

        server = ThreadingHTTPServer(
            (bind_ip, port), handler_class, bind_and_activate=False
        )

        # Restore original family to avoid polluting global state
        ThreadingHTTPServer.address_family = original_family

        # Enable Dual Stack (IPv4 fallback on IPv6 socket) if binding ::
        if server.address_family == socket.AF_INET6 and bind_ip == "::":
            try:
                IPPROTO_IPV6 = getattr(socket, "IPPROTO_IPV6", 41)
                IPV6_V6ONLY = getattr(socket, "IPV6_V6ONLY", 26)
                server.socket.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            except Exception as e:
                log.warning(f"[{name}] Could not set IPV6_V6ONLY=0: {e}")

        server.server_bind()
        server.server_activate()

        log.info(f"[{name}] Started {name} listener on {bind_ip}:{port}")
        server.serve_forever()
    except Exception as e:
        log.error(f"[{name}] Failed to start listener on {port}: {e}")
