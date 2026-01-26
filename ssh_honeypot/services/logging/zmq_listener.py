import json
import logging
import os
import signal
import sys
import time

from dotenv import load_dotenv
import zmq
from zmq.auth.thread import ThreadAuthenticator

# Add project root to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(BASE_DIR)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

# Load env from project root
env_path = os.path.join(PROJECT_ROOT, ".env")
load_dotenv(env_path)

from ssh_honeypot.core.logging_setup import log


def main():
    log.info("[ZmqListener] Starting centralized log aggregation server...")

    zmq_url = os.getenv("LOGGING_ZMQ_URL", "tcp://0.0.0.0:5555")

    # Simple port extraction (tcp://host:port)
    try:
        bind_port = zmq_url.split(":")[-1]
        bind_url = f"tcp://0.0.0.0:{bind_port}"
    except Exception:
        bind_url = "tcp://0.0.0.0:5555"

    allow_user = os.getenv("LOGGING_ZMQ_USER", "admin")
    shared_secret = os.getenv("LOGGING_ZMQ_PASS", "secret")

    context = zmq.Context()
    auth = ThreadAuthenticator(context)
    auth.start()

    # Security Check: Prevent usage of default placeholder password
    if shared_secret == "secret_password_here":
        log.error(
            "[ZmqListener] CRITICAL SECURITY RISK: LOGGING_ZMQ_PASS is set "
            "to the default placeholder. Server will not start."
        )
        return

    # Allow the configured user
    users_passwords = {allow_user.strip(): shared_secret}

    auth.configure_plain(domain="*", passwords=users_passwords)

    server = context.socket(zmq.PULL)
    server.plain_server = True  # Enable PLAIN auth
    server.bind(bind_url)

    log.info("[ZmqListener] Listening on %s", bind_url)
    log.info("[ZmqListener] Authenticator active. Allowed user: %s", allow_user)

    # Import slogger only after path setup
    try:
        from ssh_honeypot.core.slogging import slogger

        log.info("[ZmqListener] Connected to Slogging Processor (DB/LLM)")
    except ImportError as e:
        log.error("[ZmqListener] Failed to import slogging: %s", e)
        return

    # Signal handling
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        log.info("[ZmqListener] Shutting down...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while running:
        try:
            # Poll with timeout to allow checking 'running' flag
            if server.poll(1000):
                msg = server.recv_json()
                if isinstance(msg, list):
                    # It's a batch
                    slogger.handle_batch(msg)
                else:
                    # Single event? Wrap in list
                    slogger.handle_batch([msg])
        except zmq.ZMQError as e:
            if running:
                log.error("[ZmqListener] ZMQ Error: %s", e)
        except Exception as e:
            log.error("[ZmqListener] Processing Error: %s", e)

    auth.stop()
    server.close()
    context.term()
    log.info("[ZmqListener] Stopped.")


if __name__ == "__main__":
    main()
