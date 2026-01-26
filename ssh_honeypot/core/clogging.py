import gzip
import json
import logging
import os
import socket
import threading
import time
import uuid
from datetime import datetime

from ssh_honeypot.core.config import config
from ssh_honeypot.core.event_logger import EventLogger
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.utils import sanitize_obj

try:
    import zmq
except ImportError:
    zmq = None


class ClientLogger:
    """
    'clogging' - Client-side logging component.
    Buffers events locally and ships them to slogging (local or remote/ZMQ).
    Separates emission from analysis.
    """

    def __init__(self):
        # Configuration Priorities: Env > Config > Default
        self.enabled = config.get("logging", "centralized", "enabled") or True

        # Mode: local, zmq, both (default: local)
        self.log_mode = os.getenv(
            "CLOGGING_MODE", config.get("logging", "centralized", "mode") or "local"
        ).lower()

        # Use system hostname as default if not explicitly set
        self.server_name = os.getenv("CLOGGING_SERVER_NAME") or config.get(
            "logging", "centralized", "server_name"
        )
        if not self.server_name or self.server_name == "hp-default":
            self.server_name = socket.gethostname()

        # Check for test mode or explicit disable to ensure immediate flushes
        disable_batching = (
            os.getenv("LOGGING_DISABLE_BATCHING", "false").lower() == "true"
            or os.getenv("FAUXSSH_TEST_MODE") == "true"
        )

        self.settings = {
            "batch_size": (
                1
                if disable_batching
                else (config.get("logging", "centralized", "batch_size") or 50)
            ),
            "batch_timeout": (
                0
                if disable_batching
                else (config.get("logging", "centralized", "batch_timeout") or 10)
            ),
            "remote_url": config.get("logging", "centralized", "remote_url"),
            "api_key": config.get("logging", "centralized", "api_key"),
            "use_compression": config.get("logging", "centralized", "compression")
            or True,
        }

        self._buffer = []
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._shutdown = False
        self._stop_event = threading.Event()
        self._event_logger = EventLogger()

        # ZMQ Setup
        self.zmq_context = None
        self.zmq_socket = None

        # Safety Check: Prevent duplicate logging if 'both' and ZMQ is local
        if "both" in self.log_mode:
            zmq_url = os.getenv("LOGGING_ZMQ_URL", "")
            if self._is_local_host(zmq_url):
                log.warning(
                    "[Clogging] Configuration 'both' detected with local ZMQ URL (%s). "
                    "Switching to 'zmq' mode to prevent duplicate logs.",
                    zmq_url,
                )
                self.log_mode = "zmq"

        if "zmq" in self.log_mode or "both" in self.log_mode:
            if zmq:
                self._setup_zmq()
            else:
                log.warning(
                    "[Clogging] ZMQ mode requested but 'pyzmq' not installed. "
                    "Falling back to local."
                )
                self.log_mode = "local"

        # Start flusher thread
        self._flusher = threading.Thread(target=self._flusher_loop, daemon=True)
        self._flusher.start()

        log.info(
            "[Clogging] Initialized in '%s' mode for server '%s'",
            self.log_mode,
            self.server_name,
        )

    def _is_local_host(self, url):
        """Checks if a ZMQ URL points to the local machine."""
        if not url:
            return False
        try:
            # Parse tcp://host:port
            if "://" in url:
                host = url.split("://")[1].split(":")[0]
            else:
                host = url  # Fallback if just host? Unlikely for ZMQ URL

            # Common loopback identifiers
            if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", ""):
                return True

            # Check against local hostname IP
            if host == socket.gethostname():
                return True
            try:
                if host == socket.gethostbyname(socket.gethostname()):
                    return True
            except socket.error:
                pass

        except Exception:  # Catch other parsing/network errors
            pass
        return False

    def _setup_zmq(self):
        try:
            url = os.getenv("LOGGING_ZMQ_URL")
            if not url:
                log.error("[Clogging] ZMQ enabled but LOGGING_ZMQ_URL not set.")
                return

            self.zmq_context = zmq.Context()
            self.zmq_socket = self.zmq_context.socket(zmq.PUSH)

            # Auth (PLAIN)
            user = os.getenv("LOGGING_ZMQ_USER")
            password = os.getenv("LOGGING_ZMQ_PASS")

            # Security Check: Prevent usage of default placeholder password
            if password == "secret_password_here":
                log.error(
                    "[Clogging] ZMQ Security Risk: LOGGING_ZMQ_PASS is set to "
                    "the default placeholder. ZMQ logging disabled for safety."
                )
                self.zmq_socket = None
                return

            if user and password:
                self.zmq_socket.plain_username = user.encode("utf-8")
                self.zmq_socket.plain_password = password.encode("utf-8")

            # Reliability settings
            self.zmq_socket.setsockopt(zmq.LINGER, 0)  # Don't hang on close
            self.zmq_socket.setsockopt(
                zmq.SNDHWM, 1000
            )  # Drop after 1000 buffered msgs
            self.zmq_socket.connect(url)
            log.info("[Clogging] Connected PUSH socket to %s", url)
        except Exception as e:
            log.error("[Clogging] Failed to setup ZMQ: %s", e)
            self.zmq_socket = None

    def log_event(self, event_type, data, session_id=None, protocol="ssh", ip=None):
        """Emits a raw event. Returns immediately."""
        if not self.enabled:
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "ver": "2.0",
            "timestamp": datetime.now().isoformat(),
            "source": self.server_name,
            "session_id": session_id,
            "protocol": protocol,
            "type": event_type,
            "data": sanitize_obj(data),
            "remote_ip": ip,
        }

        # 1. Local Filesystem Logging (Legacy/Safety Net)
        if self.log_mode in ("local", "both"):
            try:
                # Use standard logger for file consistency
                self._event_logger._logger.info(
                    json.dumps(event, separators=(",", ":"))
                )
            except Exception as e:
                log.error("[Clogging] Local file log failed: %s", e)

        # 2. Batch for Dispatch
        with self._lock:
            self._buffer.append(event)
            buffer_len = len(self._buffer)

        if buffer_len >= self.settings["batch_size"]:
            self.flush()

    def flush(self, force=False):
        """Triggers a manual flush of the buffer."""
        with self._lock:
            if not self._buffer and not force:
                self._last_flush = time.time()  # Reset timer anyway
                return
            if not self._buffer:
                self._last_flush = time.time()
                return
            batch = list(self._buffer)
            self._buffer = []
            self._last_flush = time.time()

        self._dispatch(batch)

    def _dispatch(self, batch):
        """Sends the batch to its destination."""
        if not batch:
            return

        # Local Dispatch
        if self.log_mode in ("local", "both"):
            try:
                from ssh_honeypot.core.slogging import slogger

                slogger.handle_batch(batch)
            except Exception as e:
                log.error("[Clogging] Local dispatch failed: %s", e)

        # ZMQ Dispatch
        if (self.log_mode in ("zmq", "both")) and self.zmq_socket:
            try:
                # Send as JSON list
                self.zmq_socket.send_json(batch, flags=zmq.NOBLOCK)
            except zmq.Again:
                log.warning("[Clogging] ZMQ HWM reached, dropping batch.")
            except Exception as e:
                log.error("[Clogging] ZMQ send failed: %s", e)

        # Legacy HTTP Remote
        if self.log_mode == "remote" and self.settings["remote_url"]:
            self._send_remote(batch)

    def _send_remote(self, batch):
        """Ships compressed JSON to the central server (HTTP)."""
        # TODO: Implement HTTP POST with gzip
        log.debug(
            "[Clogging] Simulated remote send of %d events to %s",
            len(batch),
            self.settings["remote_url"],
        )

    def _flusher_loop(self):
        """Background thread to flush based on timeout."""
        while not self._shutdown:
            # Sleep in small increments or wait for stop event
            self._stop_event.wait(1.0)
            if self._shutdown:
                break

            # Only flush if timeout reached
            with self._lock:
                elapsed = time.time() - self._last_flush
                timeout = self.settings.get("batch_timeout", 10)

            if elapsed >= timeout:
                self.flush()

    def stop(self):
        self._shutdown = True
        self._stop_event.set()
        self.flush(force=True)
        if hasattr(self, "_flusher") and self._flusher.is_alive():
            self._flusher.join(timeout=2)

        if self.zmq_socket:
            self.zmq_socket.close()
        if self.zmq_context:
            self.zmq_context.term()


# Global Instance
clogger = ClientLogger()
