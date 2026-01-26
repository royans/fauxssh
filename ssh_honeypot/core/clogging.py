import os
import json
import time
import uuid
import gzip
import threading
import logging
from datetime import datetime
from ssh_honeypot.core.config import config
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.utils import sanitize_obj
from ssh_honeypot.core.event_logger import EventLogger


class ClientLogger:
    """
    'clogging' - Client-side logging component.
    Buffers events locally and ships them to slogging (local or remote).
    Separates emission from analysis.
    """

    def __init__(self):
        self.enabled = config.get("logging", "centralized", "enabled") or True
        self.log_mode = config.get("logging", "centralized", "mode") or "local"
        self.server_name = (
            config.get("logging", "centralized", "server_name") or "hp-default"
        )
        self.batch_size = config.get("logging", "centralized", "batch_size") or 50
        self.batch_timeout = config.get("logging", "centralized", "batch_timeout") or 10
        self.remote_url = config.get("logging", "centralized", "remote_url")
        self.api_key = config.get("logging", "centralized", "api_key")
        self.use_compression = (
            config.get("logging", "centralized", "compression") or True
        )

        self._buffer = []
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._shutdown = False
        self._event_logger = EventLogger()

        # Start flusher thread if decentralized or both
        self._flusher = threading.Thread(target=self._flusher_loop, daemon=True)
        self._flusher.start()

        log.info(
            f"[Clogging] Initialized in '{self.log_mode}' mode for server '{self.server_name}'"
        )

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

        # 1. Local Filesystem Logging (Immediate)
        if self.log_mode in ("local", "both"):
            try:
                # Use standard logger for file consistency
                self._event_logger._logger.info(
                    json.dumps(event, separators=(",", ":"))
                )
            except Exception as e:
                log.error(f"[Clogging] Local file log failed: {e}")

        # 2. Batch for Dispatch
        with self._lock:
            self._buffer.append(event)
            buffer_len = len(self._buffer)

        if buffer_len >= self.batch_size:
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
        if self.log_mode in ("local", "both"):
            # Call slogging directly
            try:
                from ssh_honeypot.core.slogging import slogger

                slogger.handle_batch(batch)
            except Exception as e:
                log.error(f"[Clogging] Local dispatch failed: {e}")

        if self.log_mode in ("remote", "both"):
            if self.remote_url:
                self._send_remote(batch)
            else:
                log.warning(
                    "[Clogging] Remote logging enabled but no remote_url configured"
                )

    def _send_remote(self, batch):
        """Ships compressed JSON to the central server."""
        # TODO: Implement HTTP POST with gzip
        # For Phase 1 (Local), we just log that we would have sent it
        log.debug(
            f"[Clogging] Simulated remote send of {len(batch)} events to {self.remote_url}"
        )

    def _flusher_loop(self):
        """Background thread to flush based on timeout."""
        while not self._shutdown:
            time.sleep(1)
            # Only flush if timeout reached
            if time.time() - self._last_flush >= self.batch_timeout:
                self.flush()

    def stop(self):
        self._shutdown = True
        self.flush()
        if self._flusher and self._flusher.is_alive():
            self._flusher.join(timeout=2)


# Global Instance
clogger = ClientLogger()
