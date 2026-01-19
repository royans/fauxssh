import os
import json
import time
import uuid
import logging
import hashlib
from typing import Dict, Any, Optional
from .config import get_data_dir

# Use a separate logger name to avoid conflicts
LOGGER_NAME = "unified_event_logger"
LOG_FILENAME = "events.json.log"


class EventLogger:
    _instance = None
    _logger = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EventLogger, cls).__new__(cls)
            cls._instance._init_logger()
        return cls._instance

    def _init_logger(self):
        from .config import config

        # Respect the configured filename, defaulting to the new standard if not set
        # But we need to be careful: LoggingConfig currently defaults to "honeypot.json.log" (legacy)
        # We should prefer "events.json.log" for the Unified Logger unless overridden.
        # Respect the configured filename, defaulting to the new standard if not set
        # We should prefer "events.json.log" for the Unified Logger unless overridden.
        configured_path = config.get("logging", "json_log_file")

        # Determine strict path
        if not configured_path:
            configured_path = os.path.join(get_data_dir(), LOG_FILENAME)
        elif not os.path.isabs(configured_path):
            configured_path = os.path.join(get_data_dir(), configured_path)

        logger = logging.getLogger(LOGGER_NAME)
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.FileHandler(configured_path)
            formatter = logging.Formatter("%(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            # Do not propagate to root logger to avoid console spam
            logger.propagate = False

        self._logger = logger

    def log_event(
        self,
        session_id: str,
        source_ip: str,
        event_type: str,
        protocol: str = "ssh",
        data: Dict[str, Any] = None,
        source_meta: Dict[str, Any] = None,
        analysis: Dict[str, Any] = None,
    ):
        """
        Logs a unified JSON event.

        Args:
            session_id: The session identifier.
            source_ip: The client IP address.
            event_type: 'interaction', 'auth', 'heartbeat', etc.
            protocol: 'ssh', 'http', etc.
            data: Polymorphic data block (auth details or interaction I/O).
            source_meta: Optional dictionary for extended source info (geo, user_agent, fingerprint).
            analysis: Optional dictionary for risk analysis (score, summary).
        """

        event_id = str(uuid.uuid4())
        # Use ISO 8601 format with 'Z' for UTC or offset
        # time.strftime("%Y-%m-%dT%H:%M:%S%z") is decent.
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())

        # Construct Source Object
        source = {
            "ip": source_ip,
        }
        if source_meta:
            source.update(source_meta)

        # Build Event Envelope
        event = {
            "event_id": event_id,
            "ver": "1.0",
            "timestamp": timestamp,
            "sensor_id": os.getenv(
                "FAUXSSH_SENSOR_ID", "sensor_01"
            ),  # Configurable sensor ID
            "session_id": session_id,
            "protocol": protocol,
            "type": event_type,
            "source": source,
            "data": data or {},
        }

        if analysis:
            event["analysis"] = analysis

        try:
            # Compact JSON
            json_line = json.dumps(event, separators=(",", ":"))
            self._logger.info(json_line)
        except Exception as e:
            # Fallback for serialization errors, don't crash
            # We strictly don't want to log this to the main logger to avoid recursion loops if we hook there
            print(f"[EventLogger] Error serializing event: {e}")

    # Helper methods for specific event types
    def log_auth(
        self,
        session_id,
        ip,
        username,
        password,
        success,
        method,
        protocol="ssh",
        client_version=None,
        fingerprint=None,
    ):
        data = {
            "username": username,
            "password": password,
            "success": success,
            "method": method,
        }
        source_meta = {}
        if client_version:
            source_meta["client_version"] = client_version
        if fingerprint:
            source_meta["fingerprint"] = fingerprint

        self.log_event(session_id, ip, "auth", protocol, data, source_meta)

    def log_interaction(
        self,
        session_id,
        ip,
        input_cmd,
        output_content,
        protocol="ssh",
        analysis=None,
        user_agent=None,
    ):
        # Calculate content metrics
        output_size = len(output_content) if output_content else 0
        output_md5 = (
            hashlib.md5(output_content.encode("utf-8", errors="ignore")).hexdigest()
            if output_content
            else None
        )
        # Head: First 200 chars
        output_head = output_content[:200] if output_content else ""

        data = {
            "input": input_cmd,
            "output_head": output_head,
            "output_size": output_size,
            "output_md5": output_md5,
        }

        source_meta = {}
        if user_agent:
            source_meta["user_agent"] = user_agent

        self.log_event(
            session_id, ip, "interaction", protocol, data, source_meta, analysis
        )
