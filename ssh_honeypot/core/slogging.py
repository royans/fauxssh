import json
import logging
from typing import List, Dict, Any
from ssh_honeypot.core.database import get_db_backend
from ssh_honeypot.core.logging_setup import log


class SloggingProcessor:
    """
    'slogging' - Server-side logging component.
    Receives raw events from clogging (local or remote),
    saves them to DB, and triggers analysis.
    """

    def __init__(self):
        self._db = None

    @property
    def db(self):
        if self._db is None:
            self._db = get_db_backend()
        return self._db

    def handle_batch(self, batch: List[Dict[str, Any]]):
        """Processes a batch of raw events."""
        from ssh_honeypot.core.config import config

        # If batching is effectively disabled via env, we still get called with valid lists
        # from the centralized logging poller. This just processes them.
        # But if the user wants to DISABLE batching, it usually means "flush immediately".
        # The polling mechanism controls the batch accumulation.
        # However, checking the flag here can serve as verification or enforcement.

        disable_batching = config.get("logging", "disable_batching")
        if disable_batching:
            log.debug("[Slogging] Batch processing disabled (Simulated instant flush)")

        for event in batch:
            try:
                self.handle_event(event)
            except Exception as e:
                log.error(
                    f"[Slogging] Failed to handle event {event.get('event_id')}: {e}"
                )

    def handle_event(self, event: Dict[str, Any]):
        """
        Main entry point for slogging.
        Processes a single raw event.
        """
        event_type = event.get("type")
        data = event.get("data", {})
        session_id = event.get("session_id")
        protocol = event.get("protocol", "ssh")
        ip = event.get("remote_ip")
        source = event.get("source")  # ServerName
        timestamp = event.get("timestamp")

        # 1. Save to Database (Low-level)
        self._save_to_db(event_type, data, session_id, protocol, ip, source, timestamp)

        # 2. Trigger Analysis/Enrichment (The 'Heavy' part)
        self._trigger_analysis(event_type, data, session_id, protocol, ip)

    def _save_to_db(
        self, event_type, data, session_id, protocol, ip, source, timestamp=None
    ):
        """Standard DB insertion logic."""
        try:
            if event_type == "auth":
                self.db.log_auth_event(
                    client_ip=ip,
                    username=data.get("username"),
                    auth_method=data.get("method"),
                    auth_data=data.get("password"),
                    success=data.get("success"),
                    client_version=data.get("client_version"),
                    fingerprint=data.get("fingerprint"),
                    protocol=protocol,
                    created_at=timestamp,
                )
            elif event_type == "interaction":
                # Standardize source: use execution source (handler/llm) if available,
                # otherwise fallback to server name (source).
                exec_source = data.get("source") or source
                self.db.log_interaction(
                    session_id=session_id,
                    cwd=data.get("cwd"),
                    command=data.get("input"),
                    response=data.get("response"),
                    source=exec_source,
                    duration_ms=data.get("duration_ms", 0),
                    request_md5=data.get("request_md5"),
                    created_at=timestamp,
                )
            elif event_type == "session_start":
                self.db.start_session(
                    session_id=session_id,
                    ip=ip,
                    username=data.get("username"),
                    password=data.get("password"),
                    client_version=data.get("client_version"),
                    fingerprint=data.get("fingerprint"),
                    protocol=protocol,
                    start_time=timestamp,
                )
            elif event_type == "session_end":
                self.db.end_session(session_id)
            elif event_type == "url":
                self.db.log_url_request(
                    session_id=session_id,
                    url=data.get("url"),
                    method=data.get("method", "GET"),
                    user_agent=data.get("user_agent"),
                    command_text=data.get("command_text"),
                )
        except Exception as e:
            log.error(f"[Slogging] DB Error in {event_type}: {e}")

    def _trigger_analysis(self, event_type, data, session_id, protocol, ip):
        """
        Triggers heavy processing tasks.
        In Phase 1, these still run locally if they were doing so before.
        """
        # IP Enrichment Trigger
        if event_type in ("session_start", "auth"):
            self.db.log_ip_visit(ip)  # This eventually triggers background enrichment

        # URL Extraction from commands
        if event_type == "interaction":
            command = data.get("input")
            if command:
                try:
                    from ssh_honeypot.core.payload_manager import PayloadManager

                    pm = PayloadManager(self.db)
                    urls = pm.extract_urls(command)
                    for url in urls:
                        pm.queue_payload(url, session_id, ip)
                except Exception as e:
                    log.error(f"[Slogging] Payload Queue Error: {e}")


# Global Instance
slogger = SloggingProcessor()
