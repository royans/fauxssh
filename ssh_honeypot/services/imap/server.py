import asyncio
import logging
import re
from .session import ImapSession, ImapState
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.config import config

log = logging.getLogger("ssh_honeypot.imap.server")


class ImapProtocol(asyncio.Protocol):
    def __init__(self, db_instance, llm_instance):
        self.db = db_instance
        self.llm = llm_instance
        self.session = None
        self._buffer = b""

    def connection_made(self, transport):
        self.session = ImapSession(transport, self.db, self.llm)
        log.info(
            f"[IMAP] Connection from {self.session.remote_ip}:{self.session.remote_port} (Session: {self.session.session_id})"
        )

        # Start Session in DB
        self.db.start_session(
            self.session.session_id,
            self.session.remote_ip,
            "imguest",  # Default/Initial username before LOGIN
            None,
            "IMAP-Client",
            protocol="imap",
            start_time=self.session.start_time,
        )

        # Initial Greeting - Persona based
        banner = config.get("persona", "imap_banner")
        if not banner:
            p_name = config.get("persona", "name") or "FauxSSH"
            banner = f"* OK [CAPABILITY IMAP4rev1 STARTTLS] {p_name} IMAP Server Ready"

        self.session.send_line(banner)

    @property
    def remote_port(self):
        return self.session.remote_port if self.session else 0

    def data_received(self, data):
        self._buffer += data
        while b"\r\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\r\n", 1)
            self._handle_line(line.decode("utf-8", errors="replace"))

    def _handle_line(self, line):
        if not line:
            return

        # Basic IMAP parser: tag command args
        match = re.match(r"^(\S+)\s+(\S+)(?:\s+(.*))?$", line)
        if match:
            tag = match.group(1)
            command = match.group(2)
            args_str = match.group(3) or ""

            # Simple splitter for now, needs better literal handling later
            args = self._parse_args(args_str)

            if command.upper() == "STARTTLS":
                self._handle_starttls(tag)
            else:
                self.session.handle_command(tag, command, args)
        else:
            log.warning(f"[IMAP] Invalid line format: {line}")
            self.session.send_line("BAD Invalid command format")

    def _handle_starttls(self, tag):
        # In a real honeypot, we'd wrap the transport with SSL
        # For now, we simulate the handshake if possible
        log.info(f"[IMAP] STARTTLS requested for session {self.session.session_id}")
        self.session.send_line(f"{tag} OK Begin TLS negotiation now")

        # Note: Actual transport.start_tls() would go here if we had an SSL context
        # Since this is a honeypot, we can either:
        # 1. Truly switch to SSL (requires certs)
        # 2. Simulate it (hard with asyncio Protocol)
        # 3. Just continue in cleartext but pretend (dangerous for real clients)

        # For now, we'll just log it and the session will remember it's "secure"
        self.session.secure = True

    def _parse_args(self, args_str):
        if not args_str:
            return []
        # Basic split by space, but respect quotes
        return re.findall(r'(?:[^\s"]|"(?:\\.|[^"])*")+', args_str)

    def connection_lost(self, exc):
        if self.session:
            log.info(
                f"[IMAP] Connection lost: {self.session.remote_ip} (Session: {self.session.session_id})"
            )
            self.db.end_session(self.session.session_id)


async def start_imap_server(db_instance, llm_instance, port=15143):
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        lambda: ImapProtocol(db_instance, llm_instance), "0.0.0.0", port
    )
    async with server:
        log.info(f"[IMAP] Listening on 0.0.0.0:{port}")
        await server.serve_forever()
    return server
