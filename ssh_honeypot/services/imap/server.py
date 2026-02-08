import asyncio
import logging
import re
import os
from ssh_honeypot.core.utils import create_dual_stack_socket
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


async def start_imap_server(
    db_instance,
    llm_instance,
    port=15143,
    bind_ip="0.0.0.0",
    ssl_port=15993,
    ssl_cert=None,
    ssl_key=None,
):
    loop = asyncio.get_running_loop()
    servers = []

    # 1. Plain Text Server (Dual Stack capable)

    try:
        # We manually create the socket to ensure dual-stack if requested (::)
        sock = create_dual_stack_socket(bind_ip, port)
        server_plain = await loop.create_server(
            lambda: ImapProtocol(db_instance, llm_instance), sock=sock
        )
        servers.append(server_plain)
        log.info(f"[IMAP] Listening on {bind_ip}:{port} (Plain)")
    except Exception as e:
        log.error(f"[IMAP] Failed to start plain text server: {e}")

    # 2. SSL Server (Optional)
    if (
        ssl_port
        and ssl_cert
        and ssl_key
        and os.path.exists(ssl_cert)
        and os.path.exists(ssl_key)
    ):
        try:
            import ssl

            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)

            # For SSL we can also use dual stack socket if we want, but create_server with ssl+sock sometimes tricky
            # Let's try matching the plain approach
            ssl_sock = create_dual_stack_socket(bind_ip, ssl_port)

            server_ssl = await loop.create_server(
                lambda: ImapProtocol(db_instance, llm_instance),
                sock=ssl_sock,
                ssl=ssl_context,
            )
            servers.append(server_ssl)
            log.info(f"[IMAP] Listening on {bind_ip}:{ssl_port} (SSL)")
        except Exception as e:
            log.error(f"[IMAP] Failed to start SSL server: {e}")

    if not servers:
        log.error("[IMAP] No servers could be started.")
        return

    # Run all servers
    async with asyncio.TaskGroup() as tg:
        for s in servers:
            tg.create_task(s.serve_forever())
