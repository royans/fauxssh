import socket
import threading
import paramiko
import os
import time
import json
import random
import logging
import struct
import hashlib

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.llm import LLMInterface
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.session_analyzer import analyze_session
from ssh_honeypot.core.config import config, get_data_dir
from ssh_honeypot.services.ssh.sftp import HoneySFTPServer
from ssh_honeypot.core.alert_manager import AlertManager
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.persona_validator import validate_active_persona
from ssh_honeypot.core.clogging import clogger
from ssh_honeypot.core.utils import get_ignored_ips


# --- Logging Filter for Paramiko Noise ---
class ParamikoFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        if "Error reading SSH protocol banner" in msg:
            return False
        if record.exc_info:
            exc_type, exc_value, _ = record.exc_info
            if "Error reading SSH protocol banner" in str(exc_value):
                return False
        return True


logging.getLogger("paramiko.transport").addFilter(ParamikoFilter())
# -----------------------------------------

# Global Limits
MAX_CONCURRENT_SESSIONS = 20
MAX_SESSIONS_PER_IP = 3
MAX_FILES_PER_SESSION = 50

# Shared Constants
HOST_KEY_FILE = os.path.join(get_data_dir(), "host.key")

active_sessions = 0
active_sessions_lock = threading.Lock()
ip_connection_counts = (
    {}
)  # collections.defaultdict(int) replacement for simplicity if needed, but import collections better

import collections

ip_connection_counts = collections.defaultdict(int)


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.username = None
        self.password = None
        self.subsystem = None
        self.transport_ref = None

        # We need DB access here. Assuming Global DB or passing it in.
        # For thread safety and architecture, better to use the db instance passed to start_server
        # But Paramiko instantiates this. We can use a class var or global db.
        # Existing code uses global 'db'.

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def _parse_ssh_string(self, data, offset=0):
        try:
            if len(data) < offset + 4:
                return None, offset
            length = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4
            if len(data) < offset + length:
                return None, offset
            s = data[offset : offset + length]
            return s.decode("utf-8", errors="ignore"), offset + length
        except:
            return None, offset

    def _compute_hassh(self, payload):
        try:
            # Skip MSG(1) + Cookie(16) = 17
            offset = 17

            # 1. KEX
            kex, offset = self._parse_ssh_string(payload, offset)
            # 2. HostKey (Skip)
            _, offset = self._parse_ssh_string(payload, offset)
            # 3. Enc C2S
            enc, offset = self._parse_ssh_string(payload, offset)
            # 4. Enc S2C (Skip)
            _, offset = self._parse_ssh_string(payload, offset)
            # 5. Mac C2S
            mac, offset = self._parse_ssh_string(payload, offset)
            # 6. Mac S2C (Skip)
            _, offset = self._parse_ssh_string(payload, offset)
            # 7. Comp C2S
            comp, offset = self._parse_ssh_string(payload, offset)

            if kex and enc and mac and comp:
                raw_str = f"{kex};{enc};{mac};{comp}"
                md5 = hashlib.md5(raw_str.encode()).hexdigest()
                return md5, raw_str
        except:
            pass
        return None, None

    def _extract_fingerprint(self):
        if not self.transport_ref:
            return None

        fp = {}
        try:
            fp["cipher"] = getattr(self.transport_ref, "remote_cipher", "unknown")
            fp["mac"] = getattr(self.transport_ref, "remote_mac", "unknown")
            fp["compression"] = getattr(
                self.transport_ref, "remote_compression", "unknown"
            )
            fp["kex"] = getattr(self.transport_ref, "kex_alg", "unknown")

            if hasattr(self.transport_ref, "_latest_kex_init"):
                hassh, raw = self._compute_hassh(self.transport_ref._latest_kex_init)
                if hassh:
                    fp["hassh"] = hassh
                    fp["hassh_algorithms"] = raw

            return fp
        except:
            return None

    def check_auth_password(self, username, password):
        from ssh_honeypot.core.utils import get_ignored_ips

        self.username = username
        self.password = password
        log.debug(f"[DEBUG] check_auth_password: user={username} pass={password}")

        # Bypass for Trusted IPs (Analytics Ignored IPs) - Move this to top to avoid anti-harvesting blocks
        ignored_ips = get_ignored_ips()
        bypass_enabled = config.get("security", "bypass_auth_for_ignored_ips")
        is_trusted = bypass_enabled and (
            self.client_ip in ignored_ips
            or self.client_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
        )

        log.info(
            f"[SSH] Auth Attempt: User='{username}' IP='{self.client_ip}' Trusted={is_trusted}"
        )

        if not is_trusted:
            # Use globally bound db (will be set in start_ssh_server scope or truly global)
            is_safe, reason = db.validate_anti_harvesting(
                self.client_ip, username, password
            )
            if not is_safe:
                log.warning(f"[SSH] [!] {reason}")
                return paramiko.AUTH_FAILED

        # Check Root Policy
        allow_root = config.get("persona", "access_control", "allow_root")
        if allow_root is None:
            allow_root = False

        if is_trusted:
            allow_root = True
            log.info(f"[SSH] Allowing login from Trusted IP: {self.client_ip}")

        # Root Desperation Check
        if username == "root":
            desperation = db.check_root_desperation(self.client_ip)
            if desperation == "BLOCK":
                log.info(
                    f"[SSH] Root Blocked (Desperation Rule): {self.client_ip} has prior non-root access."
                )
                allow_root = False
            elif desperation == "ALLOW":
                log.info(
                    f"[SSH] Root Allowed (Desperation Rule): {self.client_ip} 3rd attempt granted."
                )
                allow_root = True

        if is_trusted:
            success = True
            log.info(f"[SSH] Bypassing auth check for Trusted IP: {self.client_ip}")
        elif username == "root" and not allow_root:
            success = False
        else:
            success = True

        client_version = "unknown"
        if self.transport_ref:
            client_version = self.transport_ref.remote_version

        fp = self._extract_fingerprint()

        auth_data = {
            "username": username,
            "password": password,
            "success": success,
            "method": "password",
            "client_version": client_version,
            "fingerprint": fp,
        }

        clogger.log_event("auth", auth_data, session_id="pre-auth", ip=self.client_ip)
        db.log_auth_event(
            self.client_ip,
            username,
            "password",
            password,
            success,
            client_version,
            fingerprint=fp,
        )

        if not success:
            return paramiko.AUTH_FAILED

        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        client_version = "unknown"
        if self.transport_ref:
            client_version = self.transport_ref.remote_version

        key_type = key.get_name()
        key_b64 = key.get_base64()
        key_str = f"{key_type} {key_b64}"

        home_dir = "/root" if username == "root" else f"/home/{username}"
        auth_keys_path = f"{home_dir}/.ssh/authorized_keys"

        node = db.get_user_node(self.client_ip, username, auth_keys_path)

        authorized = False
        if node and node.get("type") == "file" and node.get("content"):
            content = node["content"]
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Standard SSH authorized_keys format: [options] keytype base64-key [comment]
                parts = line.split()
                # Skip options if present (detected by parts[0] not starting as a key type)
                # Key types usually start with "ssh-", "ecdsa-", etc.
                key_type_index = 0
                while key_type_index < len(parts) and not (
                    parts[key_type_index].startswith("ssh-")
                    or parts[key_type_index].startswith("ecdsa-")
                ):
                    key_type_index += 1

                if key_type_index + 1 < len(parts):
                    l_type = parts[key_type_index]
                    l_key = parts[key_type_index + 1]
                    if l_type == key_type and l_key == key_b64:
                        authorized = True
                        break

        fp = self._extract_fingerprint()
        auth_data = {
            "username": username,
            "password": key_str,  # Use key_str which is the b64 key for publickey
            "success": authorized,
            "method": "publickey",
            "client_version": client_version,
            "fingerprint": fp,
        }
        clogger.log_event("auth", auth_data, session_id="pre-auth", ip=self.client_ip)
        db.log_auth_event(
            self.client_ip,
            username,
            "publickey",
            auth_data,
            authorized,
            client_version,
            fingerprint=fp,
        )

        ignored_ips = get_ignored_ips()
        bypass_enabled = config.get("security", "bypass_auth_for_ignored_ips")
        is_trusted = (
            self.client_ip in ignored_ips or self.client_ip == "127.0.0.1"
        ) and bypass_enabled

        if not is_trusted:
            is_safe, reason = db.validate_anti_harvesting(
                self.client_ip, username, key_str
            )
            if not is_safe:
                log.warning(f"[SSH] [!] {reason}")
                return paramiko.AUTH_FAILED

        if authorized or is_trusted:
            log.info(
                f"[SSH] Public Key Login SUCCESS for '{username}' from {self.client_ip} (Authorized or Trusted)"
            )
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        from ssh_honeypot.core.utils import get_ignored_ips

        ignored_ips = get_ignored_ips()
        bypass_enabled = config.get("security", "bypass_auth_for_ignored_ips")
        is_trusted = bypass_enabled and (
            self.client_ip in ignored_ips
            or self.client_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
        )

        if is_trusted:
            log.info(
                f"[SSH] Allowing passwordless (none) auth for Trusted IP: {self.client_ip}"
            )
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        from ssh_honeypot.core.utils import get_ignored_ips

        ignored_ips = get_ignored_ips()
        bypass_enabled = config.get("security", "bypass_auth_for_ignored_ips")
        is_trusted = bypass_enabled and (
            self.client_ip in ignored_ips
            or self.client_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
        )

        if is_trusted:
            return "none,password,publickey"
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.command = command
        # log.debug(f"[DEBUG] check_channel_exec_request: command={command}")
        self.event.set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        self.subsystem = name
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


def latency_jitter():
    """Injects random network latency if enabled."""
    try:
        conf = config.get("realism", "latency")
        if not conf or not conf.get("enabled", False):
            return

        min_ms = conf.get("min_ms", 20)
        max_ms = conf.get("max_ms", 300)

        delay = random.randint(min_ms, max_ms) / 1000.0
        time.sleep(delay)
    except:
        pass


# Handlers needed for loop
def handle_tab_completion(chan, command_buffer, vfs, cwd, prompt):
    parts = command_buffer.split()
    if not parts and not command_buffer:
        prefix = ""
    elif command_buffer.endswith(" "):
        prefix = ""
    else:
        prefix = parts[-1]

    candidates = []
    current_files = vfs.get(cwd, [])

    for f in current_files:
        if f.startswith(prefix):
            candidates.append(f)

    if len(candidates) == 1:
        match = candidates[0]
        remainder = match[len(prefix) :]
        command_buffer += remainder
        chan.send(remainder)
        return command_buffer

    elif len(candidates) > 1:
        chan.send(b"\r\n")
        output_list = "  ".join(candidates)
        chan.send(output_list.encode("utf-8"))
        chan.send(b"\r\n")
        chan.send(prompt)
        chan.send(command_buffer.encode("utf-8"))
        return command_buffer

    return command_buffer


def stream_output(chan, text):
    """
    Simulates realistic terminal output by streaming lines with micro-delays.
    """
    if not text:
        return

    # Heuristic: If short, dump immediately
    if len(text) < 500 and text.count("\r\n") < 10:
        chan.send(text)
        return

    # Long output: Stream line by line (or chunk by chunk)
    lines = text.split("\r\n")
    # split removes the delimiter, so we must add it back except for maybe the last one if original didn't have it?
    # Actually, fmt_resp usually has newlines converted to \r\n

    # Safest: Use a chunking generator or just split and rejoin with limits
    # Let's simple split by lines for visual effect

    for i, line in enumerate(lines):
        # Determine chunk to send
        chunk = line
        if i < len(lines) - 1:
            chunk += "\r\n"

        # Send
        try:
            chan.send(chunk)
        except:
            break

        # Delay (Micro-jitter)
        # 0.005 to 0.05 seconds (Simulates fast scrolling but visible)
        if len(chunk) > 0:
            time.sleep(random.uniform(0.005, 0.03))


from ssh_honeypot.core.dos_protection import dos_protector


# Connection Handler
def handle_connection(client, addr, db_inst, llm_inst):
    global active_sessions
    ip = addr[0]

    # 0. DoS Protection (Silent Drop)
    if not dos_protector.is_allowed(ip, "SSH"):
        # Log is handled inside is_allowed for ban event.
        # If banned, we strictly silent drop (close without sending anything)
        client.close()
        return

    with active_sessions_lock:
        if active_sessions >= MAX_CONCURRENT_SESSIONS:
            log.warning(
                f"[SSH] Dropping connection from {ip}: Max sessions reached ({MAX_CONCURRENT_SESSIONS})"
            )
            client.close()
            return

        if ip_connection_counts[ip] >= MAX_SESSIONS_PER_IP:
            log.warning(
                f"[SSH] Dropping connection from {ip}: Max sessions per IP reached ({MAX_SESSIONS_PER_IP})"
            )
            client.close()
            return

        active_sessions += 1
        ip_connection_counts[ip] += 1

    try:
        try:
            _handle_connection_logic(client, addr, db_inst, llm_inst)
        except Exception as e:
            log.error(f"[SSH] Handle Connection Error: {e}")
    finally:
        with active_sessions_lock:
            active_sessions -= 1
            ip_connection_counts[ip] -= 1
            if ip_connection_counts[ip] <= 0:
                del ip_connection_counts[ip]


def _handle_connection_logic(client, addr, db, llm):
    ip = addr[0]
    # Inject db into global scope for HoneypotServer to pick up?
    # Or rely on HoneypotServer finding the global 'db' variable.
    # To be safe, we rely on the file-level global `db` which we will set in `start_ssh_server`.

    transport = paramiko.Transport(client)

    # 1. Resolve Banner
    # Priority: Persona > Config Default > Hardcoded
    banner = config.get("persona", "network", "ssh_banner")
    if not banner:
        banner = config.get("server", "banner_default")
    if not banner:
        banner = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"

    transport.local_version = banner

    try:
        host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)
    except FileNotFoundError:
        log.info("[SSH] Generating new host key...")
        host_key = paramiko.RSAKey.generate(2048)
        host_key.write_private_key_file(HOST_KEY_FILE)
    except Exception as e:
        log.error(f"[!] Error loading host key: {e}")
        return

    logger = None
    try:
        transport.add_server_key(host_key)
        server = HoneypotServer(ip)
        transport.add_server_key(host_key)
        server = HoneypotServer(ip)
        server.transport_ref = transport
        transport.start_server(server=server)
    except paramiko.SSHException as e:
        if "Error reading SSH protocol banner" in str(e):
            # print(f"[!] Scanner disconnected without sending banner: {ip}")
            pass
        else:
            print(f"[!] SSH Error with {ip}: {e}")
        return
    except Exception as e:
        print(f"[!] Unexpected error during handshake with {ip}: {e}")
        return

    chan = transport.accept(20)
    if chan is None:
        return

    server.event.wait(10)
    if not server.event.is_set():
        transport.close()
        return

    session_id = os.urandom(8).hex()

    fingerprint = {}
    try:
        fingerprint = {
            "cipher": getattr(transport, "remote_cipher", "unknown"),
            "mac": getattr(transport, "remote_mac", "unknown"),
            "compression": getattr(transport, "remote_compression", "unknown"),
            "kex": getattr(transport, "kex_alg", "unknown"),
        }
    except:
        pass

    try:
        session_data = {
            "username": server.username,
            "password": server.password,
            "client_version": transport.remote_version,
            "fingerprint": fingerprint,
        }
        clogger.log_event("session_start", session_data, session_id=session_id, ip=ip)
        log.info(f"[SSH] New Session {session_id} from {ip} as {server.username}")
    except Exception as e:
        log.error(f"[SSH] Critical Error starting session: {e}")

    user = server.username if server.username else "alabaster"
    if user == "root":
        cwd = "/root"
    else:
        cwd = f"/home/{user}"

    hostname = config.get("server", "hostname") or "npc-main-server-01"

    # Legacy VFS dict (list of filenames only, actual content in DB)
    vfs = {
        "/tmp": [],
        "/var/www/html": ["index.php", "config.php", "assets", "uploads"],
    }

    server.vfs = vfs
    server.cwd = cwd
    server.session_id = session_id
    server.db = db

    if server.subsystem == "sftp":
        log.info(f"[SSH] Starting SFTP Handler for {session_id}")
        try:
            sftp = paramiko.SFTPServer(chan, session_id, server, HoneySFTPServer)
            sftp.start()
            while transport.is_active():
                time.sleep(1)
        except Exception as e:
            log.error(f"[!] SFTP Error: {e}")
        return

    history = []
    history_cursor = 0
    llm_call_count = 0

    handler = CommandHandler(llm, db)
    alert_manager = AlertManager()

    # Single Command Execution
    if hasattr(server, "command") and server.command:
        cmd_bytes = server.command
        cmd = cmd_bytes.decode("utf-8", errors="ignore")

        context = {
            "cwd": cwd,
            "user": user,
            "vfs": vfs,
            "history": history,
            "client_ip": ip,
            "honeypot_ip": "192.168.1.55",
            "session_id": session_id,
            "llm_call_count": llm_call_count,
            "env": {},
            "file_list": [
                os.path.basename(x["path"]) for x in db.list_user_dir(ip, user, cwd)
            ],
            "known_paths": list(vfs.keys()),
        }

        if cmd.strip().startswith("scp "):
            log.info(f"[SSH] Starting SCP Handler for {session_id} (cmd: {cmd})")

            # Log the SCP command itself as an interaction
            try:
                cmd_hash = hashlib.md5(cmd.encode("utf-8")).hexdigest()
                interaction_data = {
                    "cwd": cwd,
                    "input": cmd,
                    "response": "[SCP Transfer Initiated]",
                    "request_md5": str(cmd_hash),
                    "duration_ms": 0,
                    "source": "handler",
                    "cached": False,
                }
                clogger.log_event(
                    "interaction", interaction_data, session_id=session_id, ip=ip
                )
            except:
                pass

            try:
                handler.handle_scp_interactive(cmd, chan, context)
                chan.send_exit_status(0)
                chan.close()
                return
            except Exception as e:
                log.error(f"[!] SCP Handler Error: {e}")
                return

        start_time = time.time()
        resp_text, updates, metadata = handler.process_command(cmd, context)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        try:
            cmd_hash = hashlib.md5(cmd.encode("utf-8")).hexdigest()
        except:
            cmd_hash = "unknown"

        log.debug(f"[SSH] Exec '{cmd}' -> Response Len: {len(resp_text)}")

        interaction_data = {
            "cwd": cwd,
            "input": cmd,
            "response": resp_text,
            "request_md5": str(cmd_hash),
            "duration_ms": duration_ms,
            "source": str(metadata.get("source", "unknown")),
            "cached": metadata.get("cached", False),
        }
        clogger.log_event("interaction", interaction_data, session_id=session_id, ip=ip)

        if resp_text:
            try:
                chan.send(resp_text)
                if not resp_text.endswith("\n"):
                    chan.send("\n")
            except (OSError, socket.error):
                pass  # Socket closed by client

        if updates and updates.get("terminate"):
            log.debug("[DEBUG] Termination signal detected in single command")
            chan.send_exit_status(0)
            chan.close()
            return

        log.debug("[DEBUG] Sending exit status 0")
        chan.send_exit_status(0)
        chan.close()
        return

    # Shell Mode
    if user == "root":
        prompt_symbol = "#"
    else:
        prompt_symbol = "$"
    prompt = f"\r\n{user}@{hostname}:{cwd}{prompt_symbol} "
    chan.send(
        f"Linux {hostname} 3.16.0-6-amd64 #1 SMP Debian 3.16.56-1+deb8u1 (2018-04-23) x86_64\r\n"
    )
    chan.send(
        f"The programs included with the Debian GNU/Linux system are free software.\r\n"
    )

    # Randomize Last Login IP
    rand_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    chan.send(f"Last login: {time.ctime()} from {rand_ip}\r\n")
    chan.send(prompt)

    command_buffer = ""
    env = {}

    try:
        while True:
            char = chan.recv(1)

            if not char:
                break

            if char == b"\x03":  # Ctrl+C
                chan.send(b"^C\r\n")
                command_buffer = ""
                history_cursor = len(history)
                chan.send(prompt)

            elif char == b"\r" or char == b"\n":
                if char == b"\n" and command_buffer == "":
                    continue
                chan.send(b"\r\n")
                cmd = command_buffer.strip()
                command_buffer = ""
                history_cursor = len(history)

                if cmd:
                    # Generic exit check still useful as fallback
                    if cmd == "exit" or cmd == "logout":
                        break
                    if cmd == "clear":
                        chan.send(b"\033[2J\033[H")
                        chan.send(prompt)
                        continue

                    context = {
                        "env": env,
                        "cwd": cwd,
                        "user": user,
                        "vfs": vfs,
                        "history": history,
                        "client_ip": ip,
                        "honeypot_ip": "192.168.1.55",
                        "session_id": session_id,
                        "llm_call_count": llm_call_count,
                        "file_list": [
                            os.path.basename(x["path"])
                            for x in db.list_user_dir(ip, user, cwd)
                        ],
                        "known_paths": list(vfs.keys()),
                        "protocol": "ssh",
                    }

                    # Rate Limit Judge
                    rpm = config.get_rate_limit("ssh", "llm", "rpm")
                    rph = config.get_rate_limit("ssh", "llm", "rph")
                    rpd = config.get_rate_limit("ssh", "llm", "rpd")

                    allowed, reason = db.check_llm_rate_limit(ip, rpm, rph, rpd)
                    if not allowed:
                        log.warning(f"[SSH] Rate Limit {ip}: {reason}")
                        chan.send(
                            f"\r\nSystem: Resource quota exceeded. Please wait.\r\n".encode(
                                "utf-8"
                            )
                        )
                        chan.send(prompt.encode("utf-8"))
                        continue

                    start_time = time.time()
                    resp_text, updates, metadata = handler.process_command(cmd, context)
                    duration_ms = round((time.time() - start_time) * 1000, 2)
                    try:
                        cmd_hash = hashlib.md5(cmd.encode("utf-8")).hexdigest()
                    except:
                        cmd_hash = "unknown"

                    llm_call_count += 1

                    if updates:
                        if updates.get("new_cwd"):
                            cwd = updates.get("new_cwd")
                            if cwd not in vfs:
                                vfs[cwd] = []
                        if updates.get("env"):
                            context["env"].update(updates["env"])

                        if updates.get("file_modifications"):
                            for mod in updates.get("file_modifications"):
                                action = mod.get("action")
                                path = mod.get("path")
                                target_dir = cwd
                                filename = path
                                if "/" in path:
                                    parts = path.rsplit("/", 1)
                                    if path.startswith("/"):
                                        target_dir = parts[0] if len(parts) > 1 else "/"
                                    filename = parts[1]

                                if target_dir not in vfs:
                                    vfs[target_dir] = []
                                if action == "create":
                                    if (
                                        len(vfs.get(target_dir, []))
                                        < MAX_FILES_PER_SESSION
                                        and filename not in vfs[target_dir]
                                    ):
                                        vfs[target_dir].append(filename)
                                elif action == "delete":
                                    if filename in vfs[target_dir]:
                                        vfs[target_dir].remove(filename)

                        if updates.get("terminate"):
                            log.info(
                                f"[SSH] Session {session_id} Termination requested via command: {cmd}"
                            )
                            # Send response before breaking if not already sent
                            # (resp_text is handled below)
                            # break will trigger cleanup in finally block
                            # However, we need to send the final prompt/message if appropriate
                            break

                    fmt_resp = resp_text.replace("\n", "\r\n")

                    # Inject Jitter before output (Network Latency)
                    latency_jitter()

                    # Stream Output (Typing Effect)
                    stream_output(chan, fmt_resp)

                    if fmt_resp and not fmt_resp.endswith("\r\n"):
                        chan.send(b"\r\n")

                    interaction_data = {
                        "cwd": cwd,
                        "input": cmd,
                        "response": resp_text,
                        "request_md5": str(cmd_hash),
                        "duration_ms": duration_ms,
                        "source": str(metadata.get("source", "unknown")),
                        "cached": metadata.get("cached", False),
                    }
                    clogger.log_event(
                        "interaction",
                        interaction_data,
                        session_id=session_id,
                        ip=addr[0],
                    )

                    try:
                        alert_manager.handle_interaction(session_id, ip, cmd, resp_text)
                    except Exception as e:
                        log.error(f"[Alert] Stream Error: {e}")

                    history.append((cmd, resp_text))

                if user == "root":
                    prompt_symbol = "#"
                else:
                    prompt_symbol = "$"
                prompt = f"{user}@{hostname}:{cwd}{prompt_symbol} "
                chan.send(prompt)
                history_cursor = len(history)

            elif char == b"\x08" or char == b"\x7f":
                if len(command_buffer) > 0:
                    command_buffer = command_buffer[:-1]
                    chan.send(b"\x08 \x08")

            elif char == b"\x1b":
                # Simplified Arrow handling
                try:
                    seq = chan.recv(2)
                    if seq == b"[A":  # Up
                        if history_cursor > 0 and history:
                            history_cursor -= 1
                            prev_cmd = history[history_cursor][0]
                            backspaces = b"\x08" * len(command_buffer)
                            spaces = b" " * len(command_buffer)
                            chan.send(backspaces + spaces + backspaces)
                            command_buffer = prev_cmd
                            chan.send(command_buffer)
                    elif seq == b"[B":  # Down
                        if history_cursor < len(history):
                            history_cursor += 1
                            backspaces = b"\x08" * len(command_buffer)
                            spaces = b" " * len(command_buffer)
                            chan.send(backspaces + spaces + backspaces)
                            if history_cursor == len(history):
                                command_buffer = ""
                            else:
                                command_buffer = history[history_cursor][0]
                            chan.send(command_buffer)
                except:
                    pass

            elif char == b"\t":
                command_buffer = handle_tab_completion(
                    chan, command_buffer, vfs, cwd, prompt
                )

            else:
                try:
                    c = char.decode("utf-8")
                    if c.isprintable():
                        command_buffer += c
                        chan.send(char)
                except:
                    pass

    except Exception as e:
        log.error(f"Session Error: {e}")
    finally:
        # Trigger Session Analysis (Researcher Intel)
        try:
            status = analyze_session(session_id, db, llm)
            log.info(f"Session Analysis: {status}")
        except Exception as e:
            log.error(f"Analysis Error: {e}")

        db.end_session(session_id)
        transport.close()


# Global DB reference helper for the server instance which is instantiated by paramiko internal thread
db = None
llm = None


def start_ssh_server(port, db_instance, llm_instance):
    import sys

    sys.stderr.write(f"DEBUG: start_ssh_server entry port={port}\n")
    """
    Start the SSH Honeypot Server.
    Run this in a thread or separate process.
    """
    global db, llm
    db = db_instance  # Bind global for Paramiko instantiation callbacks
    llm = llm_instance  # Expose for tests

    # Generate Host Key if needed
    if not os.path.exists(HOST_KEY_FILE):
        print("[*] Generating Host Key...")
        k = paramiko.RSAKey.generate(2048)
        k.write_private_key_file(HOST_KEY_FILE)

    BIND_IP = (
        os.getenv("FAUXSSH_BIND_IP") or config.get("server", "bind_ip") or "0.0.0.0"
    )
    from ssh_honeypot.core.utils import create_dual_stack_socket

    try:
        sock = create_dual_stack_socket(BIND_IP, port, backlog=100)
        family_str = "IPv6 (Dual Stack)" if sock.family == socket.AF_INET6 else "IPv4"
        log.info(f"[SSH] Listening on {BIND_IP}:{port} ({family_str})")
    except Exception as e:
        log.error(f"[!] Failed to bind SSH port {port} on {BIND_IP}: {e}")
        return

    while True:
        try:
            client, addr = sock.accept()
            import sys

            # try:
            #     sys.stderr.write(f"DEBUG: Server accepted connection from {addr}\n")
            # except:
            #     pass
            # sys.stderr.flush() # This line was removed as it was associated with the debug print.
            # Launch thread handling connection, passing db and llm explicitly (globals to allow mocking)
            t = threading.Thread(target=handle_connection, args=(client, addr, db, llm))
            t.daemon = True
            t.start()
        except Exception as e:
            log.error(f"[!] Accept Loop Error: {e}")
