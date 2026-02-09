import socket
import threading
import time
import os
import logging
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.config import config
from ssh_honeypot.core.clogging import clogger


# Telnet Constants
IAC = b"\xff"  # Interpret As Command
DONT = b"\xfe"
DO = b"\xfd"
WONT = b"\xfc"
WILL = b"\xfb"
SB = b"\xfa"  # Subnegotiation Begin
SE = b"\xf0"  # Subnegotiation End
ECHO = b"\x01"  # Echo Option
SGA = b"\x03"  # Suppress Go Ahead


class TelnetHelper:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""
        self.skip_lf = False

    def read_line(self, echo=True):
        line_bytes = b""
        while True:
            # 1. Handle Skip LF from previous CR
            if self.skip_lf:
                if self.buffer.startswith(b"\n"):
                    self.buffer = self.buffer[1:]
                    self.skip_lf = False
                elif self.buffer:
                    # Buffer has non-LF bytes, so no LF followed CR.
                    self.skip_lf = False
                # If buffer empty, we keep skip_lf=True and wait for data to confirm

            # 2. Refill Buffer
            if not self.buffer:
                try:
                    data = self.sock.recv(1024)
                    if not data:
                        return line_bytes.decode("utf-8", errors="ignore").strip()
                    self.buffer += data
                except OSError:
                    return line_bytes.decode("utf-8", errors="ignore").strip()

            # Re-check Skip LF in case we just filled buffer
            if self.skip_lf:
                if self.buffer.startswith(b"\n"):
                    self.buffer = self.buffer[1:]
                    self.skip_lf = False
                else:
                    self.skip_lf = False

            if not self.buffer:
                continue  # Should return on EOF loop above, but safety

            # 3. Process Byte
            char = self.buffer[0:1]
            self.buffer = self.buffer[1:]

            # Handle IAC
            if char == IAC:
                # Need at least 2 more bytes for standard CMD OPT
                # We loop to fill buffer if needed
                need = 2
                while len(self.buffer) < need:
                    try:
                        more = self.sock.recv(1024)
                        if not more:
                            break
                        self.buffer += more
                    except:
                        break

                if len(self.buffer) >= need:
                    self.buffer = self.buffer[need:]  # consume CMD + OPT
                # If EOF during negotiation, we just continue (next loop handles EOF)
                continue

            # Handle Backspace
            if char == b"\x08" or char == b"\x7f":
                if len(line_bytes) > 0:
                    line_bytes = line_bytes[:-1]
                    if echo:
                        self.sock.sendall(b"\x08 \x08")
                continue

            # Handle CR (Carriage Return)
            if char == b"\r":
                # Treat as Newline.
                # Mark to skip *possible* next LF
                self.skip_lf = True
                if echo:
                    self.sock.sendall(b"\r\n")
                return line_bytes.decode("utf-8", errors="ignore").strip()

            # Handle LF (Line Feed)
            if char == b"\n":
                # Treat as Newline (Standalone LF)
                if echo:
                    self.sock.sendall(b"\r\n")
                return line_bytes.decode("utf-8", errors="ignore").strip()

            # Normal Char
            line_bytes += char
            if echo:
                self.sock.sendall(char)


# Telnet Session Limits
MAX_CONCURRENT_TELNET_SESSIONS = 20
MAX_TELNET_SESSIONS_PER_IP = 3

active_telnet_sessions = 0
active_telnet_lock = threading.Lock()
telnet_ip_counts = {}


def handle_telnet_session(client_sock, addr, db, llm):
    global active_telnet_sessions
    ip = addr[0]
    session_id = os.urandom(8).hex()

    # 1. DoS Protection
    from ssh_honeypot.core.dos_protection import dos_protector

    if not dos_protector.is_allowed(ip, "Telnet"):
        # dos_protector logs the ban
        client_sock.close()
        return

    # 2. Concurrency Limits
    should_drop = False
    with active_telnet_lock:
        ip_count = telnet_ip_counts.get(ip, 0)

        if active_telnet_sessions >= MAX_CONCURRENT_TELNET_SESSIONS:
            log.warning(
                f"[Telnet] Max sessions reached ({MAX_CONCURRENT_TELNET_SESSIONS}). Dropping {ip}"
            )
            should_drop = True
        elif ip_count >= MAX_TELNET_SESSIONS_PER_IP:
            log.warning(
                f"[Telnet] Max sessions per IP reached ({MAX_TELNET_SESSIONS_PER_IP}) for {ip}"
            )
            should_drop = True
        else:
            active_telnet_sessions += 1
            telnet_ip_counts[ip] = ip_count + 1

    if should_drop:
        client_sock.close()
        return

    try:
        from ssh_honeypot.core.utils import get_ignored_ips

        ignored_ips = get_ignored_ips()
        bypass_enabled = config.get("security", "bypass_auth_for_ignored_ips")
        is_trusted = bypass_enabled and (
            ip in ignored_ips or ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
        )

        log.info(f"[Telnet] New Connection from {ip} (Trusted: {is_trusted})")
        # 1. Basic Telnet Negotiation
        # Load Cisco IOS Persona
        persona_config = config.get_persona_by_name("cisco_ios")

        # Determine Hostname/Banner
        hostname = "Router"
        if persona_config and "system" in persona_config:
            hostname = persona_config["system"].get("hostname", hostname)
        else:
            hostname = config.get("server", "hostname") or "npc-main-server-01"

        banner = ""
        if persona_config and "network" in persona_config:
            banner = persona_config["network"].get("ssh_banner", "")

        if not banner:
            banner = f"\r\nDebian GNU/Linux 10 (buster)\r\n{hostname} login: "
        else:
            # Persona provided banner (usually includes "User Access Verification" or similar)
            # Just append Username prompt
            banner = f"{banner}\r\nUsername: "

        client_sock.sendall(banner.encode())

        # Negotiate Character Mode (Suppress Go Ahead) + Server Echo
        # This prevents Line Mode buffering on client and Local Echo
        client_sock.sendall(IAC + WILL + SGA)
        client_sock.sendall(IAC + WILL + ECHO)

        # Helper for buffered IO and CR/LF handling
        tn = TelnetHelper(client_sock)

        if is_trusted:
            log.info(f"[Telnet] Bypassing login for Trusted IP: {ip}")
            username = "trusted_user"
            password = ""
        else:
            # 2. Login Loop
            username = ""
            while True:
                # Use separate helper
                text = tn.read_line(echo=True)

                if not text:
                    pass  # Empty line or EOF

                # Note: TelnetHelper handles echoing, backspaces, and IACs

                # Fix: Detect SSH Client on Telnet Port
                if text.startswith("SSH-"):
                    log.warning(
                        f"[Telnet] Protocol Mismatch: SSH Client detected from {ip} (Banner: {text.strip()}). Rejecting."
                    )
                    client_sock.close()
                    return

                if not text:
                    continue  # Prompt again effectively

                username = text
                break

            client_sock.sendall(b"Password: ")

            # --- PASSWORD MASKING START ---
            # Send IAC WILL ECHO. This tells client "Server will handle echo".
            # Standard clients will STOP local echoing.
            # Since we (server) won't echo the password chars, it remains hidden.
            client_sock.sendall(IAC + WILL + ECHO)

            password = ""
            while True:
                # Use helper with echo=False
                text = tn.read_line(echo=False)
                if not text:
                    pass

                # Allow empty password? Maybe. But let's assume not.
                if not text:
                    continue
                password = text
                break

            # --- PASSWORD MASKING END ---
        # We stay in WILL ECHO mode (Server Handles Echo)
        # But we start actually echoing in the shell loop.
        # We re-affirm WILL ECHO just in case client state drifted,
        # and ensure SGA is set for Character Mode interaction.
        client_sock.sendall(IAC + WILL + ECHO)
        client_sock.sendall(IAC + WILL + SGA)

        client_sock.sendall(b"\r\n")

        # Log Attempt
        log.info(f"[Telnet] Auth attempt: {username}/{password} from {ip}")

        # Anti-Harvesting Check
        is_safe, reason = db.validate_anti_harvesting(ip, username, password)
        if not is_safe:
            log.warning(f"[Telnet] {reason}")
            # Simulate generic login failure or disconnect
            client_sock.sendall(b"\r\nLogin incorrect\r\n")
            client_sock.close()
            auth_data = {
                "username": username,
                "password": password,
                "success": False,
                "method": "password",
                "client_version": "telnet_simple",
                "fingerprint": "telnet",
            }
            clogger.log_event("auth", auth_data, ip=ip, protocol="telnet")
            db.log_auth_event(
                ip,
                username,
                "password",
                password,
                False,
                "telnet_simple",
                fingerprint="telnet",
                protocol="telnet",
            )
            return

        auth_data = {
            "username": username,
            "password": password,
            "success": True,
            "method": "password",
            "client_version": "telnet_simple",
            "fingerprint": "telnet",
        }
        clogger.log_event("auth", auth_data, ip=ip, protocol="telnet")
        db.log_auth_event(
            ip,
            username,
            "password",
            password,
            True,
            "telnet_simple",
            fingerprint="telnet",
            protocol="telnet",
        )

        session_data = {
            "username": username,
            "password": password,
            "client_version": "telnet_client",
            "fingerprint": "telnet",
        }
        clogger.log_event(
            "session_start",
            session_data,
            session_id=session_id,
            ip=ip,
            protocol="telnet",
        )

        # 3. Shell State
        user = username
        if user == "root":
            cwd = "/root"
        else:
            cwd = f"/home/{user}"

        # Setup specific for this session
        vfs = {
            "/tmp": [],
            "/var/www/html": ["index.php", "config.php", "assets", "uploads"],
        }
        history = []
        env = {}
        llm_call_count = 0

        handler = CommandHandler(llm, db, allow_all_commands=True)

        # Initial Message (MOTD)
        # Only show Linux banner if NOT a specialized network device
        is_network_device = False
        if persona_config and (
            "cisco" in persona_config.get("system", {}).get("handler_type", "")
            or "juniper" in persona_config.get("system", {}).get("handler_type", "")
        ):
            is_network_device = True

        if not is_network_device:
            client_sock.sendall(
                f"Linux {hostname} 3.16.0-6-amd64 #1 SMP Debian 3.16.56-1+deb8u1 (2018-04-23) x86_64\r\n".encode()
            )
            client_sock.sendall(
                f"The programs included with the Debian GNU/Linux system are free software.\r\n".encode()
            )
            client_sock.sendall(
                f"Last login: {time.ctime()} from 10.0.0.5\r\n".encode()
            )

        if "cisco_ios" in str(persona_config):
            prompt = f"{hostname}> "
        else:
            prompt = f"{user}@{hostname}:{cwd}$ "
        client_sock.sendall(prompt.encode())

        # Command Loop
        cmd_buffer = ""

        while True:
            try:
                chunk = client_sock.recv(1024)
            except OSError:
                break
            if not chunk:
                break

            # Telnet Filtering (Inline)
            i = 0
            while i < len(chunk):
                byte = chunk[i : i + 1]

                # Handle IAC
                if byte == IAC:
                    if i + 2 < len(chunk) and chunk[i + 1 : i + 2] in [
                        DO,
                        DONT,
                        WILL,
                        WONT,
                    ]:
                        i += 3
                        continue
                    i += 1
                    continue

                # Handle Newlines (Robust CR/LF/CR-NUL)
                is_newline = False
                if byte == b"\n":
                    is_newline = True
                elif byte == b"\r":
                    if i + 1 < len(chunk) and chunk[i + 1 : i + 2] == b"\n":
                        # CR followed by LF: Skip CR, let next iteration (LF) handle it
                        i += 1
                        continue
                    else:
                        # CR alone or CR NUL: Treat as Newline
                        is_newline = True

                if is_newline:
                    # Execute
                    cmd = cmd_buffer.strip()
                    client_sock.sendall(b"\r\n")

                    if cmd == "exit" or cmd == "logout":
                        break
                    if cmd == "clear":
                        client_sock.sendall(b"\033[2J\033[H")
                        cmd_buffer = ""
                    elif cmd:
                        # Process
                        log.debug(f"[Telnet] Exec: {cmd}")

                        context = {
                            "env": env,
                            "cwd": cwd,
                            "user": user,
                            "vfs": vfs,
                            "history": history,
                            "client_ip": ip,
                            "try_stream": False,
                            "honeypot_ip": "192.168.1.55",
                            "llm_call_count": llm_call_count,
                            "file_list": [
                                os.path.basename(x.get("path", ""))
                                for x in (db.list_user_dir(ip, user, cwd or "/") or [])
                                if x and x.get("path")
                            ],
                            "known_paths": list(vfs.keys()) if vfs else ["/"],
                            "prompt": prompt,
                            "protocol": "telnet",
                            "session_id": session_id,
                            "persona_config": persona_config,
                        }

                        # Command Delay (Throttling)
                        from ssh_honeypot.core.utils import random_response_delay

                        random_response_delay(0.5, 2.0)

                        start_time = time.time()
                        updates = {}  # Initialize to prevent UnboundLocalError
                        # Resilient Unpacking
                        try:
                            res_obj = handler.process_command(cmd, context)
                            if isinstance(res_obj, (list, tuple)) and len(res_obj) >= 2:
                                resp_text = res_obj[0]
                                updates = res_obj[1] or {}
                                metadata = (
                                    res_obj[2]
                                    if len(res_obj) > 2
                                    else {"source": "handler", "cached": False}
                                )
                            else:
                                # Fallback for unexpected return types
                                resp_text = str(res_obj) if res_obj is not None else ""
                                updates = {}
                                metadata = {"source": "handler", "cached": False}

                            if resp_text:
                                client_sock.sendall(
                                    resp_text.replace("\n", "\r\n").encode()
                                )

                            if updates:
                                if updates.get("new_cwd"):
                                    new_dir = updates.get("new_cwd")
                                    if new_dir:
                                        cwd = new_dir
                                        prompt = f"{user}@{hostname}:{cwd}$ "
                                if updates.get("env") and isinstance(
                                    updates.get("env"), dict
                                ):
                                    # Merge env updates
                                    env.update(updates.get("env"))

                            if updates.get("terminate"):
                                log.info(
                                    f"[Telnet] Session {session_id} Termination requested via command: {cmd}"
                                )
                                # Final response will be sent below
                                break

                        except Exception as e:
                            log.error(f"[Telnet] Command Execution Error: {e}")
                            # Suppress raw traceback in standard logs unless DEBUG is set
                            # We can still log the fact that an error occurred.
                            if os.getenv("SSHPOT_DEBUG", "false").lower() == "true":
                                import traceback

                                traceback.print_exc()

                            client_sock.sendall(b"Internal error executing command\r\n")
                        duration = time.time() - start_time

                        llm_call_count += 1

                        # Apply Updates
                        if updates:
                            if updates.get("new_cwd"):
                                new_dir = updates.get("new_cwd")
                                if new_dir:
                                    cwd = new_dir
                                    if cwd not in vfs:
                                        vfs[cwd] = []
                            if updates.get("env") and isinstance(
                                updates.get("env"), dict
                            ):
                                env.update(updates["env"])

                        # Send Output
                        # Normalize newlines to \r\n for Telnet
                        net_resp = resp_text.replace("\n", "\r\n")
                        if net_resp:
                            if not net_resp.endswith("\r\n"):
                                net_resp += "\r\n"
                            client_sock.sendall(
                                net_resp.encode("utf-8", errors="replace")
                            )

                        # Log
                        interaction_data = {
                            "cwd": cwd,
                            "input": cmd,
                            "response": resp_text,
                            "source": str(metadata.get("source")),
                            "duration_ms": round(duration * 1000, 2),
                        }
                        clogger.log_event(
                            "interaction",
                            interaction_data,
                            session_id=session_id,
                            ip=ip,
                            protocol="telnet",
                        )

                    cmd_buffer = ""

                    # Updates Prompt dynamic
                    is_cisco = False
                    cisco_persona = config.get_persona_by_name("cisco_ios")
                    if cisco_persona and "cisco" in cisco_persona.get("system", {}).get(
                        "handler_type", ""
                    ):
                        is_cisco = True
                    elif persona_config and "cisco" in persona_config.get(
                        "system", {}
                    ).get("handler_type", ""):
                        is_cisco = True
                        is_cisco = True

                    if is_cisco:
                        priv = env.get("privilege_level", 0)
                        conf = env.get("config_mode", False)
                        prompt_char = ">"
                        if priv >= 15:
                            prompt_char = "#"

                        host_disp = env.get("hostname_override", hostname)
                        if conf:
                            host_disp += "(config)"

                        prompt = f"{host_disp}{prompt_char} "
                    else:
                        prompt = f"{user}@{hostname}:{cwd}$ "

                    client_sock.sendall(prompt.encode())
                    i += 1
                    continue

                # Backspace
                if byte == b"\x08" or byte == b"\x7f":
                    if len(cmd_buffer) > 0:
                        cmd_buffer = cmd_buffer[:-1]
                        # Visual backspace
                        client_sock.sendall(b"\x08 \x08")
                    i += 1
                    continue

                # Normal Char
                try:
                    char = byte.decode("utf-8")
                    cmd_buffer += char
                    client_sock.sendall(byte)
                except:
                    pass

                i += 1

    except Exception as e:
        log.error(f"[Telnet] Session Error: {e}")
    finally:
        with active_telnet_lock:
            active_telnet_sessions -= 1
            if ip in telnet_ip_counts:
                telnet_ip_counts[ip] -= 1
                if telnet_ip_counts[ip] <= 0:
                    del telnet_ip_counts[ip]

        try:
            client_sock.close()
        except:
            pass


def start_telnet_server(port, db, llm):
    """
    Starts the Telnet Server Listener thread.
    """

    def runner():
        bind_ip = (
            os.getenv("FAUXSSH_BIND_IP") or config.get("server", "bind_ip") or "0.0.0.0"
        )
        from ssh_honeypot.core.utils import create_dual_stack_socket

        try:
            sock = create_dual_stack_socket(bind_ip, port, backlog=100)
            family_str = (
                "IPv6 (Dual Stack)" if sock.family == socket.AF_INET6 else "IPv4"
            )
            log.info(f"[Telnet] Starting Honeypot on {bind_ip}:{port} ({family_str})")

            while True:
                client, addr = sock.accept()
                t = threading.Thread(
                    target=handle_telnet_session, args=(client, addr, db, llm)
                )
                t.daemon = True
                t.start()
        except Exception as e:
            log.critical(f"[!] Telnet Bind/Loop Error: {e}")

    t = threading.Thread(target=runner, args=())
    t.daemon = True
    t.start()
    return t
