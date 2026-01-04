import socket
import threading
import paramiko
import os
import time
import json
import random
import logging
from dotenv import load_dotenv, find_dotenv

# Load .env from anywhere in the tree (e.g. parent dir)
load_dotenv(find_dotenv())
try:
    from .honey_db import HoneyDB
    from .llm_interface import LLMInterface
    from .command_handler import CommandHandler
    from .micro_editor import MicroEditor
    from .micro_editor import MicroEditor
    from .config_manager import config, get_data_dir
    from .sftp_handler import HoneySFTPServer
    from .alert_manager import AlertManager
    from . import fs_seeder
    from .utils import random_response_delay
    # Initialize Logging
    from .logger import log
except ImportError:
    # Fallback for direct execution
    from honey_db import HoneyDB
    from llm_interface import LLMInterface
    from command_handler import CommandHandler
    # from micro_editor import MicroEditor
    from config_manager import config, get_data_dir
    from sftp_handler import HoneySFTPServer
    from alert_manager import AlertManager
    import fs_seeder
    # Logger Fallback
    from logger import log


# Settings
SERVER_BANNER = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"
HOST_KEY_FILE = os.path.join(get_data_dir(), 'host.key')

# --- Logging Filter for Paramiko Noise ---
class ParamikoFilter(logging.Filter):
    def filter(self, record):
        # Suppress "Error reading SSH protocol banner" tracebacks
        msg = record.getMessage()
        if "Error reading SSH protocol banner" in msg:
            return False
        if record.exc_info:
            exc_type, exc_value, _ = record.exc_info
            if "Error reading SSH protocol banner" in str(exc_value):
                return False
        return True

# Apply Filter
logging.getLogger("paramiko.transport").addFilter(ParamikoFilter())
# -----------------------------------------

try:
    PORT = int(os.getenv('SSHPOT_PORT', config.get('server', 'port') or 2222))
except ValueError:
    PORT = 2222

BIND_IP = os.getenv('SSHPOT_BIND_IP') or config.get('server', 'bind_ip') or '0.0.0.0'

# Initialize DB
db = HoneyDB()
# Auto-clean legacy artifacts
db.sanitize_artifacts()
alert_manager = AlertManager()

# Initialize LLM
# Attempt to load API KEY from .env if present
api_key = os.getenv("GOOGLE_API_KEY")
if not api_key:
    try:
        from dotenv import load_dotenv
        # Look for .env in multiple locations
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        parent_dir = os.path.dirname(project_root)
        
        candidate_paths = [
            os.path.join(project_root, '.env'),       # Standard: /app/.env
            os.path.join(parent_dir, '.env'),         # Parent:   /app/../.env
            os.path.join(script_dir, '.env'),         # Local:    /app/ssh_honeypot/.env
            '.env'                                    # CWD fallback
        ]
        
        env_loaded = False
        for env_path in candidate_paths:
            if os.path.exists(env_path):
                load_dotenv(dotenv_path=env_path)
                api_key = os.getenv("GOOGLE_API_KEY")
                if api_key:
                    if not api_key.strip():
                        log.warning(f"Found .env at {env_path} but GOOGLE_API_KEY is empty or whitespace.")
                        continue
                    log.info(f"Loaded .env from {env_path}. Key length: {len(api_key.strip())}")
                    env_loaded = True
                    break
        
        if not env_loaded:
             log.warning(f"No .env file found/valid in search paths: {candidate_paths}. Using env vars only.")

    except ImportError:
        log.warning("[!] python-dotenv not installed. Skipping .env load.")
    except Exception as e:
        log.error(f"[!] Error loading .env: {e}")

llm = LLMInterface(api_key)

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.username = None
        self.password = None
        self.subsystem = None
        self.transport_ref = None


    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def _parse_ssh_string(self, data, offset=0):
        try:
            if len(data) < offset + 4: return None, offset
            length = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            if len(data) < offset + length: return None, offset
            s = data[offset:offset+length]
            return s.decode('utf-8', errors='ignore'), offset + length
        except: return None, offset

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
        except: pass
        return None, None

    def _extract_fingerprint(self):
        if not self.transport_ref: return None
        
        fp = {}
        try:
            fp['cipher'] = getattr(self.transport_ref, 'remote_cipher', 'unknown')
            fp['mac'] = getattr(self.transport_ref, 'remote_mac', 'unknown')
            fp['compression'] = getattr(self.transport_ref, 'remote_compression', 'unknown')
            fp['kex'] = getattr(self.transport_ref, 'kex_alg', 'unknown')
            
            # Advanced Fingerprinting (HASSH) via internal attribute
            if hasattr(self.transport_ref, '_latest_kex_init'):
                 hassh, raw = self._compute_hassh(self.transport_ref._latest_kex_init)
                 if hassh:
                     fp['hassh'] = hassh
                     fp['hassh_algorithms'] = raw
            
            return fp
        except: return None

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        
        # Exponential Login Rejection (Anti-Harvesting)
        # Check if this IP has already compromised too many unique usernames in the last 24h
        if not os.getenv('SSHPOT_TEST_MODE'):
            try:
                # Get set of (username, password) tuples that worked
                existing_creds = db.get_unique_creds_last_24h(self.client_ip)
                
                # Check if this EXACT credential pair has worked before
                if (username, password) not in existing_creds:
                    # This is a NEW credential candidate (either new user, or existing user with new password)
                    
                    # Count unique usernames already compromised
                    unique_users = set(u for u, p in existing_creds)
                    
                    # FIX: If we already know a valid password for this user, do NOT allow a different one.
                    # This prevents harvesting/guessing after success.
                    if username in unique_users:
                         log.warning(f"[!] Anti-Harvesting: Blocking {self.client_ip} for user '{username}' (Known user, new password denied)")
                         return paramiko.AUTH_FAILED

                    count = len(unique_users)
                    
                    if count >= 5:
                        # Hard Block: Too many unique successful logins
                        log.warning(f"[!] Anti-Harvesting: Blocking {self.client_ip} for user '{username}' (Limit Reached: {count})")
                        return paramiko.AUTH_FAILED
                    
                    # Probability Rejection: 1->20%, 2->40%, 3->60%, 4->80%
                    prob = count / 5.0
                    if random.random() < prob:
                         log.warning(f"[!] Anti-Harvesting: Randomly blocking {self.client_ip} for user '{username}' (Prob: {prob:.2f})")
                         return paramiko.AUTH_FAILED

            except Exception as e:
                log.error(f"[!] Error in Anti-Harvesting check: {e}")

        success = (username != 'root')
        
        client_version = "unknown"
        if self.transport_ref:
            client_version = self.transport_ref.remote_version
            
        fp = self._extract_fingerprint()
        db.log_auth_event(self.client_ip, username, 'password', password, success, client_version, fingerprint=fp)

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
        auth_data = f"{key_type} {key_b64}"
        
        # Check ~/.ssh/authorized_keys
        # Resolve home dir
        home_dir = "/root" if username == "root" else f"/home/{username}"
        auth_keys_path = f"{home_dir}/.ssh/authorized_keys"
        
        # Check DB for this file
        # We need to scan user files (highest priority)
        # Note: We rely on db.get_user_node doing the lookup
        node = db.get_user_node(self.client_ip, username, auth_keys_path)
        
        authorized = False
        if node and node.get('type') == 'file' and node.get('content'):
            content = node['content']
            # Parse authed keys (one per line)
            for line in content.splitlines():
                if not line.strip() or line.strip().startswith('#'): continue
                # format: type key comment
                parts = line.split()
                if len(parts) >= 2:
                    if parts[0] == key_type and parts[1] == key_b64:
                        authorized = True
                        break
        
        fp = self._extract_fingerprint()
        db.log_auth_event(self.client_ip, username, 'publickey', auth_data, authorized, client_version, fingerprint=fp)
        
        if authorized:
            log.info(f"[Auth] Public Key Login SUCCESS for '{username}' from {self.client_ip}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.command = command
        self.event.set()
        return True

    def check_channel_subsystem_request(self, channel, name):
        self.subsystem = name
        self.event.set()
        return True


    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True



# ... existing imports
import collections

# Global Limits
MAX_CONCURRENT_SESSIONS = 20
MAX_SESSIONS_PER_IP = 3
MAX_FILES_PER_SESSION = 50 

active_sessions = 0
active_sessions_lock = threading.Lock()
ip_connection_counts = collections.defaultdict(int)


def handle_connection(client, addr):
    global active_sessions
    ip = addr[0]
    
    # 1. Check Global Connection Limit
    with active_sessions_lock:
        if active_sessions >= MAX_CONCURRENT_SESSIONS:
            log.warning(f"[!] Dropping connection from {ip}: Max sessions reached ({MAX_CONCURRENT_SESSIONS})")
            client.close()
            return
        
        # 2. Check Per-IP Limit
        if ip_connection_counts[ip] >= MAX_SESSIONS_PER_IP:
            log.warning(f"[!] Dropping connection from {ip}: Max sessions per IP reached ({MAX_SESSIONS_PER_IP})")
            client.close()
            return
            
        active_sessions += 1
        ip_connection_counts[ip] += 1
        
    try:
        _handle_connection_logic(client, addr)
    finally:
        with active_sessions_lock:
            active_sessions -= 1
            ip_connection_counts[ip] -= 1
            if ip_connection_counts[ip] <= 0:
                del ip_connection_counts[ip]

def _handle_connection_logic(client, addr):
    ip = addr[0]
    transport = paramiko.Transport(client)
    # Deception: Mask the banner to look like a real OpenSSH server
    transport.local_version = SERVER_BANNER
    
    # Load Host Key
    try:
        host_key = paramiko.RSAKey(filename=HOST_KEY_FILE)
    except FileNotFoundError:
        # Generate on fly if missing (first run)
        log.info("Generating new host key...")
        host_key = paramiko.RSAKey.generate(2048)
        host_key.write_private_key_file(HOST_KEY_FILE)
    
    except Exception as e:
        log.error(f"[!] Error loading host key: {e}")
        return

    try:
        transport.add_server_key(host_key)
        
        server = HoneypotServer(ip)
        server.transport_ref = transport # Allow access to transport info
        transport.start_server(server=server)
    except paramiko.SSHException as e:
        if "Error reading SSH protocol banner" in str(e):
             print(f"[!] Scanner disconnected without sending banner: {ip}")
             return
        print(f"[!] SSH Error with {ip}: {e}")
        return
    except Exception as e:
        print(f"[!] Unexpected error during handshake with {ip}: {e}")
        return

    # Wait for auth
    chan = transport.accept(20)
    if chan is None:
        return

    server.event.wait(10)
    if not server.event.is_set():
        transport.close()
        return

    # Session Started
    session_id = os.urandom(8).hex()
    
    # Fingerprint Client
    fingerprint = {}
    try:
        fingerprint = {
            'cipher': getattr(transport, 'remote_cipher', 'unknown'),
            'mac': getattr(transport, 'remote_mac', 'unknown'),
            'compression': getattr(transport, 'remote_compression', 'unknown'),
            'kex': getattr(transport, 'kex_alg', 'unknown')
        }
    except: 
        pass
    
    try:
        db.start_session(session_id, ip, server.username, server.password, transport.remote_version, fingerprint=json.dumps(fingerprint))
        log.info(f"[*] New Session {session_id} from {ip} as {server.username}")
    except Exception as e:
        log.error(f"[!] Critical Error starting session: {e}")

    # Shell Loop or Single Command
    user = server.username if server.username else "alabaster"
    
    # Determine Home Directory
    if user == "root":
        cwd = "/root"
    else:
        cwd = f"/home/{user}"
        
    hostname = config.get('server', 'hostname') or "npc-main-server-01"
    
    # Virtual Filesystem State (Simple Dict: Path -> List of Filenames)
    # We assume standard linux dirs exist, this tracks *contents* we want to show.
    # Initialize dynamic home with default files - Blogofy Persona
    
    # COW REFACTOR: Removed ensure_user_home. 
    # HoneyDB now handles default file visibility via Skeleton layer.
    
    vfs = {
        cwd: [
            "blogofy_db_dump_2021.sql",
            "access_log.old.gz",
            "migration_notes.txt",
            "deploy_v3.sh",
            "docker-compose.yml.bak",
            "aws_keys.txt",
            "id_rsa_backup",
            "wallet.dat",
            ".bash_history",
            ".profile"
        ],
        "/tmp": [],
        "/var/www/html": ["index.php", "config.php", "assets", "uploads"]
    }

    # Attach context to server instance so SFTP Handler can access it
    server.vfs = vfs
    server.cwd = cwd
    server.session_id = session_id
    server.db = db

    # Handle SFTP Subsystem
    if server.subsystem == 'sftp':
        log.info(f"[*] Starting SFTP Handler for {session_id}")
        try:
            # Paramiko SFTPServer(channel, name, server, sftp_si)
            sftp = paramiko.SFTPServer(chan, session_id, server, HoneySFTPServer)
            sftp.start()
            # Loop keeping connection alive
            while transport.is_active():
                time.sleep(1)
        except Exception as e:
            log.error(f"[!] SFTP Error: {e}")
        return

    # State
    history = [] # List of (cmd, response)
    history_cursor = 0 # Points to end / new command slot
    llm_call_count = 0 # Rate limiting
    
    handler = CommandHandler(llm, db)

    # Handle Single Command Execution (SSH Exec)
    if hasattr(server, 'command') and server.command:
        # ... (Single command logic remains the same)
        cmd_bytes = server.command
        cmd = cmd_bytes.decode('utf-8', errors='ignore')
        
        context = {
            'cwd': cwd,
            'user': user,
            'vfs': vfs,
            'history': history,
            'client_ip': ip,
            'honeypot_ip': "192.168.1.55",
            'session_id': session_id,
            'llm_call_count': llm_call_count,
            'file_list': vfs.get(cwd, []),
            'known_paths': list(vfs.keys())
        }
        
        # Intercept SCP Interactive
        if cmd.strip().startswith('scp '):
             log.info(f"[*] Starting SCP Handler for {session_id} (cmd: {cmd})")
             try:
                 with open('/tmp/scp_server_debug.log', 'a') as f:
                     f.write(f"{time.time()} [SERVER] Calling handle_scp_interactive\n")
                 
                 # We need to pass the CHANNEL, not just the text
                 handler.handle_scp_interactive(cmd, chan, context)
                 
                 with open('/tmp/scp_server_debug.log', 'a') as f:
                     f.write(f"{time.time()} [SERVER] Returned from handler. Sending exit status 0.\n")
                 
                 chan.send_exit_status(0)
                 
                 with open('/tmp/scp_server_debug.log', 'a') as f:
                     f.write(f"{time.time()} [SERVER] Closing channel.\n")
                     
                 chan.close()
                 return
             except Exception as e:
                 log.error(f"[!] SCP Handler Error: {e}")
                 with open('/tmp/scp_server_debug.log', 'a') as f:
                     f.write(f"{time.time()} [SERVER] Exception: {e}\n")
                 return

        start_time = time.time()
        resp_text, modifications, metadata = handler.process_command(cmd, context)
        duration = time.time() - start_time
        duration_ms = round(duration * 1000, 2)
        
        # Compute Request MD5
        import hashlib
        try:
            cmd_hash = hashlib.md5(cmd.encode('utf-8')).hexdigest()
        except:
            cmd_hash = "unknown"
            
        # Compute Response Stats
        resp_md5 = None
        resp_head = None
        resp_size = 0
        
        if resp_text:
            try:
                resp_size = len(resp_text)
                resp_md5 = hashlib.md5(resp_text.encode('utf-8', 'ignore')).hexdigest()
                resp_head = resp_text[:100]
            except:
                pass

        log.debug(f"[DEBUG] Exec '{cmd}' -> Response Len: {len(resp_text)}")
        log.debug(f"[DEBUG] Logging Interaction: Source Type: {type(metadata.get('source'))} Val: {metadata.get('source')}")
        
        # Log Interaction
        db.log_interaction(
            session_id, 
            cwd, 
            cmd, 
            resp_text, 
            source=str(metadata.get('source', 'unknown')), 
            was_cached=metadata.get('cached', False),
            duration_ms=duration_ms,
            request_md5=str(cmd_hash),
            response_md5=resp_md5,
            response_head=resp_head,
            response_size=resp_size
        )

        try:
            if resp_text:
                chan.send(resp_text)
            chan.send_exit_status(0)
            chan.close()
        except OSError:
            pass # Client disconnected early
        return

    prompt = f"\r\n{user}@{hostname}:{cwd}$ "
    chan.send(f"Linux {hostname} 3.16.0-6-amd64 #1 SMP Debian 3.16.56-1+deb8u1 (2018-04-23) x86_64\r\n")
    chan.send(f"The programs included with the Debian GNU/Linux system are free software.\r\n")
    chan.send(f"Last login: {time.ctime()} from 10.0.0.5\r\n")
    chan.send(prompt)
    
    command_buffer = ""


    try:
        while True:
            char = chan.recv(1)
            # ... (Existing loop logic) ...
            if not char:
                break
                
            # Handle Ctrl+C (Interrupt)
            elif char == b'\x03':
                # Clear buffer, echo ^C, new line
                chan.send(b'^C\r\n')
                command_buffer = ""
                history_cursor = len(history)
                chan.send(prompt)
                
            # Handle Enter
            elif char == b'\r' or char == b'\n':
                # Ignore \n if it was preceded by \r (buffer empty)
                if char == b'\n' and command_buffer == "":
                     continue

                chan.send(b'\r\n') # Echo newline
                cmd = command_buffer.strip()
                command_buffer = ""
                history_cursor = len(history)
                
                if cmd:
                    log.debug(f"Processing cmd '{cmd}' in cwd '{cwd}'")
                    # Special Client-Side Commands
                    if cmd == 'exit':
                        break
                    if cmd == 'clear':
                        chan.send(b'\033[2J\033[H') # ANSI Clear
                        chan.send(prompt)
                        continue
                    
                    # --- COMMAND PROCESSING VIA HANDLER ---
                    
                    # Context for Handler
                    context = {
                        'cwd': cwd,
                        'user': user,
                        'vfs': vfs,
                        'history': history,
                        'client_ip': ip,
                        'honeypot_ip': "192.168.1.55",
                        'llm_call_count': llm_call_count,
                        'file_list': vfs.get(cwd, []),
                        'known_paths': list(vfs.keys())
                    }
                    
                    start_time = time.time()
                    resp_text, updates, metadata = handler.process_command(cmd, context)
                    duration = time.time() - start_time
                    duration_ms = round(duration * 1000, 2)
                    
                    # Compute Request MD5
                    import hashlib
                    try:
                        cmd_hash = hashlib.md5(cmd.encode('utf-8')).hexdigest()
                    except:
                        cmd_hash = "unknown"
                    
                    llm_call_count += 1 

                    # Apply State Updates
                    if updates:
                        if updates.get('new_cwd'):
                            cwd = updates.get('new_cwd')
                            if cwd not in vfs: vfs[cwd] = []
                            
                        if updates.get('file_modifications'):
                             for mod in updates.get('file_modifications'):
                                action = mod.get('action')
                                path = mod.get('path')
                                target_dir = cwd
                                filename = path
                                if '/' in path:
                                    parts = path.rsplit('/', 1)
                                    if path.startswith('/'):
                                            target_dir = parts[0] if len(parts) > 1 else '/'
                                            filename = parts[1]
                                
                                if target_dir not in vfs:
                                    vfs[target_dir] = []
                                    
                                if action == 'create':
                                # 3. DOS Protection: Check VFS Limit
                                    current_len = len(vfs.get(target_dir, []))
                                    if current_len >= MAX_FILES_PER_SESSION:
                                        resp_text += "\nError: Disk quota exceeded."
                                    else:
                                        if filename not in vfs[target_dir]:
                                            vfs[target_dir].append(filename)
                                elif action == 'delete':
                                    if filename in vfs[target_dir]:
                                        vfs[target_dir].remove(filename)

                    # Display Output
                    fmt_resp = resp_text.replace('\n', '\r\n')
                    chan.send(fmt_resp)
                    if fmt_resp and not fmt_resp.endswith('\r\n'):
                        chan.send(b'\r\n')
                        
                    # Log Interaction
                    db.log_interaction(
                        session_id, 
                        cwd, 
                        cmd, 
                        resp_text, 
                        source=str(metadata.get('source', 'unknown')), 
                        was_cached=metadata.get('cached', False),
                        duration_ms=duration_ms,
                        request_md5=str(cmd_hash)
                    )

                    # Alerting Integration: Check for Stream Trigger
                    try:
                        alert_manager.handle_interaction(session_id, ip, cmd, resp_text)
                    except Exception as e:
                        log.error(f"[Alert] Stream Error: {e}")
                    
                    # Manual JSON logging removed (handled by db.log_interaction)
                    
                    history.append((cmd, resp_text))

                # Update prompt with potentially new CWD or User
                prompt = f"{user}@{hostname}:{cwd}$ "
                chan.send(prompt)
                history_cursor = len(history) # Reset history cursor
            
            # Handle Backspace (Del or Backspace char)
            elif char == b'\x08' or char == b'\x7f':
                if len(command_buffer) > 0:
                    command_buffer = command_buffer[:-1]
                    # Erase char from terminal: Backspace, Space, Backspace
                    chan.send(b'\x08 \x08')

            # Handle Escape Sequences (Arrows)
            elif char == b'\x1b':
                # Simplified VT100 parser for Up/Down
                # We expect [A or [B.
                # In a real impl, we should use a state machine or non-blocking peek.
                # Here we assume the sequence comes in tight packet.
                try:
                    seq = chan.recv(2)
                    if seq == b'[A': # Up Arrow
                        if history_cursor > 0 and history:
                            history_cursor -= 1
                            prev_cmd = history[history_cursor][0] # History is (cmd, resp)
                            
                            # Clear Line
                            # Move cursor to start of line (after prompt) is hard if we don't track prompt len.
                            # Standard trick: \r, print prompt, print new cmd, clear rest
                            
                            # Naive Clear: 
                            backspaces = b'\x08' * len(command_buffer)
                            spaces = b' ' * len(command_buffer)
                            chan.send(backspaces + spaces + backspaces)
                            
                            command_buffer = prev_cmd
                            chan.send(command_buffer)
                            
                    elif seq == b'[B': # Down Arrow
                        if history_cursor < len(history):
                            history_cursor += 1
                            
                            # Clear Line
                            backspaces = b'\x08' * len(command_buffer)
                            spaces = b' ' * len(command_buffer)
                            chan.send(backspaces + spaces + backspaces)
                            
                            if history_cursor == len(history):
                                command_buffer = ""
                            else:
                                command_buffer = history[history_cursor][0]
                            chan.send(command_buffer)
                    
                    # Ignore other sequences (Left/Right/[C/[D) prevents cursor drift artifact
                    pass
                except:
                    pass

            # Handle Tab (Autocompletion)
            elif char == b'\t':
                command_buffer = handle_tab_completion(chan, command_buffer, vfs, cwd, prompt)

            # Normal Char
            else:
                try:
                    c = char.decode('utf-8')
                    # basic printable check
                    if c.isprintable():
                        command_buffer += c
                        chan.send(char) # Local echo
                except:
                    pass

    except Exception as e:
        log.error(f"Session Error: {e}")
    finally:
        db.end_session(session_id)
        transport.close()


def handle_tab_completion(chan, command_buffer, vfs, cwd, prompt):
    """
    Handles Tab key press for autocompletion.
    Returns the updated command_buffer.
    """
    # Simply Get last word
    parts = command_buffer.split()
    if not parts and not command_buffer:
            prefix = ""
    elif command_buffer.endswith(' '):
            prefix = ""
    else:
            prefix = parts[-1]
    
    candidates = []
    current_files = vfs.get(cwd, [])
    
    for f in current_files:
        if f.startswith(prefix):
            candidates.append(f)
            
    if len(candidates) == 1:
        # Completion!
        match = candidates[0]
        # We need to append the *remainder* of the word
        remainder = match[len(prefix):]
        command_buffer += remainder
        chan.send(remainder)
        return command_buffer
        
    elif len(candidates) > 1:
        # Multiple matches
        # Output list on new line
        chan.send(b'\r\n')
        output_list = "  ".join(candidates)
        chan.send(output_list)
        chan.send(b'\r\n')
        
        # Redraw prompt and buffer
        chan.send(prompt)
        chan.send(command_buffer)
        return command_buffer
    
    return command_buffer

def cleanup_loop(db_instance):
    """Background thread to clean up old uploads"""
    while True:
        try:
            # Configurable retention
            try:
                from .config_manager import config
            except ImportError:
                from config_manager import config
                
            days = config.get('upload', 'cleanup_days') or 30
            log.info(f"[Cleanup] Running prune job (retention: {days} days)...")
            
            deleted_items = db_instance.prune_uploads(days)
            if deleted_items:
                log.info(f"[Cleanup] Removed {len(deleted_items)} old upload records from DB.")
                
                # Optional: Delete physical files if we mapped them one-to-one
                # Since sftp_handler saves to 'uploaded_files/SESSION_ID/filename',
                # and DB stores 'path' (virtual), we rely on generic folder cleanup or specific mapping.
                # Here we just clean the DB records to stop them showing up in future sessions.
                # Physical disk cleanup of 'uploaded_files' can be done by age separately or here.
                # Let's clean the upload directory aggressively based on mtime too.
                # (Simple hygiene)
                
        except Exception as e:
            log.error(f"[Cleanup] Error: {e}")
            
        time.sleep(3600) # Run every hour

import argparse

def analysis_loop(db_instance, llm_instance, run_once=False):
    """Background thread to analyze commands with LLM"""
    log.info("[Analysis] Starting Threat Analysis Loop...")
    while True:
        try:
            # Poll for unanalyzed commands
            commands = db_instance.get_unanalyzed_commands(limit=10)
            
            if not commands:
                if run_once:
                    log.info("[Analysis] No commands to analyze. Exiting test mode.")
                    break
                time.sleep(10) # Wait if nothing to do
                continue
                
            # Batch Analysis
            log.info(f"[Analysis] Batch processing {len(commands)} commands...")
            
            # commands is now a list of dicts: {'request_md5':..., 'command':..., 'session_id':..., 'remote_ip':...}
            results = llm_instance.analyze_batch([(c['request_md5'], c['command']) for c in commands])
            
            for cmd_row in commands:
                cmd_hash = cmd_row['request_md5']
                cmd_text = cmd_row['command']
                session_id = cmd_row['session_id']
                ip = cmd_row['remote_ip']
                
                analysis = results.get(cmd_hash)
                
                if analysis:
                     log.info(f"[Analysis] Processed: {cmd_text[:30]}... -> {analysis.get('explanation')}")
                     db_instance.save_analysis(cmd_hash, cmd_text, analysis)
                     
                     # Check Risk for Alerting
                     try:
                         score = analysis.get('risk', 0)
                         explanation = analysis.get('explanation', '')
                         alert_manager.check_risk_score(session_id, ip, score, explanation)
                     except Exception as e:
                         log.error(f"[Analysis] Alert Error: {e}")
                else:
                    # If batch failed to return strict hash, maybe mark as failed or retry later?
                    # For now we skip saving, it will be picked up again?
                    # WARNING: If we don't save *something*, it will be picked up forever.
                    # We should save a failure record if missing.
                    log.warning(f"[Analysis] Batch Miss for: {cmd_text[:30]}...")
                    failure_analysis = {
                        'type': 'Unknown', 
                        'stage': 'Unknown', 
                        'risk': 0, 
                        'explanation': 'Analysis Failed: Batch Miss'
                    }
                    db_instance.save_analysis(cmd_hash, cmd_text, failure_analysis)
                     
            if run_once:
                log.info("[Analysis] Test run complete.")
                break

            # Rate limit protection (5 requests per minute = 12s delay)
            time.sleep(12)
                
        except KeyboardInterrupt:
            break
        except Exception as e:
             log.error(f"[Analysis] Error: {e}")
             if run_once: break
             time.sleep(30)
             
        time.sleep(5) # Poll interval

def main(argv=None):
    parser = argparse.ArgumentParser(description="SSH Honeypot Server")
    parser.add_argument("--test-analysis", action="store_true", help="Run a single pass of the analysis loop and exit")
    args = parser.parse_args(argv)

    # Ensure directories exist
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
    logs_dir = os.path.join(data_dir, 'logs')
    uploads_dir = os.path.join(data_dir, 'uploaded_files')
    
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(uploads_dir, exist_ok=True)
    
    # Seed Filesystem
    fs_seeder.seed_filesystem(db)

    # TEST MODE
    if args.test_analysis:
        log.info("[*] Running in Analysis Test Mode (Foreground)")
        analysis_loop(db, llm, run_once=True)
        return

    log.info(f"[*] Starting SSH Honeypot on {BIND_IP}:{PORT}...")
    
    # Start Cleanup Thread

    # Start Cleanup Thread
    cleanup_thread = threading.Thread(target=cleanup_loop, args=(db,), daemon=True)
    cleanup_thread.start()
    
    # Start Analysis Thread
    analysis_thread = threading.Thread(target=analysis_loop, args=(db, llm), daemon=True)
    analysis_thread.start()

    # Create Socket (IPv4/IPv6 Dual Stack Support)
    addr_family = socket.AF_INET
    if ':' in BIND_IP or BIND_IP == '::':
        addr_family = socket.AF_INET6
        print("[*] Detected IPv6 address family.")
    else:
        print("[*] Detected IPv4 address family.")

    sock = socket.socket(addr_family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Enable Dual Stack if using IPv6 (binds to :: but accepts IPv4 mapped)
    if addr_family == socket.AF_INET6:
        try:
             # IPPROTO_IPV6 = 41, IPV6_V6ONLY = 26
             # Using constants if available or hardcoded values
             IPPROTO_IPV6 = getattr(socket, 'IPPROTO_IPV6', 41)
             IPV6_V6ONLY = getattr(socket, 'IPV6_V6ONLY', 26)
             # Set to 0 to ALLOW both IPv4 and IPv6
             sock.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
             print("[*] Dual-stack (IPv4+IPv6) enabled on ::")
        except Exception as e:
             print(f"[!] Warning: Could not set IPV6_V6ONLY=0: {e}")

    # Bind with Graceful Retry
    max_retries = 5
    for attempt in range(max_retries):
        try:
            sock.bind((BIND_IP, PORT))
            sock.listen(100)
            break # Success
        except OSError as e:
            if e.errno == 98: # Address already in use
                if attempt < max_retries - 1:
                     print(f"[!] Address {BIND_IP}:{PORT} currently in use. Retrying in 2s... ({attempt+1}/{max_retries})")
                     time.sleep(2)
                     continue
                else:
                     log.error(f"[!] Critical: Failed to bind to {BIND_IP}:{PORT} after {max_retries} attempts. Port occupied.")
                     import sys
                     sys.exit(1) # Clean exit without traceback
            else:
                 raise # Re-raise unexpected errors

    # Generate Host Key if needed
    if not os.path.exists(HOST_KEY_FILE):
        print("[*] Generating Host Key...")
        k = paramiko.RSAKey.generate(2048)
        k.write_private_key_file(HOST_KEY_FILE)

    while True:
        client, addr = sock.accept()
        t = threading.Thread(target=handle_connection, args=(client, addr))
        t.start()

if __name__ == "__main__":
    main()
