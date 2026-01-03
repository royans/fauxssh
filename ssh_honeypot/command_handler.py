import json
import re
import os
import datetime
import time
import hashlib
import json
import logging
try:
    from .utils import random_response_delay
except ImportError:
    from utils import random_response_delay

import random

try:
    from .config_manager import config
except ImportError:
    from config_manager import config
import shlex

try:
    from .logger import log
except ImportError:
    from logger import log

class CommandHandler:
    def __init__(self, llm_interface, db):
        self.llm = llm_interface
        self.db = db
        self.honey_db = db # Alias for newer handlers


        
        try:
            from .config_manager import config
        except ImportError:
            from config_manager import config

        try:
            from .security_filter import SecurityFilter
        except ImportError:
            from security_filter import SecurityFilter
            
        try:
            from .handlers.system import SystemHandler
        except ImportError:
            from handlers.system import SystemHandler

        try:
            from .handlers import network_handlers
        except ImportError:
            from handlers import network_handlers

        self.security = SecurityFilter()
        self.system_handler = SystemHandler(db, llm_interface)
        self.network_handlers = network_handlers
        
        # Expanded whitelist maps commands to handler functions or generic
        self.STATE_COMMANDS = {
            'cd', 'touch', 'mkdir', 'rm', 'mv', 'cp', 'rmdir',
            'chmod', 'chown', 'wget', 'curl', 'scp',
            'export', 'alias', 'unalias', 'source', '.'
        }
        self.READ_ONLY_COMMANDS = {
            'ls', 'pwd', 'echo', 'cat', 
            'whoami', 'id', 'sudo', 'su',
            'history', 'help', 'man',
            'ps', 'top', 'kill', 'killall',
            'uname', 'hostname', 'uptime', 'date', 'df', 'du', 'free', 'nproc',
            'grep', 'awk', 'sed', 'find', 'locate', 'head', 'tail', 'more', 'less', 'wc', 'diff',
            'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'md5sum',
            'ssh', 'ping', 'sleep',
            'ifconfig', 'ip', 'netstat', 'ss', 'route', 'mount',
            'python', 'python3', 'perl', 'bash', 'sh', 'base64', 'time',
            'dmidecode', 'lscpu', 'lspci', 'fdisk'
        }
        self.HONEYTOKENS = {"aws_keys.txt", "id_rsa_backup", "wallet.dat"}
        self.FILESYSTEMS = [
            {"fs": "/dev/sda1", "mount": "/", "size": "40G", "used": "8.2G", "avail": "30G", "use": "22%", "type": "ext4"},
            {"fs": "udev", "mount": "/dev", "size": "3.9G", "used": "0", "avail": "3.9G", "use": "0%", "type": "devtmpfs"},
            {"fs": "tmpfs", "mount": "/run", "size": "796M", "used": "1.2M", "avail": "795M", "use": "1%", "type": "tmpfs"},
            {"fs": "/dev/sda15", "mount": "/boot/efi", "size": "124M", "used": "6.1M", "avail": "118M", "use": "5%", "type": "vfat"}
        ]


    def _handle_known_recon(self, cmd, context):
        # Deterministic handler for frequent botnet recon script
        if 'echo "UNAME:$uname"' in cmd and 'echo "GPU:$gpu_info"' in cmd:
             user = context.get('user', 'root')
             client_ip = context.get('client_ip', '192.168.1.150')
             
             uname = config.get('persona', 'kernel_version') or "Linux" # Actually custom fmt
             # Recon wants "Unix" style? No, it echoes $uname.
             # In _handle_known_recon line 78, it was "Linux ... ...".
             # That matches `uname -a`.
             # So I should construct it.
             k_name = config.get('persona', 'kernel_name') or "Linux"
             k_rel = config.get('persona', 'kernel_release') or "5.10.0-21-cloud-amd64"
             k_ver = config.get('persona', 'kernel_version') or "#1 SMP Debian 5.10.162-1 (2023-01-21)"
             k_mach = config.get('persona', 'machine') or "x86_64"
             
             uname = f"{k_name} npc-main-server-01 {k_rel} {k_ver} {k_mach}"
             arch = k_mach
             uptime = "202654.32" 
             cpus = "128"
             cpu_model = "Intel(R) Xeon(R) Platinum 8480+" 
             gpu_info = "00:00.0 3D controller: NVIDIA Corporation H100 PCIe [Hopper] (rev a1)"
             
             # Realistic help texts (truncated for brevity but sufficient for recon)
             ls_help = "Usage: ls [OPTION]... [FILE]... List information about the FILEs (the current directory by default). Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.  Mandatory arguments to long options are mandatory for short options too.   -a, --all                  do not ignore entries starting with .   -A, --almost-all           do not list implied . and ..       --author               with -l, print the author of each file   -b, --escape               print C-style escapes for nongraphic characters       --block-size=SIZE      with -l, scale sizes by SIZE when printing them;                              e.g., '--block-size=M'; see SIZE format below    -B, --ignore-backups       do not list implied entries ending with ~   -c                         with -lt: sort by, and show, ctime (time of last                              modification of file status information);                              with -l: show ctime and sort by name;                              otherwise: sort by ctime, newest first    -C                         list entries by columns       --color[=WHEN]         color the output WHEN; more info below   -d, --directory            list directories themselves, not their contents   -D, --dired                generate output designed for Emacs' dired mode"
             
             cat_help = "Usage: cat [OPTION]... [FILE]... Concatenate FILE(s) to standard output.  With no FILE, or when FILE is -, read standard input.    -A, --show-all           equivalent to -vET   -b, --number-nonblank    number nonempty output lines, overrides -n   -e                       equivalent to -vE   -E, --show-ends          display $ at end of each line   -n, --number             number all output lines   -s, --squeeze-blank      suppress repeated empty output lines   -t                       equivalent to -vT   -T, --show-tabs          display TAB characters as ^I   -u                       (ignored)   -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB       --help     display this help and exit       --version  output version information and exit  Examples:   cat f - g  Output f's contents, then standard input, then g's contents.   cat        Copy standard input to standard output.  GNU coreutils online help: <https://www.gnu.org/software/coreutils/> Full documentation <https://www.gnu.org/software/coreutils/cat> or available locally via: info '(coreutils) cat invocation'"
             
             last = f"root     pts/0        192.168.1.55     Tue Oct 27 10:00   still logged in\n{user}     pts/1        {client_ip}     Wed Oct 28 10:00   still logged in"
             
             response = f"UNAME:{uname}\nARCH:{arch}\nUPTIME:{uptime}\nCPUS:{cpus}\nCPU_MODEL:{cpu_model}\nGPU:{gpu_info}\nCAT_HELP:{cat_help}\nLS_HELP:{ls_help}\nLAST:{last}\n"
             return response, {}, {'source': 'simulated', 'cached': False}
        return None

    # --- NEW HANDLERS (Jan 2nd) ---

    def handle_time(self, cmd, context):
        """
        Executes a command and reports its execution time.
        Format:
        real    0m0.000s
        user    0m0.000s
        sys     0m0.000s
        """
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            return "bash: time: usage: time COMMAND [ARGS...]\n", {}, {'source': 'local', 'cached': False}
        
        sub_cmd = parts[1]
        
        # Measurement
        start = time.time()
        
        # Recursive execution
        out, updates, meta = self.process_command(sub_cmd, context)
        
        duration = time.time() - start
        
        # Format typical bash time output
        # real 0m0.002s
        mins = int(duration // 60)
        secs = duration % 60
        
        time_stats = f"\nreal\t{mins}m{secs:.3f}s\nuser\t0m0.000s\nsys\t0m0.000s\n"
        
        return out + time_stats, updates, meta

    def handle_echo(self, cmd, context):
        """
        Local echo handler.
        """
        import shlex
        try:
             parts = shlex.split(cmd)
             return " ".join(parts[1:]) + "\n", {}, {'source': 'local', 'cached': False}
        except:
             return cmd[5:] + "\n", {}, {'source': 'local', 'cached': False}

    def handle_fdisk(self, cmd, context):
        """
        Simulates fdisk -l output.
        """
        # Only support -l or no args (which usually errors but we can be nice or error)
        if '-l' not in cmd:
             return "fdisk: usage: fdisk [options] <disk>    change partition table\n       fdisk [options] -l <disk> list partition table(s)\n", {}, {'source': 'local', 'cached': False}

        # Simulated Output
        output = """Disk /dev/sda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 9A8B7C6D-1E2F-3G4H-5I6J-7K8L9M0N1O2P

Device        Start      End  Sectors  Size Type
/dev/sda1      2048     4095     2048    1M BIOS boot
/dev/sda2      4096 83884031 83880000   40G Linux filesystem

Disk /dev/sdb: 10 GiB, 10737418240 bytes, 20971520 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
"""
        return output, {}, {'source': 'local', 'cached': False}

    def handle_history(self, cmd, context):
        """
        Lists or clears history.
        """
        history = context.get('history', [])
        
        if '-c' in cmd:
            history.clear()
            return "", {}, {'source': 'local', 'cached': False}
            
        # List history
        lines = []
        for i, (c, _) in enumerate(history):
            lines.append(f" {i+1}  {c}")
            
        return '\n'.join(lines) + '\n', {}, {'source': 'local', 'cached': False}

    def handle_sudo(self, cmd, context):
        """
        Simulates sudo behavior.
        Anti-Escalation:
        - Rejects 'sudo su', 'sudo -i', 'sudo bash' (Root attempt)
        - Allows 'sudo su <user>' if user matches current user (No-op realism)
        - Generally returns 'Sorry' or incident report for others.
        """
        user = context.get('user', 'unknown')
        parts = cmd.split()
        
        # Logic: If they try to become root, block it realistically
        # "user is not in the sudoers file. This incident will be reported."
        
        if 'su' in parts:
             # Check if target user is self
             # sudo su user
             if len(parts) > 2 and parts[2] == user:
                 return "", {}, {'source': 'local', 'cached': False} # Success (no-op)
             
             if len(parts) == 2 or (len(parts) > 2 and parts[2] == '-'):
                 # sudo su / sudo su - (Root)
                if os.getenv('SSHPOT_TEST_MODE'):
                    random_response_delay(0.01, 0.05)
                else:
                    random_response_delay(1.0, 2.5) # Fake password delay?
                # Actually, real sudo asks password first.
                # We skip interaction and fail.
                return f"[sudo] password for {user}: \nSorry, try again.\n[sudo] password for {user}: \n", {}, {'source': 'local', 'cached': False}

        if '-i' in parts or '/bin/bash' in cmd or 'sh' in cmd:
             if os.getenv('SSHPOT_TEST_MODE'):
                 random_response_delay(0.01, 0.05)
             else:
                 random_response_delay(1.0, 2.0)
             return f"{user} is not in the sudoers file.  This incident will be reported.\n", {}, {'source': 'local', 'cached': False}

        # Default fail
        return f"sudo: a password is required\n", {}, {'source': 'local', 'cached': False}


    def process_command(self, cmd, context):
        """
        Input: cmd (str), context (dict)
        Output: (response_text_for_user, updates_dict, metadata)
        updates_dict = {'new_cwd': str, 'file_modifications': list}
        metadata = {'source': 'llm'|'cache'|'local', 'cached': bool}
        """
        cwd = context.get('cwd', '/')
        vfs = context.get('vfs', {})
        history = context.get('history', [])
        client_ip = context.get('client_ip', 'Unknown')
        honeypot_ip = context.get('honeypot_ip', '192.168.1.55')
        llm_call_count = context.get('llm_call_count', 0)

        # 0. Security / Injection Check
        is_safe, reason = self.security.validate_input(cmd)
        if not is_safe:
            print(f"[SECURITY] Blocked Input: {cmd} Reason: {reason}")
            # Log this? self.db.log_interaction(...) - Optional
            return f"bash: command blocked by security policy: {reason}\n", {}, {'source': 'security', 'cached': False}

        # 0. Special Recon Script Interception (Botnet optimization)
        recon_resp = self._handle_known_recon(cmd, context)
        if recon_resp:
            print(f"[Handler] Intercepted known recon script from {client_ip}")
            return recon_resp

        # 0. Complex Chain / Long Command Handling
        # If the command is very long or involves complex chaining/logic that our simple emulation
        # can't handle (and would benefit from LLM reasoning), offload it immediately.
        # Thresholds: > 150 chars, > 2 semicolons, > 2 pipes, or presence of logical AND/OR (&&, ||)
        # 0. Complex Command Chains (Simple Heuristic for now)
        try:
            base_cmd = cmd.split()[0]
        except IndexError:
            return "", {}, {'source': 'local', 'cached': False}

        # 0. Complex Command Chains (Simple Heuristic for now)
        is_complex = (len(cmd) > 150) or (cmd.count(';') > 2) or (cmd.count('|') > 2) or ('&&' in cmd) or ('||' in cmd)
        
        # Exempt 'echo' from complexity check (always handle locally to prevent JSON leaks on long strings)
        if is_complex and base_cmd != 'echo':
             # Check if we should log/print this event
             # Calculate signature for debug/cache key (though handle_generic uses raw cmd)
             sig = hashlib.md5(cmd.encode()).hexdigest()
             log.info(f"[Command] Complex chain detected (Len: {len(cmd)}, Sig: {sig[:8]}). Offloading entire chain to LLM.")
             
             # handle_generic checks cache internally and calls LLM if needed
             # This effectively treats the long chain as a single script execution
             return self.handle_generic(cmd, context)
        
        # 0. Command Chaining Support (;)
        # We need to handle this BEFORE pipe support, as ; has lower precedence.
        # e.g. "echo A ; echo B" -> [echo A, echo B]
        # But we must be careful not to split inside quotes (simplistic split for now)
        if ';' in cmd:
            parts = [p.strip() for p in cmd.split(';') if p.strip()]
            if len(parts) > 1:
                final_out = []
                final_updates = {}
                current_context = context.copy()
                
                for part in parts:
                    out, updates, meta = self.process_command(part, current_context)
                    final_out.append(out)
                    
                    # Update context for next command in chain
                    if updates:
                        if updates.get('new_cwd'):
                            current_context['cwd'] = updates['new_cwd']
                        # Merge updates
                        for k, v in updates.items():
                             if k == 'new_cwd': 
                                 final_updates[k] = v # Last one wins
                             elif k == 'file_modifications':
                                 if 'file_modifications' not in final_updates: final_updates['file_modifications'] = []
                                 final_updates['file_modifications'].extend(v)

                return "".join(final_out), final_updates, {'source': 'chain', 'cached': False}

        # 0. Tarpitting & Honeytoken Detection
        if llm_call_count > 30:
            time.sleep(3) # Heavy tarpit
        elif llm_call_count > 15:
            time.sleep(1) # Light tarpit

        for token in self.HONEYTOKENS:
            if token in cmd:
                log.warning(f"[!!!] HONEYTOKEN TRIGGERED: {token} by {client_ip}")
                try:
                     self.db.log_interaction(context.get('session_id', 'unknown'), f"ALERT: Token {token}", "User accessed bait file", "ALERT: Honeytoken Triggered", source="system", was_cached=False)
                except: pass

        # 0.5 Pipe Support (Simple Grep)
        # 0.5 Pipe Support (Context-Aware)
        pipe_pos = -1
        in_sq = False
        in_dq = False
        escaped = False
        
        for i, char in enumerate(cmd):
            if escaped:
                escaped = False
                continue
            
            if char == '\\':
                escaped = True
                continue
                
            if char == "'" and not in_dq:
                in_sq = not in_sq
            elif char == '"' and not in_sq:
                in_dq = not in_dq
            elif char == '|' and not in_sq and not in_dq:
                pipe_pos = i
                break
        
        if pipe_pos != -1:
            left_cmd = cmd[:pipe_pos].strip()
            right_cmd = cmd[pipe_pos+1:].strip()
            
            # Generalized Pipe Support
            # Recursive execution: Execute left, pass output as stdin to right
            
            # Execute Left Side
            out_text, updates, meta = self.process_command(left_cmd, context)
            
            # Prepare context for Right Side
            # We must copy context to avoid polluting parent scope (though in this design it might be fine)
            right_context = context.copy()
            right_context['stdin'] = out_text
            
            # Execute Right Side
            return self.process_command(right_cmd, right_context)

        # 0.6 Redirection Support (> and >>)
        redirect_pos = -1
        append_mode = False
        in_sq = False
        in_dq = False
        escaped = False
        
        for i, char in enumerate(cmd):
            if escaped: escaped = False; continue
            if char == '\\': escaped = True; continue
            
            if char == "'" and not in_dq: in_sq = not in_sq
            elif char == '"' and not in_sq: in_dq = not in_dq
            elif char == '>' and not in_sq and not in_dq:
                redirect_pos = i
                if i + 1 < len(cmd) and cmd[i+1] == '>':
                     append_mode = True
                break
        
        if redirect_pos != -1:
            left_cmd = cmd[:redirect_pos].strip()
            right_file = cmd[redirect_pos+1:].strip()
            if append_mode: right_file = cmd[redirect_pos+2:].strip()
            
            # Execute command to get output
            out_text, updates, meta = self.process_command(left_cmd, context)
            
            # Strip target file quotes if present
            if (right_file.startswith('"') and right_file.endswith('"')) or (right_file.startswith("'") and right_file.endswith("'")):
                 right_file = right_file[1:-1]
                 
            # Resolve path
            abs_path = self._resolve_path(cwd, right_file)
            
            if not self._is_modification_allowed(abs_path):
                 return f"bash: {right_file}: Permission denied\n", {}, {'source': 'local', 'cached': False}
            
            # Handle Write
            # We need client_ip and user from context
            user = context.get('user')
            
            # Content to write
            new_content = out_text
            
            # If append, read existing (from DB first, then check LLM fallback or assume empty?)
            # For simplicity, we only append if file exists in DB.
            if append_mode:
                node = self.db.get_user_node(client_ip, user, abs_path)
                if node and node.get('type') == 'file':
                     existing = node.get('content', '')
                     new_content = existing + new_content
            
            # Write to DB
            self.db.update_user_file(client_ip, user, abs_path, os.path.dirname(abs_path), 'file',
                                    {'size': len(new_content), 'permissions': '-rw-r--r--', 'owner': user, 'group': user, 'created': datetime.datetime.now().isoformat()}, new_content)
            
            # Return empty output (redirected)
            # Merge updates? Yes.
            if 'file_modifications' not in updates: updates['file_modifications'] = []
            updates['file_modifications'].append({'action': 'create', 'path': abs_path})
            
            return "", updates, {'source': 'redirection', 'cached': False}

        # 0.7 Execution Simulation (Malware/Script Execution)
        # Check if the command refers to a local file (uploaded or generated)
        # We need to handle ./ prefix explicitly or rely on resolve
        potential_path = base_cmd
        if not potential_path.startswith('/') and './' not in potential_path:
             # If just "script.sh", technically shell looks in PATH. 
             # But for honeypot, if it's in CWD, we might allow it if clearly user intent?
             # Standard Linux: must be ./script.sh unless in PATH.
             # We stick to standard: only check if it resolves to absolute path AND (is absolute OR starts with ./)
             pass 
        
        abs_path = self._resolve_path(cwd, potential_path)
        
        # Only check DB if it looks like a path execution (contains /) OR if we want to be generous
        if '/' in potential_path: 
            node = self.db.get_fs_node(abs_path)
            if node and node.get('type') == 'file':
                 log.debug(f"[DEBUG] Execution attempt on {abs_path}")
                 content = node.get('content', '')
                 
                 # Basic Executable Check (permissions would be better but we rely on content validty)
                 # Limit size sent to LLM
                 if not content:
                     return f"bash: {base_cmd}: Permission denied\n", {}, {'source': 'local', 'cached': False}
                 
                 if len(content) > 10000:
                     return f"bash: {base_cmd}: text file busy (simulated)\n", {}, {'source': 'local', 'cached': False}

                 log.info(f"[Execution] Simulating script via LLM: {abs_path}")
                 
                 prompt = f"The user is executing a script found at '{abs_path}' with content:\n---\n{content}\n---\n(INSTRUCTION: Act as the interpreter. EXECUTE this script virtually and return the Standard Output. Do not describe what it does, just show the output. If it modifies files, include file_modifications in JSON.)"
                 
                 resp = self.llm.generate_response(
                    cmd, # Use full cmd (args included)
                    cwd, 
                    history, 
                    [], 
                    [],
                    client_ip=client_ip, 
                honeypot_ip=honeypot_ip,
                    override_prompt=prompt
                 )
                 j, t = self._extract_json_or_text(resp)
                 out, ups = self._process_llm_json(j, t)
                 return out, ups, {'source': 'llm_exec', 'cached': False}

        # 1. Access Control
        if not self._is_allowed(cmd):
            return f"bash: {base_cmd}: command not found", {}, {'source': 'denied', 'cached': False}

        # 2. Cache Check Moved to handle_generic to allow overrides

        # 3. Rate Limit Check (if not cached)
        if llm_call_count >= 50:
            return "bash: fork: retry: Resource temporarily unavailable", {}, {'source': 'ratelimit', 'cached': False}

        # 4. Dispatch to Specific Handlers (or generic LLM)
        handler_name = f"handle_{base_cmd}"
        import sys
        sys.stderr.write(f"DEBUG: Dispatching '{base_cmd}' -> '{handler_name}'. HasAttr: {hasattr(self, handler_name)}\n")
        
        if hasattr(self, handler_name):
            # Deception: Add random delay to local commands to match LLM latency timing
            if not os.getenv('SSHPOT_TEST_MODE'):
                random_response_delay(0.5, 1.5)
            res = getattr(self, handler_name)(cmd, context)
            
            # Allow handlers to return custom metadata (esp. for hybrid handlers like cat)
            if len(res) == 3:
                return res[0], res[1], res[2]
            else:
                return res[0], res[1], {'source': 'local', 'cached': False}
        else:
            # Fallback: Try basename (e.g. /bin/ls -> ls, /bin/./uname -> uname)
            normalized_base = os.path.basename(base_cmd)
            handler_name_norm = f"handle_{normalized_base}"
            if hasattr(self, handler_name_norm):
                if not os.getenv('SSHPOT_TEST_MODE'):
                    random_response_delay(0.5, 1.5)
                # We pass the ORIGINAL cmd to the handler, it must handle parsing if needed.
                res = getattr(self, handler_name_norm)(cmd, context)
                 # Allow handlers to return custom metadata (esp. for hybrid handlers like cat)
                if len(res) == 3:
                    return res[0], res[1], res[2]
                else:
                    return res[0], res[1], {'source': 'local', 'cached': False}
            
            return self.handle_generic(cmd, context)

    def _is_allowed(self, cmd):
        base_cmd = cmd.split()[0]
        if '/' in base_cmd: return True
        if '=' in base_cmd: return True
        if base_cmd in self.STATE_COMMANDS: return True
        if base_cmd in self.READ_ONLY_COMMANDS: return True
        return False

    def _process_llm_json(self, r_json, r_text, vfs=None, cwd=None, user=None):
        """
        Standardizes return format.
        Output: (text_output, updates)
        """
        output_text = ""
        updates = {}

        if r_json:
            output_text = r_json.get('output', '')
            updates['new_cwd'] = r_json.get('new_cwd')
            updates['file_modifications'] = r_json.get('file_modifications')
        else:
            output_text = r_text
        
        # Post-Processing: Replace 'alabaster' artifact with actual user
        if user and output_text:
            output_text = output_text.replace("alabaster", user)
            output_text = output_text.replace("Alabaster", user.capitalize())
        
        return output_text, updates

    def _simple_grep(self, text, grep_cmd):
        """
        Rudimentary grep implementation for VFS checks.
        Supports: grep pattern, -i, -v, -E (regex), -m N (max count)
        """
        try:
            args = shlex.split(grep_cmd)
        except:
            args = grep_cmd.split()
            
        if len(args) < 2: return text
        
        # Naive Argument Parsing
        case_insensitive = '-i' in args
        invert = '-v' in args
        use_regex = '-E' in args or '--extended-regexp' in args
        
        max_count = None
        pattern = None
        
        # Iterate to find flags and pattern
        # Skip 'grep' (args[0])
        i = 1
        while i < len(args):
            arg = args[i]
            
            if arg == '-i' or arg == '-v' or arg == '-E' or arg == '--extended-regexp':
                i += 1
                continue
                
            if arg.startswith('-m'):
                if arg == '-m':
                    if i + 1 < len(args):
                        try:
                            max_count = int(args[i+1])
                            i += 1
                        except: pass
                else:
                    try:
                        max_count = int(arg[2:])
                    except: pass
                i += 1
                continue
            
            if arg.startswith('-') and len(arg) > 1:
                # Handle combined flags roughly? e.g. -iv
                # Just ignore unknown flags for now to avoid consuming pattern
                pass
                
            # If not a flag, assume Pattern (first positional)
            if pattern is None and not arg.startswith('-'):
                pattern = arg
            
            i += 1

        if pattern is None:
             # Fallback: Last arg?
             pattern = args[-1]
        
        filtered = []
        count = 0
        
        # Pre-compile regex if needed
        regex_obj = None
        if use_regex:
            flags = 0
            if case_insensitive: flags |= re.IGNORECASE
            try:
                regex_obj = re.compile(pattern, flags)
            except:
                pass # Fail gracefully, match nothing? or strings?
        
        for line in text.splitlines():
            # Strip ANSI for matching check (keep in output)
            clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
            
            match = False
            
            if regex_obj:
                if regex_obj.search(clean_line):
                    match = True
            else:
                # Substring match
                check_l = clean_line
                check_p = pattern
                if case_insensitive:
                    check_l = check_l.lower()
                    check_p = check_p.lower()
                
                if check_p in check_l:
                    match = True
            
            if invert:
                match = not match
            
            if match:
                filtered.append(line)
                count += 1
                if max_count is not None and count >= max_count:
                    break
        
        return '\n'.join(filtered)

    # --- NETWORK HANDLERS (Simulated Latency) ---
    
    def _is_whitelisted(self, cmd):
        """
        Simple heuristic to check if the command targets a popular/whitelisted domain.
        """
        whitelist = [
            "google.com", "www.google.com",
            "github.com", "raw.githubusercontent.com",
            "microsoft.com",
            "ubuntu.com", "security.ubuntu.com", "archive.ubuntu.com", "ports.ubuntu.com",
            "debian.org", "ftp.debian.org", "security.debian.org",
            "python.org", "pypi.org",
            "stackoverflow.com",
            "blogofy.com", "example.com",
            "127.0.0.1", "localhost", "0.0.0.0", "::1"
        ]
        
        # Check if any whitelist item is in the command string (simplistic but effective)
        for domain in whitelist:
            if domain in cmd:
                return True
        return False

    def handle_ssh(self, cmd, context):
        # Fake connection time
        if os.getenv('SSHPOT_TEST_MODE'):
             random_response_delay(0.01, 0.05)
        else:
             random_response_delay(1.0, 3.0)
        # Fallback to generic LLM for the actual interaction/error
        # But we can prime the LLM context or cache
        return self.handle_generic(cmd, context)


    # --- SPECIFIC HANDLERS ---
    
    # Generic Handler uses the standard big prompt from llm_interface
    def handle_generic(self, cmd, context):
        cwd = context.get('cwd')
        vfs = context.get('vfs')
        history = context.get('history')
        session_id = context.get('session_id', 'unknown')
        user = context.get('user')
        
        # 1. Check Cache (Moved here)
        log.debug(f"[Session: {session_id}] [Cache] Checking cache for '{cmd}' in '{cwd}'")
        cached_resp = self.db.get_cached_response(cmd, cwd)
        response_json, response_text = self._extract_json_or_text(cached_resp)
        if response_json or response_text:
            if "Resource temporarily unavailable" not in str(response_json) and "Resource temporarily unavailable" not in response_text:
                 log.debug(f"[Session: {session_id}] [Cache] HIT")
                 out, up = self._process_llm_json(response_json, response_text, vfs=vfs, cwd=cwd, user=user)
                 return out, up, {'source': 'cache', 'cached': True}
        
        log.debug(f"[Session: {session_id}] [Cache] MISS")
        log.info(f"[Session: {session_id}] [LLM] Calling LLM API for generic command...")

        # Call LLM
        # Note: llm_interface.generate_response uses the 'generic' prompt internally. 
        # Ideally we refactor LLMInterface to accept a prompt, but for now we reuse it.
        resp = self.llm.generate_response(
            cmd, 
            cwd, 
            history, 
            context.get('file_list', []), 
            context.get('known_paths', []), 
            client_ip=context.get('client_ip'), 
            honeypot_ip=context.get('honeypot_ip')
        )
        
        # Parse logic
        j, t = self._extract_json_or_text(resp)
        
        # Cache logic
        if "Error: AI Core Offline" not in resp and "Resource temporarily unavailable" not in resp:
            self.db.cache_response(cmd, cwd, resp)

        out, up = self._process_llm_json(j, t, user=user)
        
        # Sync Analysis Save
        if up.get('analysis'):
             try:
                 cmd_hash = hashlib.md5(cmd.encode('utf-8')).hexdigest()
                 self.db.save_analysis(cmd_hash, cmd, up['analysis'])
                 log.info(f"[Handler] Saved Sync Analysis for '{cmd}'")
             except Exception as e:
                 log.error(f"[Handler] Error saving sync analysis: {e}")
                 
        return out, up, {'source': 'llm', 'cached': False}

    def handle_ls(self, cmd, context):
        # 1. Parse Args
        parts = cmd.split()
        flags = set()
        target_path = context.get('cwd') # Default to CWD
        
        for p in parts[1:]:
            if p.startswith('-'):
                for char in p[1:]:
                     flags.add(char)
            else:
                target_path = p
        
        # 2. Resolve Path
        abs_path = self._resolve_path(context.get('cwd'), target_path)
        client_ip = context.get('client_ip')
        user = context.get('user')

        # 2a. Check if it is a specific file (Global or User)
        # Check User FS first (override)
        user_node = self.db.get_user_node(client_ip, user, abs_path)
        if user_node:
             if 'd' in flags or user_node.get('type') == 'file':
                 f = flags.copy()
                 f.add('a')
                 return self._format_ls_output([user_node], f), {}
        
        # Check Global FS
        global_node = self.db.get_fs_node(abs_path)
        if global_node and global_node.get('type') == 'file': # Only return if it's a file
             f = flags.copy()
             f.add('a')
             return self._format_ls_output([global_node], f), {}

        # 3. Check Global FS Cache (Treat as Directory)
        cached_files = self.db.list_fs_dir(abs_path)
        
        # 3a. Check User Persisted FS (Uploads)
        client_ip = context.get('client_ip')
        user = context.get('user')
        user_files = self.db.list_user_dir(client_ip, user, abs_path)
        
        # Merge User files over Global files
        # Map by filename to dedup
        file_map = {f['path'].split('/')[-1]: f for f in cached_files}
        
        for uf in user_files:
            fname = uf['path'].split('/')[-1]
            file_map[fname] = uf # User file overrides global
            
        # 3b. Merge with Session VFS (if present)
        # Session VFS is passed in context['vfs']. It is a dict of path -> [filenames] (simple strings)
        vfs_data = context.get('vfs', {})
        if abs_path in vfs_data:
             for fname in vfs_data[abs_path]:
                 # If in map, we already have metadata (either Global or User)
                 # If NOT in map, it's a temp file created in this session (touch, or generated)
                 if fname not in file_map:
                     file_map[fname] = {
                         'path': os.path.join(abs_path, fname),
                         'parent_path': abs_path,
                         'type': 'file', 
                         'metadata': {
                             'permissions': '-rw-r--r--', 
                             'size': random.randint(100, 15000) if not fname.endswith('.gz') else random.randint(100000, 500000), 
                             'owner': user or 'root', 
                             'group': user or 'root', 
                             'modified': datetime.datetime.now().strftime("%b %d %H:%M")
                         }
                     }
                     
        all_files = list(file_map.values())
        
        if all_files and len(all_files) > 0:
            log.debug(f"[DEBUG] LS Cache Hit for {abs_path}: {len(all_files)} files (DB: {len(cached_files)}, User/VFS: {len(all_files)-len(cached_files)})")
            return self._format_ls_output(all_files, flags), {}


        # 4. Fallback to LLM (Provide context if needed)
        # We pass empty file list for external paths to avoid hallucination confusion.
        lookup_files = []
        if abs_path == context.get('cwd') or abs_path.startswith('/home/'): 
             # Use vfs from context if available as fallback context
             if abs_path in context.get('vfs', {}):
                 lookup_files = context.get('vfs', {}).get(abs_path, [])
             elif abs_path == context.get('cwd'):
                 lookup_files = context.get('file_list', [])

        # Strong instruction to prevent history hallucination
        cmd_with_instruction = f"{cmd} (INSTRUCTION: List files in '{abs_path}'. Do NOT list files from {context.get('cwd')} or previous history keys. If directory is not empty, generate realistic files.)"

        resp = self.llm.generate_response(
            cmd_with_instruction, 
            context.get('cwd'), 
            context.get('history'), 
            lookup_files, 
            context.get('known_paths', []), 
            client_ip=context.get('client_ip'), 
            honeypot_ip=context.get('honeypot_ip')
        )
        
        j, t = self._extract_json_or_text(resp)
        
        # 5. Save Generated Files to DB
        if j and j.get('generated_files'):
            print(f"[DEBUG] Saving {len(j['generated_files'])} generated files for {abs_path}")
            for gf in j['generated_files']:
                # Ensure metadata fields
                if 'permissions' not in gf: gf['permissions'] = '-rw-r--r--'
                if 'size' not in gf: gf['size'] = 1024
                if 'owner' not in gf: gf['owner'] = 'root'
                if 'modified' not in gf: gf['modified'] = datetime.datetime.now().strftime("%b %d %H:%M")
                
                fname = gf.get('name')
                if fname:
                    fpath = os.path.join(abs_path, fname)
                    self.db.update_fs_node(fpath, abs_path, gf.get('type', 'file'), gf)
        
        if "Error: AI Core Offline" not in resp and "Resource temporarily unavailable" not in resp:
            self.db.cache_response(cmd, context.get('cwd'), resp)
            
        return self._process_llm_json(j, t)

    def _resolve_path(self, cwd, path):
        if path.startswith('/'):
            return os.path.normpath(path)
        elif path.startswith('~'):
             # Handle dynamic username in ~ expansion if possible, or just default to /home/user or context['cwd'] if logical
             # For now, simplistic
             if cwd.startswith('/home/'):
                  user_home = cwd.split('/', 3)[:3] # /home/user
                  return os.path.normpath(path.replace('~', '/'.join(user_home), 1))
             return os.path.normpath(path.replace('~', '/root', 1))
        else:
            return os.path.normpath(os.path.join(cwd, path))

    def _format_ls_output(self, files, flags):
        # Filter hidden
        if 'a' not in flags:
            files = [f for f in files if not f['path'].split('/')[-1].startswith('.')]

        # Sort (Name default)
        files.sort(key=lambda x: x['path'])
        if 'r' in flags:
            files.reverse()
            
        lines = []
        total_blocks = 0
        
        for f in files:
            name = f['path'].split('/')[-1]
            try:
                meta = json.loads(f['metadata']) if isinstance(f['metadata'], str) else f['metadata']
            except:
                meta = {}
            
            if 'l' in flags:
                perms = meta.get('permissions', '-rw-r--r--')
                links = 1
                owner = meta.get('owner', 'root')
                group = meta.get('group', 'root')
                size = meta.get('size', 4096)
                date = meta.get('modified', datetime.datetime.now().strftime("%b %d %H:%M")) 
                
                lines.append(f"{perms} {links} {owner} {group} {str(size).rjust(5)} {date} {name}")
                total_blocks += (int(size) // 512) + 1
            else:
                lines.append(name)
                
        if 'l' in flags:
            return f"total {total_blocks}\n" + "\n".join(lines)
        else:
            return "  ".join(lines) # Simple column view approximation


    def handle_cd(self, cmd, context):
        # Instruct LLM to be silent on success
        # 1. OPTIMIZATION: Check Local DB First
        parts = cmd.strip().split()
        target_path = parts[1] if len(parts) > 1 else "~"
        
        # Resolve target path relative to CWD
        cwd = context.get('cwd', '/')
        abs_path = self._resolve_path(cwd, target_path)
        
        # Check integrity
        # Check User FS first (override)
        user_node = self.db.get_user_node(context.get('client_ip'), context.get('user'), abs_path)
        if user_node:
             if user_node.get('type') == 'file':
                 return f"bash: cd: {target_path}: Not a directory\n", {}
             elif user_node.get('type') == 'dir': # 'dir' or 'directory'? standardized to 'dir' in mkdir but 'directory' in fs_seeder?
                 # mkdir uses 'dir'. fs_seeder seems to use 'directory'? 
                 # Let's support both or check strict.
                 # If it IS a directory, success.
                 log.debug(f"[Handler] CD Optimization Hit (User): {abs_path}")
                 return "", {'new_cwd': abs_path}

        node = self.db.get_fs_node(abs_path)
        if node:
             if node.get('type') == 'file':
                  return f"bash: cd: {target_path}: Not a directory\n", {}
             elif node.get('type') == 'directory':
                # Local Success! Return updates without LLM cost
                log.debug(f"[Handler] CD Optimization Hit (Global): {abs_path}")
                return "", {'new_cwd': abs_path}

        # 2. Fallback to LLM if path not found locally (maybe simulated in cache only?)
        # Instruct LLM to be silent on success
        cmd_with_instruction = f"{cmd} (INSTRUCTION: Execute directory change. Return 'new_cwd'. Output text MUST be empty on success. Do NOT list files.)"
        
        # We don't want to show files in context for CD usually, it confuses LLM into listing them.
        # So pass empty file list.
        resp = self.llm.generate_response(
            cmd_with_instruction, 
            context.get('cwd'), 
            context.get('history'), 
            [], # Empty context to prevent listing
            context.get('known_paths', []), 
            client_ip=context.get('client_ip'), 
            honeypot_ip=context.get('honeypot_ip')
        )
        j, t = self._extract_json_or_text(resp)
        
        # FORCE SILENCE if new_cwd is present
        if j and j.get('new_cwd'):
            j['output'] = ""
            
        if "Error: AI Core Offline" not in resp and "Resource temporarily unavailable" not in resp:
            self.db.cache_response(cmd, context.get('cwd'), resp)
        return self._process_llm_json(j, t)

    def handle_pwd(self, cmd, context):
        return f"{context.get('cwd', '/')}\n", {}

    def handle_whoami(self, cmd, context):
        return f"{context.get('user', 'unknown')}\n", {}

    # --- DELEGATES TO SYSTEM HANDLER ---
    
    def handle_hostname(self, cmd, context):
        return self.system_handler.handle_hostname(cmd, context)

    def handle_uptime(self, cmd, context):
        return self.system_handler.handle_uptime(cmd, context)

    def handle_ifconfig(self, cmd, context):
        # return self.system_handler.handle_ifconfig(cmd, context)
        # Use new consistent network persona
        out = self.network_handlers.handle_ifconfig([])
        return f"{out}\n", {}

    def handle_ip(self, cmd, context):
        args = cmd.split()[1:]
        out = self.network_handlers.handle_ip(args)
        return f"{out}\n", {}

    def handle_ping(self, cmd, context):
        args = cmd.split()[1:]
        out = self.network_handlers.handle_ping(args)
        return f"{out}\n", {}

    def handle_netstat(self, cmd, context):
        args = cmd.split()[1:]
        client_ip = context.get('client_ip', 'unknown')
        out = self.network_handlers.handle_netstat(args, client_ip)
        return f"{out}\n", {}

    def handle_ss(self, cmd, context):
        args = cmd.split()[1:]
        client_ip = context.get('client_ip', 'unknown')
        out = self.network_handlers.handle_ss(args, client_ip)
        return f"{out}\n", {}

    def handle_free(self, cmd, context):
        return self.system_handler.handle_free(cmd, context)

    def handle_df(self, cmd, context):
        return self.system_handler.handle_df(cmd, context)

    def handle_mount(self, cmd, context):
        return self.system_handler.handle_mount(cmd, context)
        
    def handle_netstat(self, cmd, context):
        return self.system_handler.handle_netstat(cmd, context)

    def handle_nproc(self, cmd, context):
        return self.system_handler.handle_nproc(cmd, context)




        
    def _generate_or_get_content(self, cmd_name, target_path, context):
        session_id = context.get('session_id', 'unknown')
        cwd = context.get('cwd')
        
        # 0. Check DB (User FS overrides Global FS)
        abs_path = self._resolve_path(cwd, target_path)
        client_ip = context.get('client_ip')
        user = context.get('user')
        
        # Check User Uploads first
        user_node = self.db.get_user_node(client_ip, user, abs_path)
        if user_node and (user_node.get('content') is not None):
             # print(f"[Session: {session_id}] [{cmd_name}] User DB HIT for {abs_path}")
             return user_node['content'], 'local'
        
        # Check Static/Dynamic Persona Files
        if hasattr(self, 'system_handler'):
            dyn_content = self.system_handler.get_dynamic_file(abs_path)
            if dyn_content:
                return dyn_content, 'local'
            
            static_content = self.system_handler.get_static_file(abs_path)
            if static_content:
                return static_content, 'local'

        # Check Global FS
        node = self.db.get_fs_node(abs_path)
        if node and (node.get('content') is not None):
             # print(f"[Session: {session_id}] [{cmd_name}] DB HIT for {abs_path}")
             return node['content'], 'local'
             
        # 1. Hardcoded Secret
        if 'notes.txt' in target_path: return "Hint: RudolphsRedNose2025!", 'local'

        print(f"[Session: {session_id}] [{cmd_name}] DB MISS for {abs_path}. Calling LLM.")
        
        # 2. LLM Call
        lookup_files = context.get('file_list', [])
        if '/' in target_path: lookup_files = []
        
        prompt = f"{cmd_name} {abs_path} (INSTRUCTION: Return a JSON object with key 'output' containing realistic file content for '{abs_path}'. Be creative.)"
        
        resp = self.llm.generate_response(
            cmd_name, 
            cwd, context.get('history'), lookup_files, 
            context.get('known_paths', []), 
            client_ip=context.get('client_ip'), 
            honeypot_ip=context.get('honeypot_ip'),
            override_prompt=prompt
        )
        
        j, t = self._extract_json_or_text(resp)
        if j and 'output' in j:
             # Ensure we store and return a string, even if LLM returns a dict
             content_str = j['output']
             if isinstance(content_str, (dict, list)):
                 content_str = str(content_str)
                 
             self.db.update_fs_node(abs_path, os.path.dirname(abs_path), 'file', {}, content_str)
             print(f"[Session: {session_id}] [{cmd_name}] Persisted content.")
             return content_str, 'llm'
        
        return t, 'llm'

    def handle_cat(self, cmd, context):
        if context.get('stdin'):
             return context['stdin'], {}, {'source': 'pipe', 'cached': False}
             
        parts = cmd.split()
        target_path = parts[-1] if len(parts) > 1 else ""
        if not target_path: return "", {}, {} # interactive cat not supported
        
        content, source = self._generate_or_get_content("cat", target_path, context)
        return content + "\n", {}, {'source': source, 'cached': source == 'local'}

    def handle_grep(self, cmd, context):
        # Delegate to _simple_grep for consistent logic (flags -i, -v, -E, -m)
        try:
            parts = shlex.split(cmd)
        except:
            parts = cmd.split()
            
        if len(parts) < 2: return "", {}, {}
        
        content = ""
        source = 'local'
        grep_cmd_for_parsing = cmd

        if context.get('stdin'):
            content = context['stdin']
            source = 'pipe'
            # cmd is like "grep pattern"
        else:
            if len(parts) < 3: return "", {}, {'source': 'local', 'cached': False}
            target_path = parts[-1]
            # Reconstruct cmd without the filename so _simple_grep handles pattern/flags correctly
            try:
                grep_cmd_for_parsing = shlex.join(parts[:-1])
            except AttributeError:
                 # Python < 3.8 fallback
                 grep_cmd_for_parsing = " ".join([shlex.quote(p) for p in parts[:-1]])
            content, source = self._generate_or_get_content("grep", target_path, context)
            
            # Remove filename from cmd so _simple_grep parses pattern correctly from last arg
            # E.g. "grep -i pattern file" -> "grep -i pattern"
            grep_cmd_for_parsing = ' '.join(parts[:-1])

        result_text = self._simple_grep(content, grep_cmd_for_parsing)
        # _simple_grep returns text, we need to ensure newline if needed or just return raw
        if result_text and not result_text.endswith('\n'):
             result_text += '\n'
             
        return result_text, {}, {'source': source, 'cached': source == 'local'}

    def handle_head(self, cmd, context):
        parts = cmd.split()
        # simplified parsing: ignore -n for now or just take last arg as file
        target_path = parts[-1] if len(parts) > 1 else ""
        content, source = self._generate_or_get_content("head", target_path, context)
        lines = content.split('\n')
        return '\n'.join(lines[:10]) + "\n", {}, {'source': source, 'cached': source == 'local'}

    def handle_tail(self, cmd, context):
        parts = cmd.split()
        target_path = parts[-1] if len(parts) > 1 else ""
        content, source = self._generate_or_get_content("tail", target_path, context)
        lines = content.split('\n')
        return '\n'.join(lines[-10:]) + "\n", {}, {'source': source, 'cached': source == 'local'}

    def handle_wc(self, cmd, context):
        parts = cmd.split()
        
        # Parse flags
        show_lines = False
        show_words = False
        show_chars = False
        target_path = None
        
        # Check flags (very naive)
        for p in parts[1:]:
            if p.startswith('-'):
                if 'l' in p: show_lines = True
                if 'w' in p: show_words = True
                if 'c' in p or 'm' in p: show_chars = True
            else:
                target_path = p
        
        # Default if no flags
        if not (show_lines or show_words or show_chars):
            show_lines = True
            show_words = True
            show_chars = True

        content = ""
        source = 'local'
        if context.get('stdin'):
            content = context['stdin']
            source = 'pipe'
            target_path = "" # No filename for stdin
        else:
            if not target_path: return "0 0 0\n", {}, {}
            content, source = self._generate_or_get_content("wc", target_path, context)

        lines = content.split('\n')
        if lines and lines[-1] == '': lines.pop() # Trailing newline handling
        
        # Counts
        c_lines = len(lines)
        c_words = len(content.split())
        c_chars = len(content)
        
        out_parts = []
        if show_lines: out_parts.append(str(c_lines))
        if show_words: out_parts.append(str(c_words))
        if show_chars: out_parts.append(str(c_chars))
        
        if target_path:
            out_parts.append(target_path)
            
        return " ".join(out_parts) + "\n", {}, {'source': source, 'cached': source == 'local'}

    def _handle_interpreter(self, cmd, context, interpreter_name="bash"):
        import hashlib # Ensure hashlib is imported for this function
        import json # Ensure json is imported for this function
        parts = cmd.split()
        if len(parts) < 2:
             # Interactive mode not supported well, return fake prompt or error
             return f"{interpreter_name}: missing file operand\n", {}
             
        target_path = parts[1] # script.sh
        
        # Get Content (Prioritizing User Uploads)
        content, source = self._generate_or_get_content(interpreter_name, target_path, context)
        
        # If content is short and looks like error (e.g. "cat: ..."), return it as is?
        # _generate_or_get_content returns LLM generated content if missing.
        # Ideally we want the REAL content.
        
        # We passed the check in process_command? No, this is the handler.
        
        print(f"[{interpreter_name}] Executing script: {target_path} (Context len: {len(content)})")
        
        prompt = f"The user is running the following {interpreter_name} script found at '{target_path}':\n\n```\n{content}\n```\n\n(INSTRUCTION: Act as the {interpreter_name} interpreter. EXECUTE this script virtually and return ONLY the Standard Output. Do not describe what it does. If it modifies files, include file_modifications in JSON.)"
        
        # Call LLM directly or via heuristic?
        # We use handle_generic logic but force specific prompt?
        # No, we call llm directly.
        # We should use cache. db.get_cached_response uses (cmd, cwd).
        # But here the 'cmd' is 'bash script.sh'. If script content changes, cmd is SAME.
        # So we MUST include content hash in the cache key.
        # OR, we construct a "virtual command" for the cache key?
        # Let's manually check cache with specific key?
        
        # Better: The LLM Interface likely doesn't cache. The DB `command_cache` does.
        # `db.get_cached_response(command, cwd)`
        # I should append the content hash to the command for caching purposes?
        # e.g. cache_key_cmd = f"{cmd}::{hash(content)}"
        
        content_hash = hashlib.md5(content.encode('utf-8', 'ignore')).hexdigest()
        cache_cmd_key = f"{cmd}::hash={content_hash}"
        
        cached = self.db.get_cached_response(cache_cmd_key, context.get('cwd'))
        if cached:
            return self._process_llm_json(json.loads(cached) if cached.startswith('{') else None, cached)
            
        # LLM Call
        history = context.get('history', [])
        # We pass minimal history to avoid noise, or full history?
        # Script execution should be stateless mostly unless it uses env vars?
        # Let's pass history.
        resp = self.llm.generate_response(prompt, context.get('cwd'), history, context.get('file_list'), context.get('known_paths'))
        
        # Cache it
        self.db.cache_response(cache_cmd_key, context.get('cwd'), resp)
        
        j, t = self._extract_json_or_text(resp)
        res, updates = self._process_llm_json(j, t)
        return res, updates, {'source': 'llm', 'cached': False}

    def handle_bash(self, cmd, context):
        return self._handle_interpreter(cmd, context, "bash")

    def handle_sh(self, cmd, context):
        return self._handle_interpreter(cmd, context, "sh")

    def handle_python(self, cmd, context):
        return self._handle_interpreter(cmd, context, "python")
        
    def handle_python3(self, cmd, context):
        return self._handle_interpreter(cmd, context, "python3")       

    def handle_md5sum(self, cmd, context):
        """
        Local md5sum handler.
        Hashes real files (uploaded) or generates deterministic hashes for fake files.
        """
        parts = cmd.split()
        if len(parts) < 2:
            return "md5sum: missing operand\n", {}, {'source': 'local', 'cached': False}
            
        target_path = parts[-1] # Simplistic arg parsing
        cwd = context.get('cwd', '/')
        abs_path = self._resolve_path(cwd, target_path)
        
        # 1. Check Real Persisted File (Uploads)
        # We need access to UPLOAD_DIR or ask DB where it is?
        # The DB doesn't store absolute local paths easily for all.
        # But we can try to see if it's in the User DB as a file.
        # Ideally, we should unify this, but for now, rely on _generate_or_get_content 
        # which pulls from DB 'content' field.
        
        # NOTE: _generate_or_get_content will either return the DB content 
        # OR generate it via LLM. This is exactly what we want.
        # We hash that content.
        
        content, source = self._generate_or_get_content("md5sum", target_path, context)
        
        # Calculate MD5
        if isinstance(content, str):
            content_bytes = content.encode('utf-8', 'ignore')
        else:
            content_bytes = content
            
        md5 = hashlib.md5(content_bytes).hexdigest()
        
        return f"{md5}  {target_path}\n", {}, {'source': source, 'cached': source == 'local'}

    def handle_date(self, cmd, context):
        return datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y\n"), {}

    def handle_id(self, cmd, context):
        user = context.get('user', 'alabaster')
        # Simulate typical uid/gid
        if user == 'root':
            return "uid=0(root) gid=0(root) groups=0(root)\n", {}
        else:
            return f"uid=1000({user}) gid=1000({user}) groups=1000({user}),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)\n", {}


    def handle_sleep(self, cmd, context):
        try:
            parts = cmd.split()
            duration = float(parts[1]) if len(parts) > 1 else 1.0
            
            # If test mode, skip sleep to avoid slow tests, UNLESS specific test requires it?
            # test_time_duration requires it to work.
            # But process_command doesn't know if it's called by test.
            # We can check environment.
            # If SSHPOT_TEST_MODE is set, we usually skip delays.
            # But for 'sleep' command specifically, maybe we should respect it if it's short?
            # Or just sleep.
            
            if os.getenv('SSHPOT_TEST_MODE'):
                # If duration is small (<3s), maybe sleep? 
                # But unit tests want speed.
                # test_time_duration is ONLY test using sleep?
                # It asserts duration.
                # So we MUST sleep.
                time.sleep(duration)
            else:
                time.sleep(duration)
        except ValueError:
             return f"sleep: invalid time interval '{parts[1]}'\n", {}
        except Exception:
             pass
        return "", {}, {'source': 'local', 'cached': False}

    def handle_ifconfig(self, cmd, context):
        # Delegate to network_handlers
        args = cmd.split()[1:]
        return self.network_handlers.handle_ifconfig(args), {}

    def handle_ip(self, cmd, context):
        args = cmd.split()[1:]
        return self.network_handlers.handle_ip(args), {}

    def handle_netstat(self, cmd, context):
        args = cmd.split()[1:]
        client_ip = context.get('client_ip', 'unknown')
        return self.network_handlers.handle_netstat(args, client_ip), {}

    def handle_ss(self, cmd, context):
        args = cmd.split()[1:]
        client_ip = context.get('client_ip', 'unknown')
        return self.network_handlers.handle_ss(args, client_ip), {}
        
    def handle_ping(self, cmd, context):
        args = cmd.split()[1:]
        # handle_ping in network_handlers typically yields? 
        # network_handlers.handle_ping returns STRING (implied from inspection)
        # But real ping streams. For now, block return is fine per current architecture
        return self.network_handlers.handle_ping(args), {}
        # Basic echo - handles "-e" partially or just returns string
        # Ignores redirection (handled by shell parser if any, else we print to stdout)
        # We need to strip "echo "
        if cmd.strip() == 'echo': return "\n", {}
        
        parts = cmd.split(' ', 1)
        if len(parts) < 2: return "\n", {}
        
        args = parts[1]
        
        # very naive quote handling
        if args.startswith('"') and args.endswith('"'):
            args = args[1:-1]
        elif args.startswith("'") and args.endswith("'"):
            args = args[1:-1]
            
        return f"{args}\n", {}

    def _is_modification_allowed(self, path):
        # Allow /tmp/, /home/, and /root/
        if path.startswith('/tmp/') or path.startswith('/home/') or path.startswith('/root/'):
            return True
        return False

    def handle_touch(self, cmd, context):
        parts = cmd.split()
        if len(parts) < 2: return "touch: missing file operand\n", {}
        
        target_path = parts[1]
        abs_path = self._resolve_path(context.get('cwd'), target_path)
        
        if not self._is_modification_allowed(abs_path):
             return f"touch: cannot touch '{target_path}': Permission denied\n", {}

        client_ip = context.get('client_ip')
        user = context.get('user')
        
        # Check if exists
        curr = self.db.get_user_node(client_ip, user, abs_path)
        if curr:
            # Update timestamp? Metadata stored as string logic... 
            # We skip timestamp update for now or simple re-save
            pass
        else:
            # Create empty file
            self.db.update_user_file(client_ip, user, abs_path, os.path.dirname(abs_path), 'file', 
                                    {'size': 0, 'permissions': '-rw-r--r--', 'owner': user, 'group': user, 'created': datetime.datetime.now().isoformat()}, "")
            
        return "", {'file_modifications': [{'action': 'create', 'path': abs_path}]}

    def handle_mkdir(self, cmd, context):
        parts = cmd.split()
        if len(parts) < 2: return "mkdir: missing operand\n", {}
        
        target_path = parts[1]
        abs_path = self._resolve_path(context.get('cwd'), target_path)
        
        if not self._is_modification_allowed(abs_path):
             return f"mkdir: cannot create directory '{target_path}': Permission denied\n", {}

        client_ip = context.get('client_ip')
        user = context.get('user')
        
        # Check if exists
        curr = self.db.get_user_node(client_ip, user, abs_path)
        if curr:
            return f"mkdir: cannot create directory '{target_path}': File exists\n", {}
            
        self.db.update_user_file(client_ip, user, abs_path, os.path.dirname(abs_path), 'dir', 
                                {'permissions': 'drwxr-xr-x', 'owner': user, 'group': user}, None)
        return "", {'file_modifications': [{'action': 'create', 'path': abs_path}]}
    
    def handle_rmdir(self, cmd, context):
        parts = cmd.split()
        if len(parts) < 2: return "rmdir: missing operand\n", {}
        target_path = parts[1]
        abs_path = self._resolve_path(context.get('cwd'), target_path)
        
        if not self._is_modification_allowed(abs_path):
             return f"rmdir: failed to remove '{target_path}': Permission denied\n", {}

        client_ip = context.get('client_ip')
        user = context.get('user')
        
        # Check if exists and is dir
        curr = self.db.get_user_node(client_ip, user, abs_path)
        if not curr:
            return f"rmdir: failed to remove '{target_path}': No such file or directory\n", {}
        if curr.get('type') != 'dir':
             return f"rmdir: failed to remove '{target_path}': Not a directory\n", {}
             
        # Check if empty from user FS perspective
        user_files = self.db.list_user_dir(client_ip, user, abs_path)
        if len(user_files) > 0:
             return f"rmdir: failed to remove '{target_path}': Directory not empty\n", {}
             
        self.db.delete_user_file(client_ip, user, abs_path)
        return "", {'file_modifications': [{'action': 'delete', 'path': abs_path}]}

    def handle_rm(self, cmd, context):
        parts = cmd.split()
        # handle -rf?
        flags = [p for p in parts if p.startswith('-')]
        targets = [p for p in parts if not p.startswith('-') and p != 'rm']
        
        if not targets: return "rm: missing operand\n", {}
        
        output = ""
        client_ip = context.get('client_ip')
        user = context.get('user')
        
        for t in targets:
            abs_path = self._resolve_path(context.get('cwd'), t)
            
            if not self._is_modification_allowed(abs_path):
                 output += f"rm: cannot remove '{t}': Permission denied\n"
                 continue

            # Only checking User FS for deletion simulation
            curr = self.db.get_user_node(client_ip, user, abs_path)
            
            if not curr:
                # If -f, ignore
                if not any('f' in f for f in flags):
                     output += f"rm: cannot remove '{t}': No such file or directory\n"
                continue
            
            if curr.get('type') == 'dir' and not any('r' in f for f in flags):
                output += f"rm: cannot remove '{t}': Is a directory\n"
                continue
                
            self.db.delete_user_file(client_ip, user, abs_path)
            
        mods = [{'action': 'delete', 'path': self._resolve_path(context.get('cwd'), t)} for t in targets]
        return output, {'file_modifications': mods}

    def handle_cp(self, cmd, context):
        parts = cmd.split()
        # cp src dest
        # Ignore flags for now
        args = [p for p in parts if not p.startswith('-') and p != 'cp']
        if len(args) < 2: return "cp: missing file operand\n", {}
        
        src = args[0]
        dest = args[1]
        
        abs_src = self._resolve_path(context.get('cwd'), src)
        abs_dest = self._resolve_path(context.get('cwd'), dest)
        
        if not self._is_modification_allowed(abs_dest):
             return f"cp: cannot create regular file '{dest}': Permission denied\n", {}

        # Get Source Content
        content, source = self._generate_or_get_content("cp", src, context)
        # Note: _generate calls LLM if missing... we trust it returns content?
        # If it returns "cat: ...", we might copy error message as content. Risk accepted for now.
        
        client_ip = context.get('client_ip')
        user = context.get('user')
        
        # Handle dest directory logic
        # is dest a dir?
        dest_node = self.db.get_user_node(client_ip, user, abs_dest)
        if dest_node and dest_node.get('type') == 'dir':
            # cp /tmp/foo.txt /home/user/ -> /home/user/foo.txt
            abs_dest = os.path.join(abs_dest, os.path.basename(abs_src))
            
            if not self._is_modification_allowed(abs_dest): # Check resolved path
                 return f"cp: cannot create regular file '{dest}': Permission denied\n", {}

        self.db.update_user_file(client_ip, user, abs_dest, os.path.dirname(abs_dest), 'file',
                                {'size': len(content), 'permissions': '-rw-r--r--', 'owner': user, 'group': user}, content)
                                
        return "", {'file_modifications': [{'action': 'create', 'path': abs_dest}]}
        
    def handle_mv(self, cmd, context):
        # reuse cp + rm logic
        parts = cmd.split()
        args = [p for p in parts if not p.startswith('-') and p != 'mv']
        if len(args) < 2: return "mv: missing operand\n", {}
        
        src = args[0]
        dest = args[1]
        
        # Check permissions handled by delegated cp and rm
        # BUT mv needs atomic check usually. 
        # If dest not allowed, cp fails. If src not allowed, rm fails.
        # Let's do explicit check for clarity.
        
        abs_dest = self._resolve_path(context.get('cwd'), dest)
        if not self._is_modification_allowed(abs_dest):
             return f"mv: cannot move '{src}' to '{dest}': Permission denied\n", {}
        
        # 1. CP
        res_cp = self.handle_cp(f"cp {src} {dest}", context)
        if "Permission denied" in res_cp[0]: return res_cp
        
        # 2. RM
        self.handle_rm(f"rm -rf {src}", context)
        
        return "", {} # Silent success assumption

    def handle_wget(self, cmd, context):
        import random
        import time
        import shlex
        
        parts = shlex.split(cmd)
        if len(parts) < 2: return "wget: missing URL\nUsage: wget [OPTION]... [URL]...", {}

        # Basic Argument Parsing
        url = None
        output_file = None
        user_agent = "Wget/1.21"
        is_quiet = False
        
        # Naive flag parsing
        skip_next = False
        for i, arg in enumerate(parts):
            if skip_next:
                skip_next = False
                continue
            
            if i == 0: continue # 'wget'
            
            if arg == '-O':
                if i + 1 < len(parts):
                    output_file = parts[i+1]
                    skip_next = True
            elif arg.startswith('-O'):
                output_file = arg[2:]
            elif arg == '-U' or arg == '--user-agent':
                if i + 1 < len(parts):
                    user_agent = parts[i+1]
                    skip_next = True
            elif arg == '-q' or arg == '--quiet':
                is_quiet = True
            elif not arg.startswith('-'):
                url = arg
        
        if not url: return "wget: missing URL", {}
        
        # Intelligence Logging
        if context.get('session_id'):
            self.honey_db.log_url_request(context['session_id'], url, "GET", user_agent, cmd)

        # Domain Extraction
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        
        # Localhost Check
        if domain in ['localhost', '127.0.0.1', '::1']:
            content = "<html><body><h1>It Works!</h1><p>Apache/2.4.56 (Debian)</p></body></html>"
            if output_file:
                # Save to VFS
                abs_path = self._resolve_path(context.get('cwd'), output_file)
                self.honey_db.update_user_file(context.get('ip'), context.get('user'), abs_path, os.path.dirname(abs_path), 'file', {'size': len(content)}, content)
                return "" if is_quiet else f"--{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving {domain}... 127.0.0.1\nConnecting to {domain}|127.0.0.1|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: {len(content)} [text/html]\nSaving to: '{output_file}'\n\n     0K .......... .......... .......... .......... ..........  100% 93.1M 0s\n\n{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ({len(content)} B/s) - '{output_file}' saved [{len(content)}/{len(content)}]\n", {}
            return content + "\n", {}

        # Hybrid LLM Generation
        if not is_quiet:
            # Simulate DNS and Connect
            response_pre = f"--{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving {domain}... {shlex.quote('1.1.1.1')}\nConnecting to {domain}|1.1.1.1|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: unspecified [text/html]\n"
            if output_file: 
                response_pre += f"Saving to: '{output_file}'\n\n"
        
        # Ask LLM for content
        prompt = f"Generate the likely source code (HTML/Shell Script) for the URL: {url}. user-agent: {user_agent}. Return ONLY the file content, no markdown."
        content = self.llm.generate_response(cmd, context.get('cwd'), override_prompt=prompt)
        
        # Post-Processing
        if output_file:
             # Save to VFS
             abs_path = self._resolve_path(context.get('cwd'), output_file)
             self.honey_db.update_user_file(context.get('ip'), context.get('user'), abs_path, os.path.dirname(abs_path), 'file', {'size': len(content)}, content)
             
             if not is_quiet:
                 # Fake Progress Bar
                 progress = f"    [ <=>                                                  ] {len(content)}        --.-K/s   in 0.1s    \n\n{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (10.0 MB/s) - '{output_file}' saved [{len(content)}]\n"
                 return response_pre + progress, {}
             return "", {}
             
        return content + "\n", {}

    def handle_curl(self, cmd, context):
        if not self._is_whitelisted(cmd):
             if os.getenv('SSHPOT_TEST_MODE'):
                 import time
                 import random
                 try:
                    from .utils import random_response_delay
                 except: from utils import random_response_delay
                 random_response_delay(0.1, 0.2)
             else:
                 import time
                 try:
                    from .utils import random_response_delay
                 except: from utils import random_response_delay
                 random_response_delay(5.0, 10.0)
             return "curl: (28) Connection timed out after 5001 milliseconds\n", {}, {'source': 'firewall', 'cached': False}

        import shlex
        import time
        import random
        
        parts = shlex.split(cmd)
        if len(parts) < 2: return "curl: try 'curl --help' for more information\n", {}
        
        url = None
        output_file = None
        user_agent = "curl/7.74.0"
        is_quiet = False
        is_head = False
        
        # Naive parsing
        skip_next = False
        for i, arg in enumerate(parts):
            if skip_next:
                skip_next = False
                continue
            if i == 0: continue
            
            if arg == '-O': # Remote Name
                skip_next = False # Url is next usually, but -O takes no arg
                # If -O is used, we need to infer filename from URL later
                output_file = "REMOTE_NAME" 
            elif arg == '-o':
                if i + 1 < len(parts):
                    output_file = parts[i+1]
                    skip_next = True
            elif arg == '-A' or arg == '--user-agent':
                if i + 1 < len(parts):
                    user_agent = parts[i+1]
                    skip_next = True
            elif arg == '-I' or arg == '--head':
                is_head = True
            elif arg == '-s' or arg == '--silent':
                is_quiet = True
            elif not arg.startswith('-'):
                url = arg

        if not url: return "curl: no URL specified!\n", {}
        
        if output_file == "REMOTE_NAME":
            output_file = url.split('/')[-1] or "index.html"

        # Intelligence
        if context.get('session_id'):
            self.honey_db.log_url_request(context['session_id'], url, "HEAD" if is_head else "GET", user_agent, cmd)
            
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]

        # Localhost
        if domain in ['localhost', '127.0.0.1', '::1']:
             content = "<html><body><h1>It Works!</h1></body></html>"
             if is_head:
                 return "HTTP/1.1 200 OK\nServer: nginx/1.18.0\nDate: Mon, 01 Jan 2026 12:00:00 GMT\nContent-Type: text/html\nContent-Length: 45\nConnection: keep-alive\n\n", {}
             return content + "\n", {}

        # Hybrid LLM
        prompt = f"Generate the likely source code for URL: {url}. Return ONLY the file content."
        if is_head:
             prompt = f"Generate HTTP Headers for URL: {url}. Return ONLY the headers."
             
        content = self.llm.generate_response(cmd, context.get('cwd'), override_prompt=prompt)
        
        if output_file and not is_head:
             abs_path = self._resolve_path(context.get('cwd'), output_file)
             self.honey_db.update_user_file(context.get('ip'), context.get('user'), abs_path, os.path.dirname(abs_path), 'file', {'size': len(content)}, content)
             if not is_quiet:
                 # Curl progress meter
                 #  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                 #                                  Dload  Upload   Total   Spent    Left  Speed
                 return f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100   {len(content)}  100   {len(content)}    0     0   {len(content)*10}      0 --:--:-- --:--:-- --:--:-- {len(content)*10}\n", {}
             return "", {}
             
        return content + "\n", {}
        
    def handle_more(self, cmd, context):
        # Alias to cat for simple non-interactive shell
        return self.handle_cat(cmd, context)

    def handle_less(self, cmd, context):
        # Alias to cat for simple non-interactive shell
        return self.handle_cat(cmd, context)


    def handle_ssh(self, cmd, context):
        import random
        # ssh user@host or ssh host
        parts = cmd.split()
        if len(parts) < 2: return "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] ...\n", {}
        
        target = parts[-1] # Simplistic
        if '@' in target:
             user, host = target.split('@', 1)
        else:
             host = target
             user = context.get('user', 'root')
             
        if host in ['localhost', '127.0.0.1', '::1']:
             # Simulate success (fake login banner)
             timestamp = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")
             return f"Last login: {timestamp} from 127.0.0.1\n", {}
        else:
             # Random network error
             time.sleep(1.0)
             errors = [
                 f"ssh: connect to host {host} port 22: Connection timed out",
                 f"ssh: connect to host {host} port 22: Connection refused",
                 f"ssh: Could not resolve hostname {host}: Name or service not known"
             ]
             return f"{random.choice(errors)}\n", {}

    def handle_scp(self, cmd, context):
        import random
        # scp source dest
        # Only handle if dest is localhost or failure
        # If -t is present, it shouldn't reach here (intercepted by server), but if it does:
        if '-t' in cmd or '-f' in cmd:
             return "scp: protocol error: unexpected internal execution\n", {}
             
        parts = cmd.split()
        args = [p for p in parts if not p.startswith('-') and p != 'scp']
        if len(args) < 2: return "usage: scp [-346BCpqrTv] [-c cipher] [-F ssh_config] ...\n", {}
        
        src = args[0]
        dest = args[1]
        
        # Check if dest is remote
        dest_host = None
        if ':' in dest:
             host_part, _ = dest.split(':', 1)
             if '@' in host_part:
                 _, dest_host = host_part.split('@', 1)
             else:
                 dest_host = host_part
        
        # Check if src is remote
        src_host = None
        if ':' in src:
             host_part, _ = src.split(':', 1)
             if '@' in host_part:
                 _, src_host = host_part.split('@', 1)
             else:
                 src_host = host_part

        remote_host = dest_host or src_host
        
        if remote_host and remote_host not in ['localhost', '127.0.0.1', '::1']:
             time.sleep(1.0)
             return f"ssh: connect to host {remote_host} port 22: Connection timed out\nlost connection\n", {}
             
        # If localhost or local->local, delegate to generic CP?
        # scp local user@localhost:/tmp/ -> cp local /tmp/
        # Simplistic mapping
        
        real_src = src.split(':')[-1]
        real_dest = dest.split(':')[-1]
        
        return self.handle_cp(f"cp {real_src} {real_dest}", context)


    def handle_uname(self, cmd, context):
        # Support basic flags: -a, -s, -n, -r, -v, -m, -p, -i, -o
        # Default (no args) is -s
        # We ignore flags for now and just return a standard "all" string if -a or multiple flags,
        # or just kernel name if no flags. 
        # Actually, let's be slightly smarter since the bot requests "-s -v -n -r -m".
        
        # Hardcoded Persona Values (Debian 11)
        kernel_name = config.get('persona', 'kernel_name') or "Linux"
        nodename = config.get('server', 'hostname') or "npc-main-server-01"
        
        kernel_release = config.get('persona', 'kernel_release') or "5.10.0-21-cloud-amd64"
        kernel_version = config.get('persona', 'kernel_version') or "#1 SMP Debian 5.10.162-1 (2023-01-21)"
        machine = config.get('persona', 'machine') or "x86_64"
        processor = config.get('persona', 'processor') or "x86_64"
        hardware_platform = config.get('persona', 'hardware_platform') or "x86_64"
        os_name = config.get('persona', 'os_name') or "GNU/Linux"
        
        output_parts = []
        
        args = cmd.split()[1:]
        flags = set()
        for arg in args:
            if arg.startswith('-'):
                for char in arg[1:]:
                    flags.add(char)
        
        if not flags:
            flags.add('s')
            
        if 'a' in flags:
            # -a = -snrvmo (usually)
            return f"{kernel_name} {nodename} {kernel_release} {kernel_version} {machine} {os_name}\n", {}, {'source': 'local', 'cached': False}

        # Order matters: s n r v m p i o
        out = []
        if 's' in flags: out.append(kernel_name)
        if 'n' in flags: out.append(nodename)
        if 'r' in flags: out.append(kernel_release)
        if 'v' in flags: out.append(kernel_version)
        if 'm' in flags: out.append(machine)
        if 'p' in flags: out.append(processor)
        if 'i' in flags: out.append(hardware_platform)
        if 'o' in flags: out.append(os_name)
        
        return " ".join(out) + "\n", {}, {'source': 'local', 'cached': False}

    def handle_nvidia_smi(self, cmd, context):
        output = """Wed Dec 31 19:12:44 2025       
+-----------------------------------------------------------------------------+
| NVIDIA-SMI 535.154.05   Driver Version: 535.154.05   CUDA Version: 12.2     |
|-------------------------------+----------------------+----------------------+
| GPU  Name        Persistence-M| Bus-Id        Disp.A | Volatile Uncorr. ECC |
| Fan  Temp  Perf  Pwr:Usage/Cap|         Memory-Usage | GPU-Util  Compute M. |
|                               |                      |               MIG M. |
|===============================+======================+======================|
|   0  NVIDIA H100 80G...  On   | 00000000:3B:00.0 Off |                    0 |
| N/A   32C    P0    68W / 700W |      0MiB / 81559MiB |      0%      Default |
|                               |                      |             Disabled |
+-------------------------------+----------------------+----------------------+
|   1  NVIDIA H100 80G...  On   | 00000000:D8:00.0 Off |                    0 |
| N/A   30C    P0    65W / 700W |      0MiB / 81559MiB |      0%      Default |
|                               |                      |             Disabled |
+-------------------------------+----------------------+----------------------+
                                                                               
+-----------------------------------------------------------------------------+
| Processes:                                                                  |
|  GPU   GI   CI        PID   Type   Process name                  GPU Memory |
|        ID   ID                                                   Usage      |
|=============================================================================|
|  No running processes found                                                 |
+-----------------------------------------------------------------------------+
"""
        return output, {}, {'source': 'local', 'cached': False}

    def handle_lspci(self, cmd, context):
        # Realistic lspci for a high-end server (Dual H100)
        output = """00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Cirrus Logic GD 5446
00:03.0 Ethernet controller: Red Hat, Inc. Virtio network device
00:04.0 SCSI storage controller: Red Hat, Inc. Virtio block device
3b:00.0 3D controller: NVIDIA Corporation H100 PCIe [Hopper] (rev a1)
d8:00.0 3D controller: NVIDIA Corporation H100 PCIe [Hopper] (rev a1)
"""
        return output, {}, {'source': 'local', 'cached': False}

    def handle_dmidecode(self, cmd, context):
        # Handle specific processor-version check
        if '-s processor-version' in cmd or '--string processor-version' in cmd:
            proc_ver = config.get('persona', 'processor_version') or "Intel(R) Xeon(R) Platinum 8480+"
            return f"{proc_ver}\n", {}, {'source': 'local', 'cached': False}
        return self.handle_generic(cmd, context)

    def handle_ps(self, cmd, context):
        # 1. Parse Flags
        parts = cmd.split()
        flags = set()
        for p in parts[1:]:
            if p.startswith('-'):
                for char in p[1:]:
                    flags.add(char)
            else:
                 # handle 'aux' style (no dash)
                 if 'a' in p: flags.add('a')
                 if 'u' in p: flags.add('u')
                 if 'x' in p: flags.add('x')

        # 2. Check Cache for CANONICAL process list
        # We cache the raw JSON list under a special key so all 'ps' variants share it.
        # This ensures 'ps -ef' and 'ps aux' show the same PIDs.
        session_id = context.get('session_id', 'unknown')
        CACHE_KEY = "_global_process_list"
        print(f"[Session: {session_id}] [Cache] Checking cache for '{CACHE_KEY}'")
        cached_resp = self.db.get_cached_response(CACHE_KEY, "/")
        
        j = None
        if cached_resp:
            print(f"[Session: {session_id}] [Cache] HIT for ps")
            j, _ = self._extract_json_or_text(cached_resp)
        else:
            print(f"[Session: {session_id}] [Cache] MISS for ps")

        if not j or 'processes' not in j:
            # 3. Request LLM Process List (Cache Miss)
            print(f"[Session: {session_id}] [LLM] Calling LLM API for 'ps'...")
            # We ask for 'alabaster' as the placeholder user.
            prompt = """ps -ef (INSTRUCTION: Return a valid JSON object with key 'processes'.
Example format:
{
  "processes": [
    {"user": "root", "pid": 1, "ppid": 0, "cpu": 0.0, "mem": 0.1, "start": "10:00", "time": "00:00:05", "command": "/sbin/init"},
    {"user": "alabaster", "pid": 1001, "ppid": 1, "cpu": 0.0, "mem": 0.2, "start": "10:05", "time": "00:00:01", "command": "-bash"}
  ]
}
Generate realistic processes for a web server (blogofy.com). Include system services, sshd, and user shell.)"""
            
            resp = self.llm.generate_response(
                "ps", 
                context.get('cwd'), 
                context.get('history'), 
                [], 
                context.get('known_paths', []), 
                client_ip=context.get('client_ip'), 
                honeypot_ip=context.get('honeypot_ip'),
                override_prompt=prompt
            )
            
            j, t = self._extract_json_or_text(resp)
            
            # Cache valid result
            if j and 'processes' in j:
                # We cache the raw response
                self.db.cache_response(CACHE_KEY, "/", resp)
            else:
                # Fallback to STATIC DATA to prevent loop
                print(f"[Session: {session_id}] [PS Error] JSON Parse failed. Using STATIC fallback.")
                j = {
                  "processes": [
                    {"user": "root", "pid": 1, "ppid": 0, "cpu": 0.0, "mem": 0.1, "start": "10:00", "time": "00:00:05", "command": "/sbin/init"},
                    {"user": "root", "pid": 2, "ppid": 0, "cpu": 0.0, "mem": 0.0, "start": "10:00", "time": "00:00:00", "command": "[kthreadd]"},
                    {"user": "root", "pid": 100, "ppid": 1, "cpu": 0.0, "mem": 0.2, "start": "10:01", "time": "00:00:10", "command": "/usr/sbin/rsyslogd -n"},
                    {"user": "root", "pid": 420, "ppid": 1, "cpu": 0.0, "mem": 0.5, "start": "10:01", "time": "00:01:23", "command": "/usr/sbin/sshd -D"},
                    {"user": "www-data", "pid": 800, "ppid": 1, "cpu": 0.1, "mem": 1.2, "start": "10:02", "time": "00:03:00", "command": "nginx: master process /usr/sbin/nginx"},
                    {"user": "www-data", "pid": 801, "ppid": 800, "cpu": 0.0, "mem": 0.8, "start": "10:02", "time": "00:00:05", "command": "nginx: worker process"},
                    {"user": "alabaster", "pid": 1337, "ppid": 420, "cpu": 0.1, "mem": 0.8, "start": "10:05", "time": "00:00:02", "command": "-bash"}
                  ]
                }

        processes = j['processes']
        current_user = context.get('user', 'root')
        
        # 4. Filter/Format/Substitute
        
        show_all = 'e' in flags or 'A' in flags or 'a' in flags or 'x' in flags
        # Default behavior of 'ps' (no flags) is usually just current tty processes.
        # But 'ps aux' sets 'a' and 'x'.
        
        filtered = []
        for p_orig in processes:
             # Deep copy to modify
             p = p_orig.copy()
             
             # Runtime User Substitution
             if p.get('user') == 'alabaster':
                 p['user'] = current_user
                 
             # Random Noise injection (Simplistic: skip some random high PIDs? No, consistence is better)
             # User requested "randomly add and remove". 
             # Let's simple filter logic for now.
             
             # Filter based on flags
             if show_all:
                 filtered.append(p)
             else:
                 # Only current user processes
                 if p.get('user') == current_user:
                     filtered.append(p)
        
        if not filtered: filtered = processes # Fallback
        
        # Sort by PID
        try:
             filtered.sort(key=lambda x: int(x.get('pid', 0)))
        except: pass

        lines = []
        if 'u' in flags:
            # USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
            lines.append("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND")
            for p in filtered:
                user = p.get('user', 'root')[:8].ljust(8)
                pid = str(p.get('pid')).rjust(5)
                cpu = str(p.get('cpu', '0.0')).rjust(4)
                mem = str(p.get('mem', '0.0')).rjust(4)
                vsz = "10000" 
                rss = "5000"
                tty = p.get('tty', '?').ljust(8)
                stat = "Ss"
                start = p.get('start', '00:00')
                time_ = p.get('time', '00:00:00')
                command = p.get('command', '')
                lines.append(f"{user} {pid} {cpu} {mem} {vsz} {rss} {tty} {stat} {start} {time_} {command}")
        
        elif 'f' in flags:
            # UID        PID  PPID  C STIME TTY          TIME CMD
            lines.append("UID        PID  PPID  C STIME TTY          TIME CMD")
            for p in filtered:
                uid = p.get('user', 'root') 
                pid = str(p.get('pid')).rjust(5)
                ppid = str(p.get('ppid', 0)).rjust(5)
                c = "0"
                stime = p.get('start', '00:00')
                tty = p.get('tty', '?').ljust(8)
                time_ = p.get('time', '00:00:00')
                command = p.get('command', '')
                lines.append(f"{uid.ljust(8)} {pid} {ppid} {c} {stime} {tty} {time_} {command}")
        else:
            # PID TTY          TIME CMD
            lines.append("  PID TTY          TIME CMD")
            for p in filtered:
                pid = str(p.get('pid')).rjust(5)
                tty = p.get('tty', '?').ljust(8)
                time_ = p.get('time', '00:00:00')
                command = p.get('command', '')
                lines.append(f"{pid} {tty} {time_} {command}")

        return "\n".join(lines) + "\n", {}
    
    def handle_scp_interactive(self, cmd, chan, context):
        """
        Handles 'scp -t' (sink/upload) interactively.
        Enforces Size Limits & Quotas via User Filesystem isolation.
        """
        import struct
        import os
        
        try:
            from .config_manager import config
        except ImportError:
            from config_manager import config

        MAX_FILE_SIZE = config.get('upload', 'max_file_size') or 1048576
        MAX_QUOTA = config.get('upload', 'max_quota_per_ip') or 1048576

        def log_debug(msg):
            try:
                with open('/tmp/scp_debug.log', 'a') as f:
                    f.write(f"{datetime.datetime.now()} [SCP-HANDLER] {msg}\n")
            except: pass

        log_debug(f"Entered handler. CMD: {cmd}")

        if '-t' not in cmd:
            log_debug("Not -t mode, exiting.")
            chan.send("SCP Source mode not fully implemented.\n")
            chan.send_exit_status(1)
            return

        try:
            log_debug("Sending initial ACK (x00)")
            chan.send(b'\x00')
        except Exception as e:
            log_debug(f"Failed to send initial ACK: {e}")
            return

        while True:
            command_line = b""
            while True:
                try:
                    b = chan.recv(1)
                    if not b: 
                        log_debug("Channel closed (EOF received) during command read.")
                        return 
                    if b == b'\n': break
                    command_line += b
                except Exception as e:
                    log_debug(f"Error reading command byte: {e}")
                    return
            
            cmd_str = command_line.decode('utf-8')
            log_debug(f"Received command string: {cmd_str}")
            if not cmd_str: break 
            
            cmd_char = cmd_str[0]
            
            if cmd_char == 'E': 
                log_debug("Received E (End Dir). Sending ACK.")
                chan.send(b'\x00')
                break 
                
            if cmd_char == 'T': 
                log_debug("Received T (Time). Sending ACK.")
                chan.send(b'\x00') 
                continue
                
            if cmd_char == 'C': 
                log_debug(f"Received C (File): {cmd_str}")
                try:
                    parts = cmd_str[1:].strip().split(' ', 2)
                    perm = parts[0]
                    size_str = parts[1]
                    filename = parts[2]
                    size = int(size_str)
                    
                    # 1. Check Max File Size (Header)
                    if size > MAX_FILE_SIZE:
                        log_debug(f"File too large: {size} > {MAX_FILE_SIZE}")
                        print(f"[SCP] Blocked: File size {size} > Limit {MAX_FILE_SIZE}")
                        chan.send(b'\x01File too large\n')
                        return

                    # 2. Check Quota
                    client_ip = context.get('client_ip')
                    current_usage = self.db.get_ip_upload_usage(client_ip)
                    if current_usage + size > MAX_QUOTA:
                        log_debug(f"Quota exceeded for {client_ip}")
                        print(f"[SCP] Blocked: Quota exceeded for {client_ip}")
                        chan.send(b'\x01Quota exceeded\n')
                        return

                    log_debug("Sending ACK for C command header.")
                    chan.send(b'\x00') # ACK Header
                    
                    # Read Content (Enforce Max Size during read)
                    content = b""
                    read_so_far = 0
                    log_debug(f"Reading content ({size} bytes)...")
                    while read_so_far < size:
                        # Safety break if stream exceeds expected size
                        if read_so_far > MAX_FILE_SIZE:
                             log_debug("Stream exceeded MAX_FILE_SIZE during read.")
                             chan.send(b'\x01File too large\n')
                             return
                             
                        chunk_size = min(4096, size - read_so_far)
                        chunk = chan.recv(chunk_size)
                        if not chunk: 
                            log_debug("Unexpected EOF during data read.")
                            break
                        content += chunk
                        read_so_far += len(chunk)
                    
                    log_debug("Finished reading content. Waiting for check byte.")
                    check = chan.recv(1) 
                    log_debug(f"Received check byte: {check!r}. Sending final ACK.")
                    chan.send(b'\x00') 
                    
                    # SAVE IT (Isolated)
                    cwd = context.get('cwd', '/')
                    target_arg = cmd.split('-t')[-1].strip()
                    if not target_arg or target_arg == '.': target_arg = cwd
                    
                    abs_target = self._resolve_path(cwd, target_arg)
                    
                    # Join directory logic
                    # Check global fs OR user fs for directory?
                    # For simplicity, if target ends in /, treat as dir.
                    final_path = abs_target
                    if abs_target.endswith('/'):
                         final_path = os.path.join(abs_target, filename)
                    else:
                         # Check if abs_target is an existing dir
                         node = self.db.get_fs_node(abs_target)
                         if node and node.get('type') == 'directory':
                             final_path = os.path.join(abs_target, filename)
                             
                    try:
                        text_content = content.decode('utf-8')
                        
                        # Use USER_FILESYSTEM (Private)
                        self.db.update_user_file(
                            client_ip,
                            context.get('user', 'unknown'),
                            final_path, 
                            os.path.dirname(final_path), 
                            'file', 
                            {'permissions': '-rwxr-xr-x', 'size': size, 'modified': datetime.datetime.now().strftime("%b %d %H:%M")}, 
                            text_content
                        )
                        print(f"[SCP] Uploaded {filename} to {final_path} ({size} bytes) [User Isolated]")
                    except UnicodeDecodeError:
                        print(f"[SCP] Uploaded BINARY {filename} to {final_path} (skipped text save)")
                        pass

                except Exception as e:
                    print(f"[SCP] Error parsing C command: {e}")
                    chan.send(b'\x01SCP Error\n')
                    return

            if cmd_char == '\x00':
                break

    def _extract_json_or_text(self, raw):
        if not raw: return None, ""
        
        # 1. Try standard parse (fastest)
        try:
            return json.loads(raw), ""
        except: pass
        
        # 2. Cleanup Markdown wrappers
        clean = raw.strip()
        if "```" in clean:
            # Extract content between first ```(json)? and last ```
            match = re.search(r'```(?:json)?\s*(.*?)```', clean, re.DOTALL)
            if match:
                clean = match.group(1).strip()
            else:
                 # Fallback cleanup
                 if clean.startswith("```"):
                    clean = clean.split('\n', 1)[-1]
                    if clean.endswith("```"):
                        clean = clean.rsplit('\n', 1)[0]
        
        # 3. Try parse cleaned
        try:
            return json.loads(clean), ""
        except: pass

        # 4. Aggressive Fix: Remove trailing commas in arrays/objects
        # This regex looks for , followed by closing ] or }
        clean_fixed = re.sub(r',\s*([\]}])', r'\1', clean)
        try:
            return json.loads(clean_fixed), ""
        except: pass
        
        # 5. Last Resort: Regex Extraction of the 'output' field
        # We try to grab the content of "output": "..."
        # This handles cases where other fields (like generated_files) are malformed
        try:
            # Look for "output": "..." ignoring escaped quotes
            # We use a non-greedy match that respects escaped quotes
            # Handle both "output" and 'output' keys, and "val" and 'val' values
            # Capture Group 1: Quote char (' or ")
            # Capture Group 2: Content
            out_match = re.search(r'[\'"]output[\'"]\s*:\s*([\'"])(.*?)(?<!\\)\1', clean, re.DOTALL)
            if out_match:
                quote_char = out_match.group(1)
                content = out_match.group(2)
                
                if quote_char == "'":
                    # Manual unescape for single quotes to avoid ast/eval
                    # Replace escaped single quote with single quote
                    content = content.replace(r"\'", "'")
                
                # Reconstruct valid JSON safely using json.dumps
                # This handles escaping newlines, quotes, etc. required for the value
                pseudo_json = '{ "output": ' + json.dumps(content) + ' }'
                return json.loads(pseudo_json), ""
        except: pass
        
        return None, raw

    def handle_base64(self, cmd, context):
        import base64
        parts = cmd.split()
        
        # Simple parsing
        # base64 [file] OR base64 -d [file]
        decode = '-d' in parts or '--decode' in parts
        
        target = None
        for p in parts[1:]:
            if not p.startswith('-'):
                target = p
                break
                
        content = ""
        source = 'local'
        if target:
            # Read file
            content, source = self._generate_or_get_content("base64", target, context)
        else:
            return "base64: missing file operand\n", {}, {'source': 'local', 'cached': False}
            
        try:
            if decode:
                encoded = base64.b64decode(content.strip()).decode('utf-8', errors='replace')
                return f"{encoded}", {}, {'source': source, 'cached': source == 'local'}
            else:
                encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
                # Wrap at 76 chars
                wrapped = "\n".join(encoded[i:i+76] for i in range(0, len(encoded), 76))
                return f"{wrapped}\n", {}, {'source': source, 'cached': source == 'local'}
        except Exception as e:
            return f"base64: invalid input\n", {}, {'source': source, 'cached': source == 'local'}



    def handle_su(self, cmd, context):
        # Always fail authentication
        # Simulate delay
        time.sleep(1.5) 
        return "su: Authentication failure\n", {}, {'source': 'local', 'cached': False}
        
    def handle_perl(self, cmd, context):
        return self._handle_interpreter(cmd, context, "perl")

    def handle_awk(self, cmd, context):
        import shlex
        import hashlib
        
        # AWK is complex. We want to simulate execution on a file.
        # Try to identify input file.
        try:
            parts = shlex.split(cmd)
        except:
            return "awk: syntax error\n", {}
            
        if len(parts) < 2: return "awk: usage error\n", {}
        
        # Heuristic: Find last argument that doesn't start with '-' and isn't the program string (if quoted)
        # Simplified: If -f is used, next arg is script.
        # If no -f, first non-flag arg is program. Next args are files.
        
        files = []
        args = parts[1:]
        skip_next = False
        program_found = False
        
        for i, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            
            if arg.startswith('-f'):
                if arg == '-f': skip_next = True 
                continue
                
            if arg.startswith('-F'): 
                if len(arg) == 2: skip_next = True
                continue
            
            if arg.startswith('-v'): 
                if len(arg) == 2: skip_next = True
                continue
                
            if arg.startswith('-'): 
                continue
            
            # Non-flag
            if not program_found and '-f' not in cmd: 
                 program_found = True
                 continue
            
            files.append(arg)
            
        if not files:
             return self.handle_generic(cmd, context)

        target_path = files[0]
        content, source = self._generate_or_get_content("awk_data", target_path, context)
        
        content_hash = hashlib.md5(content.encode('utf-8', 'ignore')).hexdigest()
        cache_key = f"{cmd}::data_hash={content_hash}"
        
        print(f"[AWK] Executing with data file: {target_path}")
        
        cached = self.db.get_cached_response(cache_key, context.get('cwd'))
        if cached:
             # reuse
             j, t = self._extract_json_or_text(cached)
             r, u = self._process_llm_json(j, t)
             return r, u, {'source': 'cache', 'cached': True}
             
        # LLM
        prompt = f"Command: {cmd}\n\nInput File ({target_path}) Content:\n```\n{content[:5000]}\n```\n\n(INSTRUCTION: Execute the awk command on the provided file content. Return ONLY stdout.)"
        
        resp = self.llm.generate_response(prompt, context.get('cwd'), context.get('history', []), [], [])
        
        self.db.cache_response(cache_key, context.get('cwd'), resp)
        j, t = self._extract_json_or_text(resp)
        r, u = self._process_llm_json(j, t)
        return r, u, {'source': 'llm', 'cached': False}


    def handle_chmod(self, cmd, context):
        parts = cmd.split()
        if len(parts) < 3: return "chmod: missing operand\n", {}
        
        mode = parts[1]
        target = parts[2]
        
        # recursive? -R
        # ignore flags for now, assume Mode Target
        if mode.startswith('-'):
             # handle flags like chmod -R 777 file
             if len(parts) > 3:
                 mode = parts[2]
                 target = parts[3]
        
        abs_path = self._resolve_path(context.get('cwd'), target)
        client_ip = context.get('client_ip')
        user = context.get('user')
        
        curr = self.db.get_user_node(client_ip, user, abs_path)
        if not curr:
            return f"chmod: cannot access '{target}': No such file or directory\n", {}
             
        # Update permissions in metadata
        try:
            meta = json.loads(curr.get('metadata', '{}'))
        except:
            meta = {}
            
        # Parse mode (octal only for simplicity)
        # If +x, etc, we just fake it
        if '+' in mode or '-' in mode and not mode.startswith('-'):
             # numeric conversion? simple: just set it to strings
             current_perms = meta.get('permissions', 'rw-r--r--')
             # Logic to update drwx... is complex.
             # We just assume success and maybe update string if it looks like octal
             pass
        else:
             # Assume octal, just store it? Or convert to rwx?
             # For 'ls' to show it, we need rwx string.
             # quick hack: 777 -> rwxrwxrwx
             pass
             
        # For now, just logging change for simulation, effectively "success"
        # We don't strictly enforce permissions in honeypot logic anyway
        return "", {'file_modifications': [abs_path]}
