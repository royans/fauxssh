import hashlib
import json
import time
from ssh_honeypot.core.utils import random_response_delay

class RedisHandler:
    def __init__(self, db, llm):
        self.db = db
        self.llm = llm

    def _encode_bulk_string(self, text):
        if text is None:
            return b"$-1\r\n"
        data = text.encode('utf-8')
        return f"${len(data)}\r\n".encode('utf-8') + data + b"\r\n"

    def _encode_simple_string(self, text):
        return f"+{text}\r\n".encode('utf-8')

    def _encode_error(self, text):
        return f"-{text}\r\n".encode('utf-8')

    def _encode_integer(self, val):
        return f":{val}\r\n".encode('utf-8')

    def handle_command(self, command, client_ip):
        """
        Input: Plain text command string (e.g. "GET key")
        Output: Bytes (RESP formatted response)
        """
        parts = command.split()
        if not parts:
            return b""
        
        cmd_upper = parts[0].upper()
        args = parts[1:]

        # 1. Local Handlers
        handler_name = f"handle_{cmd_upper}"
        if hasattr(self, handler_name):
            return getattr(self, handler_name)(args)

        # 2. Cache Check (LLM Fallback)
        # Use MD5 of command as cache key
        cmd_hash = hashlib.md5(command.encode('utf-8')).hexdigest()
        cached = self.db.get_cached_response(cmd_hash)
        if cached:
            # We assume cached content is the "text" content, we need to wrap it?
            # Or did we cache the raw RESP? 
            # Storing raw bytes in DB TEXT field is risky. 
            # Let's assume we store the "result text" and default to Bulk String wrapping.
            # UNLESS we explicitly store metadata about type.
            # For now: We store text, and wrap as Bulk String.
            return self._encode_bulk_string(cached)

        # 3. LLM Fallback
        return self.llm_fallback(command, client_ip, cmd_hash)

    # --- Local Handlers ---

    def handle_PING(self, args):
        if args:
             return self._encode_bulk_string(args[0])
        return self._encode_simple_string("PONG")

    def handle_ECHO(self, args):
        if args:
            return self._encode_bulk_string(" ".join(args))
        return self._encode_error("ERR wrong number of arguments for 'echo' command")

    def handle_SELECT(self, args):
        return self._encode_simple_string("OK")

    def handle_QUIT(self, args):
        return self._encode_simple_string("OK")

    def handle_INFO(self, args):
        # Realistic Fake Info
        info = """# Server
redis_version:6.2.6
os:Linux 5.4.0-104-generic x86_64
arch_bits:64
multiplexing_api:epoll
process_id:1
run_id:891289129812981928912
tcp_port:6379
uptime_in_seconds:129319
uptime_in_days:1
hz:10
configured_hz:10
lru_clock:12931293
executable:/usr/local/bin/redis-server

# Clients
connected_clients:12
client_recent_max_input_buffer:2
client_recent_max_output_buffer:0
blocked_clients:0

# Memory
used_memory:104857600
used_memory_human:100.00M
used_memory_rss:120586240
used_memory_rss_human:115.00M
used_memory_peak:104857600
used_memory_peak_human:100.00M
used_memory_lua:37888
used_memory_lua_human:37.00K
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
mem_fragmentation_ratio:1.15
mem_allocator:jemalloc-5.1.0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1678123123
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:0
rdb_current_bgsave_time_sec:-1
rdb_last_cow_size:0
aof_enabled:0

# Stats
total_connections_received:12401
total_commands_processed:591230
instantaneous_ops_per_sec:12
total_net_input_bytes:12939123
total_net_output_bytes:9123912
instantaneous_input_kbps:0.12
instantaneous_output_kbps:0.05
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
expired_stale_perc:0.00
expired_time_cap_reached_count:0
evicted_keys:0
keyspace_hits:123
keyspace_misses:5

# Replication
role:master
connected_slaves:0
master_replid:8127391827398127398127398127398127398127
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:123.12
used_cpu_user:45.12
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Keyspace
db0:keys=52,expires=0,avg_ttl=0
"""
        return self._encode_bulk_string(info)

    def handle_CLIENT(self, args):
        if args and args[0].upper() == 'LIST':
             # Fake client list
             res = "id=12 addr=127.0.0.1:54321 fd=8 name= age=123 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=26 qbuf-free=32742 obl=0 oll=0 omem=0 events=r cmd=client\n"
             return self._encode_bulk_string(res)
        return self._encode_simple_string("OK")
    
    def handle_CONFIG(self, args):
        # Simplified config get support
        return self._encode_bulk_string("dir /var/lib/redis\ndbfilename dump.rdb\n")

    # --- LLM Fallback ---

    def llm_fallback(self, command, client_ip, cmd_hash):
        try:
             prompt = f"""You are a Redis Data Store.
             The user sent the command: {command}
             
             Act as a real Redis server. 
             IF the command is valid (GET, SET, KEY, etc):
             - Return the OUTPUT CONTENT only (not the protocol formatting). 
             - If it is a GET for a key that doesn't exist, return nothing (empty string).
             - If it is a SET, return "OK".
             
             IF the command is invalid or unknown:
             - Return "ERR unknown command"
             
             Examples:
             Cmd: GET foo -> Response: (empty)
             Cmd: SET foo bar -> Response: OK
             Cmd: GET foo -> Response: bar
             """
             
             # Call LLM
             resp = self.llm.generate_response(
                 command, 
                 "/", 
                 [], # History? Redis is stateless mostly for this context
                 [], 
                 [],
                 client_ip=client_ip, 
                 override_prompt=prompt
             )
             
             text_resp = resp.strip()
             
             # Heuristic Response Encoding
             if text_resp == "OK":
                 self.db.cache_response(cmd_hash, "OK")
                 return self._encode_simple_string("OK")
             elif text_resp.startswith("ERR"):
                 self.db.cache_response(cmd_hash, text_resp)
                 return self._encode_error(text_resp)
             elif not text_resp:
                 self.db.cache_response(cmd_hash, "") # Store empty for cache hits
                 return self._encode_bulk_string(None) # Redis NIL
             else:
                 # Default: Bulk String content
                 self.db.cache_response(cmd_hash, text_resp)
                 return self._encode_bulk_string(text_resp)

        except Exception as e:
            return self._encode_error(f"ERR internal error: {e}")
