from .db_interface import DatabaseBackend
from .logging_setup import log
import json
import time
import datetime
import hashlib
import os

try:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import Json
except ImportError:
    log.warning("psycopg2 not installed. PostgresBackend will fail.")


class PooledConnectionWrapper:
    """
    Wraps a psycopg2 connection to intercept .close() calls and return
    the connection to the pool instead of closing the TCP socket.
    """

    def __init__(self, pool, conn):
        self._pool = pool
        self._conn = conn

    def close(self):
        if self._conn:
            try:
                self._pool.putconn(self._conn)
            except Exception as e:
                log.error(f"[PostgresPool] Error returning connection to pool: {e}")
            finally:
                self._conn = None

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def cursor(self, *args, **kwargs):
        return self._conn.cursor(*args, **kwargs)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()


class PostgresBackend(DatabaseBackend):
    def __init__(self, config=None):
        self.config = config or {}
        self.conn_params = {
            "host": self.config.get("host", "localhost"),
            "port": self.config.get("port", 5432),
            "user": self.config.get("user", "honeypot"),
            "password": self.config.get("password", ""),
            "dbname": self.config.get("dbname", "logs"),
        }
        self.placeholder = "%s"
        self.skeleton_cache = []
        self._pool = None
        self._init_pool()
        self._load_skeleton()
        self._init_db()

    def _init_pool(self):
        try:
            log.info("[Postgres] Initializing Connection Pool (min=1, max=20)...")
            self._pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1, maxconn=20, **self.conn_params
            )
        except Exception as e:
            log.error(f"[Postgres] Failed to initialize connection pool: {e}")
            raise e

    def get_connection_info(self):
        host = self.conn_params.get("host", "unknown")
        dbname = self.conn_params.get("dbname", "unknown")
        pool_status = "Active" if self._pool else "Inactive"
        return f"PostgreSQL Backend (Host: {host}, DB: {dbname}, Pool: {pool_status})"

    def _load_skeleton(self):
        try:
            from ssh_honeypot.core.fs_seeder import get_skeleton_data

            self.skeleton_cache = get_skeleton_data()
            log.info(
                f"[*] Loaded {len(self.skeleton_cache)} skeleton items (COW Layer)"
            )
        except ImportError:
            # Fallback for direct testing
            try:
                from fs_seeder import get_skeleton_data

                self.skeleton_cache = get_skeleton_data()
            except:
                log.warning("[!] Failed to load skeleton data")

    def _get_conn(self):
        try:
            conn = self._pool.getconn()
            if conn:
                return PooledConnectionWrapper(self._pool, conn)
            else:
                raise Exception("Connection pool exhausted")
        except Exception as e:
            log.error(f"[Postgres] Error getting connection from pool: {e}")
            raise e

    def __del__(self):
        if hasattr(self, "_pool") and self._pool:
            try:
                self._pool.closeall()
                # log.info("[Postgres] Connection Pool closed.")
            except:
                pass

    def get_max_interaction_id(self):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) FROM interactions")
            row = cursor.fetchone()
            return row[0] if row and row[0] else 0
        except Exception as e:
            log.error(f"[Postgres] Error getting max interaction ID: {e}")
            return 0
        finally:
            conn.close()

    def _init_db(self):
        """
        Initialize the database schema.
        """
        log.info("[Postgres] Initializing Database Schema...")
        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            # Sessions
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id SERIAL PRIMARY KEY,
                    session_id TEXT UNIQUE,
                    remote_ip TEXT,
                    username TEXT,
                    password TEXT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    client_version TEXT,
                    protocol TEXT DEFAULT 'ssh',
                    summary TEXT,
                    risk_score INTEGER,
                    fingerprint TEXT
                )
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(remote_ip)"
            )

            # Interactions
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS interactions (
                    id SERIAL PRIMARY KEY,
                    session_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    cwd TEXT,
                    command TEXT,
                    response TEXT,
                    source TEXT,
                    request_md5 TEXT,
                    response_md5 TEXT,
                    response_head TEXT,
                    response_size INTEGER,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_interactions_ts ON interactions(timestamp)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_interactions_md5 ON interactions(request_md5)"
            )

            # Auth Events
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_events (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    client_ip TEXT,
                    username TEXT,
                    auth_method TEXT,
                    auth_data TEXT,
                    success BOOLEAN,
                    client_version TEXT,
                    fingerprint TEXT,
                    protocol TEXT DEFAULT 'ssh'
                )
            """
            )

            # Global Filesystem
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS global_filesystem (
                    path TEXT PRIMARY KEY,
                    parent_path TEXT,
                    type TEXT,
                    metadata TEXT,
                    content TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_parent ON global_filesystem(parent_path)"
            )

            # User Filesystem
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS user_filesystem (
                    ip TEXT,
                    username TEXT,
                    path TEXT,
                    parent_path TEXT,
                    type TEXT,
                    metadata TEXT,
                    content TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_accessed TIMESTAMP,
                    is_deleted INTEGER DEFAULT 0,
                    PRIMARY KEY (ip, username, path)
                )
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_parent ON user_filesystem(ip, username, parent_path)"
            )

            # Command Cache
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS command_cache (
                    id SERIAL PRIMARY KEY,
                    cmd_hash TEXT UNIQUE,
                    command TEXT,
                    cwd TEXT,
                    response TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Session Summaries Cache
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS session_summaries_cache (
                    chain_hash TEXT PRIMARY KEY,
                    summary TEXT,
                    risk_score INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # IP Intelligence
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_intelligence (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT,
                    city TEXT,
                    country TEXT,
                    isp TEXT,
                    org TEXT,
                    asn TEXT,
                    network_type TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    enriched INTEGER DEFAULT 0,
                    raw_data TEXT,
                    abuse_tags TEXT DEFAULT '[]'
                )
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_ip_intel_enriched ON ip_intelligence(enriched, last_seen)"
            )

            # Malicious Payloads
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS malicious_payloads (
                    id SERIAL PRIMARY KEY,
                    url TEXT,
                    url_hash TEXT UNIQUE,
                    session_id TEXT,
                    ip TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'pending',
                    payload_md5 TEXT,
                    payload_size INTEGER,
                    file_path TEXT,
                    retry_count INTEGER DEFAULT 0,
                    error_message TEXT,
                    virustotal_result TEXT,
                    vt_last_scanned TIMESTAMP,
                    vt_scan_id TEXT
                )
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_payload_status ON malicious_payloads(status)"
            )

            # LLM Usage
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_usage (
                    id SERIAL PRIMARY KEY,
                    ip TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source TEXT DEFAULT 'http'
                )
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_llm_usage_ip_time ON llm_usage(ip, timestamp)"
            )

            # LLM Response Cache (Jan 19)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_response_cache (
                    prompt_hash TEXT PRIMARY KEY,
                    prompt_text TEXT,
                    response TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # LLM Response Cache (Jan 19)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_response_cache (
                    prompt_hash TEXT PRIMARY KEY,
                    prompt_text TEXT,
                    response TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Payload Requests (Many-to-One Tracker)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS payload_requests (
                    id SERIAL PRIMARY KEY,
                    payload_id INTEGER,
                    ip TEXT,
                    session_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(payload_id) REFERENCES malicious_payloads(id)
                )
            """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_payload_req_pid ON payload_requests(payload_id)"
            )

            # Requested URLs
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS requested_urls (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    url TEXT,
                    method TEXT,
                    user_agent TEXT,
                    command_text TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """
            )

            # Command Analysis
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS command_analysis (
                    command_hash TEXT PRIMARY KEY,
                    command_text TEXT,
                    activity_type TEXT,
                    stage TEXT,
                    risk_score INTEGER,
                    explanation TEXT,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Failed to init DB: {e}")
            conn.rollback()
        finally:
            conn.close()

    # ----------------------------------------------------------------
    # Implementation
    # ----------------------------------------------------------------

    def start_session(
        self,
        session_id,
        ip,
        username,
        password,
        client_version,
        fingerprint=None,
        protocol="ssh",
        start_time=None,
    ):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            fp_json = "{}"
            if fingerprint:
                fp_json = json.dumps(fingerprint)

            if start_time:
                cursor.execute(
                    """
                    INSERT INTO sessions (session_id, remote_ip, username, password, client_version, fingerprint, protocol, start_time)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (session_id) DO NOTHING
                """,
                    (
                        session_id,
                        ip,
                        username,
                        password,
                        client_version,
                        fp_json,
                        protocol,
                        start_time,
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO sessions (session_id, remote_ip, username, password, client_version, fingerprint, protocol)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (session_id) DO NOTHING
                """,
                    (
                        session_id,
                        ip,
                        username,
                        password,
                        client_version,
                        fp_json,
                        protocol,
                    ),
                )
            conn.commit()

            # Log IP Visit for Intelligence
            self.log_ip_visit(ip)

        except Exception as e:
            log.error(f"[Postgres] Error start_session (Protocol: {protocol}): {e}")
        finally:
            conn.close()

    def end_session(self, session_id):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # Check if we should log empty sessions
            log_empty = (
                str(os.getenv("FAUXSSH_LOG_EMPTY_SESSIONS", "false")).lower() == "true"
            )

            if not log_empty:
                # Check interaction count
                cursor.execute(
                    "SELECT COUNT(*) FROM interactions WHERE session_id = %s",
                    (session_id,),
                )
                count = cursor.fetchone()[0]

                if count == 0:
                    # Delete session entirely
                    cursor.execute(
                        "DELETE FROM sessions WHERE session_id = %s", (session_id,)
                    )
                    log.debug(
                        f"[Postgres] Deleted empty session {session_id} (No interactions)"
                    )
                    conn.commit()
                    return

            cursor.execute(
                "UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE session_id = %s",
                (session_id,),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error end_session: {e}")
        finally:
            conn.close()

    def log_interaction(
        self,
        session_id,
        cwd,
        command,
        response,
        source="unknown",
        was_cached=False,
        duration_ms=0,
        request_md5=None,
        response_md5=None,
        response_head=None,
        response_size=None,
    ):
        if not request_md5 and command:
            import hashlib

            request_md5 = hashlib.md5(command.encode("utf-8")).hexdigest()

        # Defensive Type Casting
        try:
            if isinstance(source, (dict, list)):
                source = (
                    str(source.get("source", str(source)))
                    if isinstance(source, dict)
                    else str(source)
                )
            else:
                source = str(source)

            if request_md5 and isinstance(request_md5, (dict, list)):
                request_md5 = str(request_md5)
        except Exception:
            source = "error_casting"

        # Auto-calculate Size/Head if missing
        if response is not None:
            if response_size is None:
                try:
                    response_size = len(response)
                except:
                    pass

            if response_head is None:
                try:
                    response_head = str(response)[:100]
                except:
                    pass

        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO interactions 
                (session_id, cwd, command, response, source, request_md5, response_md5, response_head, response_size) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    session_id,
                    cwd,
                    command,
                    response,
                    source,
                    request_md5,
                    response_md5,
                    response_head,
                    response_size,
                ),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error logging interaction: {e}")
        finally:
            conn.close()

        # Unified Logging Consolidation
        try:
            from .event_logger import EventLogger

            EventLogger().log_interaction(
                session_id=session_id,
                ip="unknown",  # We don't have IP here easily without a lookup, leaving for now as per SQLite impl
                input_cmd=command,
                output_content=response,
                protocol="ssh",
                analysis={"cached": was_cached, "response_time_ms": duration_ms},
            )
        except Exception:
            pass

        # Payload Pipeline Hook (Restored)
        try:
            from .payload_manager import PayloadManager

            if command and (
                "http" in command or "wget" in command or "curl" in command
            ):
                pm = PayloadManager(self)
                urls = pm.extract_urls(command)

                if urls:
                    # Fetch IP for session
                    conn = self._get_conn()
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT remote_ip FROM sessions WHERE session_id = %s",
                        (session_id,),
                    )
                    row = cursor.fetchone()
                    conn.close()

                    remote_ip = row[0] if row else "unknown"

                    for url in urls:
                        pm.queue_payload(url, session_id, remote_ip)

        except Exception as e:
            log.error(f"[Postgres] Error in Payload Pipeline: {e}")

    def get_cached_response(self, command, cwd):
        h = hashlib.sha256(f"{cwd}:{command}".encode()).hexdigest()
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT response FROM command_cache WHERE cmd_hash = %s", (h,)
            )
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def cache_response(self, command, cwd, response):
        h = hashlib.sha256(f"{cwd}:{command}".encode()).hexdigest()
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO command_cache (cmd_hash, command, cwd, response) 
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (cmd_hash) DO UPDATE SET response = EXCLUDED.response
                """,
                (h, command, cwd, response),
            )
            conn.commit()
        finally:
            conn.close()

    def get_fs_node(self, path):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM global_filesystem WHERE path = %s", (path,))
            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None
        finally:
            conn.close()

    def list_fs_dir(self, parent_path):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM global_filesystem WHERE parent_path = %s", (parent_path,)
            )
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, r)) for r in rows]
        finally:
            conn.close()

    def update_fs_node(self, path, parent_path, type, metadata, content=None):
        conn = self._get_conn()
        if isinstance(content, (dict, list)):
            content = str(content)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO global_filesystem (path, parent_path, type, metadata, content)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (path) DO UPDATE SET
                    parent_path = EXCLUDED.parent_path,
                    type = EXCLUDED.type,
                    metadata = EXCLUDED.metadata,
                    content = EXCLUDED.content
            """,
                (
                    path,
                    parent_path,
                    type,
                    json.dumps(metadata) if isinstance(metadata, dict) else metadata,
                    content,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def log_url_request(
        self, session_id, url, method="GET", user_agent=None, command_text=None
    ):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO requested_urls (session_id, url, method, user_agent, command_text)
                VALUES (%s, %s, %s, %s, %s)
            """,
                (session_id, url, method, user_agent, command_text),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error logging URL request: {e}")
        finally:
            conn.close()

    def log_auth_event(
        self,
        client_ip,
        username,
        auth_method,
        auth_data,
        success,
        client_version,
        fingerprint=None,
        protocol="ssh",
    ):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            fp_json = "{}"
            if fingerprint:
                fp_json = json.dumps(fingerprint)

            cursor.execute(
                """
                INSERT INTO auth_events (client_ip, username, auth_method, auth_data, success, client_version, fingerprint, protocol)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    client_ip,
                    username,
                    auth_method,
                    auth_data,
                    success,
                    client_version,
                    fp_json,
                    protocol,
                ),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error log_auth_event: {e}")
        finally:
            conn.close()

    def save_command_analysis(
        self, command_hash, command_text, activity_type, stage, risk_score, explanation
    ):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO command_analysis 
                (command_hash, command_text, activity_type, stage, risk_score, explanation)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (command_hash) DO UPDATE SET
                    activity_type = EXCLUDED.activity_type,
                    stage = EXCLUDED.stage,
                    risk_score = EXCLUDED.risk_score,
                    explanation = EXCLUDED.explanation
            """,
                (
                    command_hash,
                    command_text,
                    activity_type,
                    stage,
                    risk_score,
                    explanation,
                ),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error saving command analysis: {e}")
        finally:
            conn.close()

    def update_user_file(
        self, ip, username, path, parent_path, type, metadata, content=None
    ):
        conn = self._get_conn()

        # Guard: Prevent overwriting known directories with files
        if type == "file" and self.is_managed_directory(ip, username, path):
            # Logic mirrored from SQLiteBackend
            is_known_dir = False
            home_dir = "/root" if username == "root" else f"/home/{username}"
            for item in self.skeleton_cache:
                skel_path = item["path"]
                if skel_path.startswith("~"):
                    skel_path = skel_path.replace("~", home_dir, 1)
                if skel_path == path and item["type"] == "directory":
                    is_known_dir = True
                    break

            if is_known_dir:
                log.warning(
                    f"[FS Guard] Prevented overwriting directory '{path}' with file content"
                )
                conn.close()
                return

        if isinstance(content, (dict, list)):
            content = str(content)

        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO user_filesystem (ip, username, path, parent_path, type, metadata, content, is_deleted)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 0)
                ON CONFLICT (ip, username, path) DO UPDATE SET
                    parent_path = EXCLUDED.parent_path,
                    type = EXCLUDED.type,
                    metadata = EXCLUDED.metadata,
                    content = EXCLUDED.content,
                    is_deleted = 0
            """,
                (
                    ip,
                    username,
                    path,
                    parent_path,
                    type,
                    json.dumps(metadata) if isinstance(metadata, dict) else metadata,
                    content,
                ),
            )
            conn.commit()

            # Recursive directory creation (simplified)
            # In SQLiteBackend this calls _ensure_parent_dirs, omitting here for brevity
            # as it wasn't strictly required for core function but good to have.
            # Assuming parent directories exist or created by client logic.

        finally:
            conn.close()

    def record_llm_usage(self, ip, source="http"):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO llm_usage (ip, source) VALUES (%s, %s)", (ip, source)
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error recording LLM usage: {e}")
        finally:
            conn.close()

    def check_llm_rate_limit(self, ip, rpm_limit, rph_limit, rpd_limit):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            # RPM
            cursor.execute(
                "SELECT COUNT(*) FROM llm_usage WHERE ip = %s AND timestamp > NOW() - INTERVAL '60 seconds'",
                (ip,),
            )
            rpm_count = cursor.fetchone()[0]
            if rpm_count >= rpm_limit:
                return False, f"RPM Limit Exceeded ({rpm_count}/{rpm_limit})"

            # RPH
            cursor.execute(
                "SELECT COUNT(*) FROM llm_usage WHERE ip = %s AND timestamp > NOW() - INTERVAL '1 hour'",
                (ip,),
            )
            rph_count = cursor.fetchone()[0]
            if rph_count >= rph_limit:
                return False, f"RPH Limit Exceeded ({rph_count}/{rph_limit})"

            # RPD
            cursor.execute(
                "SELECT COUNT(*) FROM llm_usage WHERE ip = %s AND timestamp > NOW() - INTERVAL '24 hours'",
                (ip,),
            )
            rpd_count = cursor.fetchone()[0]
            if rpd_count >= rpd_limit:
                return False, f"RPD Limit Exceeded ({rpd_count}/{rpd_limit})"

            return True, "OK"
        except Exception as e:
            log.error(f"[Postgres] Error checking LLM limits: {e}")
            return True, "Error check failed (Fail Open)"
        finally:
            conn.close()

    def get_user_node(self, ip, username, path):
        # 1. Check User DB
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM user_filesystem WHERE ip = %s AND username = %s AND path = %s",
                (ip, username, path),
            )
            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                result = dict(zip(columns, row))
                if result.get("is_deleted"):
                    return None

                self.touch_user_file(ip, username, path)
                return result
        finally:
            conn.close()

        # 2. Check Skeleton (COW Layer)
        home_dir = "/root" if username == "root" else f"/home/{username}"
        for item in self.skeleton_cache:
            skel_path = item["path"]
            if skel_path.startswith("~"):
                resolved_path = skel_path.replace("~", home_dir, 1)
            else:
                resolved_path = skel_path

            if resolved_path == path:
                meta = item.get("metadata", {}).copy()
                if "owner" not in meta:
                    meta["owner"] = username
                if "group" not in meta:
                    meta["group"] = username

                return {
                    "ip": ip,
                    "username": username,
                    "path": resolved_path,
                    "type": item["type"],
                    "metadata": json.dumps(meta),
                    "content": item.get("content"),
                    "created_at": datetime.datetime.now().isoformat(),
                }

        # 3. Check Global DB
        return self.get_fs_node(path)

    def list_user_dir(self, ip, username, parent_path):
        items_map = {}

        # 1. Global
        g_items = self.list_fs_dir(parent_path)
        for item in g_items:
            items_map[item["path"]] = item
            items_map[item["path"]]["source_layer"] = "global"

        # 2. Skeleton
        home_dir = "/root" if username == "root" else f"/home/{username}"
        check_parent = parent_path.rstrip("/")
        if not check_parent:
            check_parent = "/"

        for item in self.skeleton_cache:
            skel_path = item["path"]
            if skel_path.startswith("~"):
                resolved_path = skel_path.replace("~", home_dir, 1)
            else:
                resolved_path = skel_path

            if os.path.dirname(resolved_path) == check_parent:
                meta = item.get("metadata", {}).copy()
                if "owner" not in meta:
                    meta["owner"] = username
                if "group" not in meta:
                    meta["group"] = username

                items_map[resolved_path] = {
                    "ip": ip,
                    "username": username,
                    "path": resolved_path,
                    "type": item["type"],
                    "metadata": json.dumps(meta),
                    "content": item.get("content"),
                    "created_at": datetime.datetime.now().isoformat(),
                    "source_layer": "skeleton",
                }

        # 3. User
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM user_filesystem WHERE ip = %s AND username = %s AND parent_path = %s",
                (ip, username, check_parent),
            )
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            for r in rows:
                u_item = dict(zip(columns, r))
                path = u_item["path"]
                if u_item.get("is_deleted"):
                    if path in items_map:
                        del items_map[path]
                else:
                    u_item["source_layer"] = "user"
                    items_map[path] = u_item
        finally:
            conn.close()

        return list(items_map.values())

    def is_managed_directory(self, ip, username, path):
        # 1. Check User Home
        home_dir = "/root" if username == "root" else f"/home/{username}"
        if path == home_dir or path.startswith(home_dir + "/"):
            return True

        # 2. Check User DB
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM user_filesystem WHERE ip=%s AND username=%s AND path=%s AND type='directory' AND is_deleted=0",
                (ip, username, path),
            )
            if cursor.fetchone():
                return True
            cursor.execute(
                "SELECT 1 FROM user_filesystem WHERE ip=%s AND username=%s AND parent_path=%s AND is_deleted=0",
                (ip, username, path),
            )
            if cursor.fetchone():
                return True
        finally:
            conn.close()

        # 3. Check Skeleton
        for item in self.skeleton_cache:
            skel_path = item["path"]
            if skel_path.startswith("~"):
                skel_path = skel_path.replace("~", home_dir, 1)
            if skel_path == path and item["type"] == "directory":
                return True
            if os.path.dirname(skel_path) == path:
                return True

        return False

    def get_ip_upload_usage(self, ip):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT metadata FROM user_filesystem WHERE ip = %s AND is_deleted = 0",
                (ip,),
            )
            rows = cursor.fetchall()
            total_size = 0
            for r in rows:
                try:
                    meta = json.loads(r[0]) if isinstance(r[0], str) else (r[0] or {})
                    total_size += int(meta.get("size", 0))
                except:
                    pass
            return total_size
        finally:
            conn.close()

    def cleanup_http_cache(self, web_root="/var/www/html"):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM command_cache WHERE command LIKE 'wget%%' OR command LIKE 'curl%%'"
            )
            conn.commit()
            log.info(f"[Postgres] HTTP Cache cleared for {web_root}")
        except Exception as e:
            log.error(f"[Postgres] Error clearing HTTP cache: {e}")
        finally:
            conn.close()

    def prune_uploads(self, days=30):
        # Postgres syntax for interval
        cutoff_time = datetime.datetime.now() - datetime.timedelta(days=days)
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # COALESCE equivalent
            cursor.execute(
                "DELETE FROM user_filesystem WHERE COALESCE(last_accessed, created_at) < %s AND is_deleted = 0 RETURNING ip, username, path",
                (cutoff_time,),
            )
            rows = cursor.fetchall()
            conn.commit()
            return [{"ip": r[0], "username": r[1], "path": r[2]} for r in rows]
        except Exception:
            return []
        finally:
            conn.close()

    def touch_user_file(self, ip, username, path):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE user_filesystem SET last_accessed = CURRENT_TIMESTAMP WHERE ip=%s AND username=%s AND path=%s",
                (ip, username, path),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Failed to touch user file: {e}")
        finally:
            conn.close()

    def delete_user_file(self, ip, username, path):
        conn = self._get_conn()
        try:
            parent_path = os.path.dirname(path)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO user_filesystem (ip, username, path, parent_path, type, metadata, content, is_deleted)
                VALUES (%s, %s, %s, %s, 'tombstone', '{}', NULL, 1)
                ON CONFLICT (ip, username, path) DO UPDATE SET is_deleted = 1
                """,
                (ip, username, path, parent_path),
            )
            conn.commit()
        finally:
            conn.close()

    def log_ip_visit(self, ip):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO ip_intelligence (ip, first_seen, last_seen, enriched)
                VALUES (%s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0)
                ON CONFLICT(ip) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
            """,
                (ip,),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error logging IP visit: {e}")
        finally:
            conn.close()

    def get_unenriched_ips(self, limit=10):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ip FROM ip_intelligence WHERE enriched = 0 ORDER BY last_seen DESC LIMIT %s",
                (limit,),
            )
            return [row[0] for row in cursor.fetchall()]
        finally:
            conn.close()

    def save_ip_intelligence(self, ip, intel_data):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE ip_intelligence 
                SET hostname=%s, city=%s, country=%s, isp=%s, org=%s, asn=%s, network_type=%s, raw_data=%s, enriched=1
                WHERE ip=%s
            """,
                (
                    intel_data.get("hostname"),
                    intel_data.get("city"),
                    intel_data.get("country"),
                    intel_data.get("isp"),
                    intel_data.get("org"),
                    intel_data.get("asn"),
                    intel_data.get("network_type"),
                    json.dumps(intel_data.get("raw_data", {})),
                    ip,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def add_ip_abuse_tag(self, ip, tag):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT abuse_tags FROM ip_intelligence WHERE ip = %s", (ip,)
            )
            row = cursor.fetchone()
            if not row:
                self.log_ip_visit(ip)
                current_tags = []
            else:
                try:
                    current_tags = json.loads(row[0]) if row[0] else []
                except:
                    current_tags = []

            if tag not in current_tags:
                current_tags.append(tag)
                cursor.execute(
                    "UPDATE ip_intelligence SET abuse_tags = %s WHERE ip = %s",
                    (json.dumps(current_tags), ip),
                )
                conn.commit()
        finally:
            conn.close()

    def scan_and_repair_corruption(self, ip, username):
        """
        Scans User Filesystem for entries where a FILE overwrites a known DIRECTORY from Global/Skeleton layers.
        Deletes the corrupt file entry if found.
        """
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # Find User Files that might be directories
            cursor.execute(
                "SELECT path, content FROM user_filesystem WHERE ip=%s AND username=%s AND type='file' AND is_deleted=0",
                (ip, username),
            )
            candidates = cursor.fetchall()

            home_dir = "/root" if username == "root" else f"/home/{username}"
            repaired_count = 0

            for row in candidates:
                path = row["path"]
                content = row["content"]
                # Check if this path IS a directory in Skeleton
                is_skel_dir = False
                for item in self.skeleton_cache:
                    skel_path = item["path"]
                    if skel_path.startswith("~"):
                        skel_path = skel_path.replace("~", home_dir, 1)
                    if skel_path == path and item["type"] == "directory":
                        is_skel_dir = True
                        break

                # Also check Global FS if needed
                is_global_dir = False
                if not is_skel_dir:
                    node = self.get_fs_node(path)
                    if node and node["type"] == "directory":
                        is_global_dir = True

                if is_skel_dir or is_global_dir:
                    log.warning(
                        f"[FS Repair] Found corrupt FILE '{path}' shadowing a directory. Content: {str(content)[:50]}..."
                    )
                    cursor.execute(
                        "DELETE FROM user_filesystem WHERE ip=%s AND username=%s AND path=%s",
                        (ip, username, path),
                    )
                    repaired_count += 1

            if repaired_count > 0:
                conn.commit()
                log.info(
                    f"[FS Repair] Repaired {repaired_count} corrupt entries for {username}@{ip}"
                )

        except Exception as e:
            log.error(f"[FS Repair] Error: {e}")
        finally:
            conn.close()

    def get_global_stats(self):
        conn = self._get_conn()
        stats = {"sessions": 0, "total_commands": 0}
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM sessions")
            row = cursor.fetchone()
            if row:
                stats["sessions"] = row[0]

            cursor.execute("SELECT count(distinct remote_ip) FROM sessions")
            row = cursor.fetchone()
            if row:
                stats["unique_ips"] = row[0]

            cursor.execute("SELECT count(*) FROM interactions")
            row = cursor.fetchone()
            if row:
                stats["total_commands"] = row[0]
        finally:
            conn.close()
        return stats

    def get_active_sessions(self):
        conn = self._get_conn()
        sessions = []
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT username, remote_ip, start_time, session_id 
                FROM sessions 
                WHERE end_time IS NULL
                ORDER BY start_time ASC
            """
            )
            rows = cursor.fetchall()
            for r in rows:
                sessions.append(
                    {
                        "user": r[0],
                        "ip": r[1],
                        "start_time": str(r[2]),
                        "session_id": r[3],
                        "tty": f"pts/{int(hashlib.md5(r[3].encode()).hexdigest(), 16) % 10}",
                    }
                )
        finally:
            conn.close()
        return sessions

    def get_unique_creds_last_24h(self, ip):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, password FROM sessions WHERE remote_ip = %s AND start_time > NOW() - INTERVAL '24 hours'",
                (ip,),
            )
            return list(set(cursor.fetchall()))
        finally:
            conn.close()

    def validate_anti_harvesting(self, ip, username, password):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password FROM sessions WHERE remote_ip = %s AND username = %s AND start_time > NOW() - INTERVAL '1 day'",
                (ip, username),
            )
            passwords = {r[0] for r in cursor.fetchall()}
            if passwords and password not in passwords:
                return (
                    False,
                    f"Anti-Harvesting: IP {ip} trying new password for {username}",
                )
            return True, None
        except Exception as e:
            log.error(f"[Postgres] Error validating anti-harvesting: {e}")
            return True, None
        finally:
            conn.close()

    def check_root_desperation(self, ip):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT count(*) FROM auth_events WHERE client_ip = %s AND success = TRUE AND username != 'root' AND protocol = 'ssh'",
                (ip,),
            )
            if cursor.fetchone()[0] > 0:
                return "BLOCK"

            cursor.execute(
                "SELECT count(*) FROM auth_events WHERE client_ip = %s AND username = 'root' AND success = FALSE AND protocol = 'ssh'",
                (ip,),
            )
            failures = cursor.fetchone()[0]

            if failures == 2:
                cursor.execute(
                    "SELECT count(*) FROM auth_events WHERE client_ip = %s AND username = 'root' AND success = TRUE AND protocol = 'ssh'",
                    (ip,),
                )
                if cursor.fetchone()[0] == 0:
                    return "ALLOW"

            return "NORMAL"
        finally:
            conn.close()

    def get_recent_sessions(self, limit=20, protocol=None):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            if protocol:
                cursor.execute(
                    "SELECT * FROM sessions WHERE protocol = %s ORDER BY start_time DESC LIMIT %s",
                    (protocol, limit),
                )
            else:
                cursor.execute(
                    "SELECT * FROM sessions ORDER BY start_time DESC LIMIT %s", (limit,)
                )

            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, r)) for r in cursor.fetchall()]
        finally:
            conn.close()

    def get_session_interactions(self, session_id):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT command FROM interactions WHERE session_id = %s ORDER BY timestamp ASC, id ASC",
                (session_id,),
            )
            return [r[0] for r in cursor.fetchall()]
        finally:
            conn.close()

    def get_cached_session_summary(self, chain_hash):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT summary, risk_score FROM session_summaries_cache WHERE chain_hash = %s",
                (chain_hash,),
            )
            row = cursor.fetchone()
            if row:
                # Explicit tuple return to avoid dictionary unpacking bugs in caller
                return (row[0], row[1])
            return None
        finally:
            conn.close()

    def save_session_summary_cache(self, chain_hash, summary, risk_score):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO session_summaries_cache (chain_hash, summary, risk_score)
                VALUES (%s, %s, %s)
                ON CONFLICT (chain_hash) DO NOTHING
                """,
                (chain_hash, summary, risk_score),
            )
            conn.commit()
        finally:
            conn.close()

    def update_session_summary(self, session_id, summary, risk_score):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sessions SET summary = %s, risk_score = %s WHERE session_id = %s",
                (summary, risk_score, session_id),
            )
            conn.commit()
        finally:
            conn.close()

    def sanitize_artifacts(self):
        conn = self._get_conn()
        try:
            tables = [
                "sessions",
                "interactions",
                "global_filesystem",
                "session_summaries_cache",
                "ip_intelligence",
                "malicious_payloads",
            ]
            cursor = conn.cursor()
            for table in tables:
                cursor.execute(f"TRUNCATE {table} RESTART IDENTITY CASCADE")
            conn.commit()
            log.info("[Postgres] Cache and Session Data Cleared.")
        except Exception as e:
            log.error(f"[Postgres] Failed to clear cache: {e}")
        finally:
            conn.close()

    def is_path_deleted(self, ip, username, path):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT 1 FROM user_filesystem WHERE ip=%s AND username=%s AND path=%s AND is_deleted=1",
                (ip, username, path),
            )
            return cursor.fetchone() is not None
        finally:
            conn.close()

    def get_unanalyzed_commands(self, limit=10):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                """
                SELECT i.id, i.session_id, i.command, i.request_md5, s.remote_ip
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                LEFT JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE ca.command_hash IS NULL
                AND i.request_md5 IS NOT NULL
                AND i.command != ''
                ORDER BY i.id DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            log.error(f"[Postgres] Error fetching unanalyzed commands: {e}")
            return []
        finally:
            conn.close()

    def get_infographic_stats(self, hours=24, ignore_ips=None):
        """Returns complex stats for the infographic dashboard (Postgres)."""
        conn = self._get_conn()
        stats = {
            "total_ips": 0,
            "total_requests": 0,
            "total_sessions": 0,
            "total_networks": 0,
            "trends": {},
            "top_ips": [],
            "top_countries": [],
            "top_isps": [],
            "service_dist": [],
            "longest_sessions": [],
            "manual_vs_bot": {"manual": 0, "bot": 0},
            "recent_unique_commands": [],
            "top_ssh_commands": [],
            "top_telnet_commands": [],
            "top_mysql_commands": [],
            "top_http_commands": [],  # Added HTTP
            "top_redis_commands": [],
            "top_mcp_commands": [],
            "top_passwords": [],
            "top_ssh_users": [],
            "top_ssh_risk": [],
            "total_payloads": 0,
            "protocol_activity": {},  # For sorting in UI
            "multi_window": {},  # Added for 24H, 48H, 1W, 2W
        }
        try:
            cursor = conn.cursor()
            time_filter = f"NOW() - INTERVAL '{hours} hours'"
            prev_time_filter = f"NOW() - INTERVAL '{hours*2} hours'"

            # IP Exclusion Filter
            ip_filter = ""
            params = []
            if ignore_ips:
                placeholders = ",".join(["%s" for _ in ignore_ips])
                ip_filter = f"AND remote_ip NOT IN ({placeholders})"
                params = list(ignore_ips)

            # Helper for interactions (needs join with sessions to check remote_ip)
            interaction_ip_filter = ""
            if ignore_ips:
                placeholders = ",".join(["%s" for _ in ignore_ips])
                interaction_ip_filter = f"AND s.remote_ip NOT IN ({placeholders})"

            # --- TOTALS & TRENDS ---
            def get_window_stats(start_expr, end_expr=None):
                e_part = f" AND start_time <= {end_expr}" if end_expr else ""
                cursor.execute(
                    f"SELECT COUNT(DISTINCT remote_ip), COUNT(*) FROM sessions WHERE start_time > {start_expr} {e_part} {ip_filter}",
                    params,
                )
                ips, sessions = cursor.fetchone()

                ei_part = f" AND i.timestamp <= {end_expr}" if end_expr else ""
                cursor.execute(
                    f"""
                    SELECT COUNT(*) FROM interactions i
                    JOIN sessions s ON i.session_id = s.session_id
                    WHERE i.timestamp > {start_expr} {ei_part} {interaction_ip_filter}
                """,
                    params,
                )
                commands = cursor.fetchone()[0] or 0

                # Count unique networks (ORGs)
                cursor.execute(
                    f"""
                    SELECT COUNT(DISTINCT intel.org) 
                    FROM sessions s
                    JOIN ip_intelligence intel ON s.remote_ip = intel.ip
                    WHERE s.start_time > {start_expr} {e_part} {ip_filter}
                """,
                    params,
                )
                networks = cursor.fetchone()[0] or 0

                return {
                    "ips": ips or 0,
                    "sessions": sessions or 0,
                    "commands": commands,
                    "networks": networks,
                }

            # Multi-window Metrics (Task 3)
            windows = {"24H": 24, "48H": 48, "1W": 168, "2W": 336}
            for label, h in windows.items():
                w_filter = f"NOW() - INTERVAL '{h} hours'"
                w_stats = get_window_stats(w_filter)
                stats["multi_window"][label] = {
                    "ips": w_stats["ips"],
                    "networks": w_stats["networks"],
                    "interactions": w_stats["commands"],
                    "sessions": w_stats["sessions"],
                }

            current_window = get_window_stats(time_filter)
            prev_window = get_window_stats(prev_time_filter, time_filter)

            stats["total_ips"] = current_window["ips"]
            stats["total_sessions"] = current_window["sessions"]
            stats["total_requests"] = current_window["commands"]
            stats["total_networks"] = current_window["networks"]

            for key in ["ips", "sessions", "commands"]:
                curr = current_window[key]
                prev = prev_window[key]
                diff = curr - prev
                pct = (diff / prev * 100) if prev > 0 else 0
                stats["trends"][key] = {"diff": diff, "pct": round(pct, 1)}

            # Total Payloads
            query = f"SELECT COUNT(*) FROM malicious_payloads WHERE timestamp > {time_filter}"
            cursor.execute(query)
            stats["total_payloads"] = cursor.fetchone()[0] or 0

            # --- PROTOCOL DISTRIBUTION ---
            query = f"""
                SELECT s.protocol, COUNT(DISTINCT s.session_id) as sess_count, COUNT(i.id) as cmd_count
                FROM sessions s
                LEFT JOIN interactions i ON s.session_id = i.session_id
                WHERE s.start_time > {time_filter} {ip_filter}
                GROUP BY s.protocol
                ORDER BY sess_count DESC
            """
            cursor.execute(query, params)
            for r in cursor.fetchall():
                proto = r[0]
                stats["service_dist"].append(
                    {"protocol": proto, "sessions": r[1], "commands": r[2]}
                )
                stats["protocol_activity"][proto] = r[2]

            # --- TOP TABLES ---

            # Top Countries (Unique IPs and Sessions)
            query = f"""
                SELECT intel.country, COUNT(DISTINCT s.remote_ip) as unique_ips, COUNT(DISTINCT s.session_id) as sessions
                FROM sessions s 
                JOIN ip_intelligence intel ON s.remote_ip = intel.ip 
                WHERE s.start_time > {time_filter} {interaction_ip_filter}
                GROUP BY intel.country 
                ORDER BY unique_ips DESC LIMIT 50
            """
            cursor.execute(query, params)
            stats["top_countries"] = [
                {"country": r[0] or "Unknown", "ips": r[1], "sessions": r[2]}
                for r in cursor.fetchall()
            ]

            # Top ISPs (Unique IPs and Sessions)
            query = f"""
                SELECT intel.org, COUNT(DISTINCT s.remote_ip) as unique_ips, COUNT(DISTINCT s.session_id) as sessions
                FROM sessions s 
                JOIN ip_intelligence intel ON s.remote_ip = intel.ip 
                WHERE s.start_time > {time_filter} {interaction_ip_filter}
                GROUP BY intel.org 
                ORDER BY unique_ips DESC LIMIT 50
            """
            cursor.execute(query, params)
            stats["top_isps"] = [
                {"isp": r[0] or "Unknown", "ips": r[1], "sessions": r[2]}
                for r in cursor.fetchall()
            ]

            # Top SSH Users
            query = f"""
                SELECT username, COUNT(*) as count, COUNT(DISTINCT remote_ip) as unique_ips
                FROM sessions 
                WHERE start_time > {time_filter} AND protocol = 'ssh' AND username IS NOT NULL AND username != '' {ip_filter}
                GROUP BY username 
                ORDER BY count DESC LIMIT 50
            """
            cursor.execute(query, params)
            stats["top_ssh_users"] = [
                {"username": r[0], "count": r[1], "ips": r[2]}
                for r in cursor.fetchall()
            ]

            # Top Passwords
            query = f"""
                SELECT password, COUNT(*) as count, COUNT(DISTINCT remote_ip) as unique_ips
                FROM sessions 
                WHERE start_time > {time_filter} AND protocol = 'ssh' AND password IS NOT NULL AND password != '' {ip_filter}
                GROUP BY password 
                ORDER BY count DESC LIMIT 50
            """
            cursor.execute(query, params)
            stats["top_passwords"] = [
                {"password": r[0], "count": r[1], "ips": r[2]}
                for r in cursor.fetchall()
            ]

            # Generic Top Command Fetcher
            def get_top_commands(proto, limit=50):
                q = f"""
                    SELECT i.command, COUNT(*) as count, COUNT(DISTINCT s.remote_ip) as unique_ips
                    FROM interactions i
                    JOIN sessions s ON i.session_id = s.session_id
                    WHERE i.timestamp > {time_filter} AND s.protocol = %s {interaction_ip_filter}
                    GROUP BY i.command 
                    ORDER BY unique_ips DESC, count DESC LIMIT %s
                """
                cursor.execute(q, [proto] + params + [limit])
                return [
                    {"command": r[0], "count": r[1], "ips": r[2]}
                    for r in cursor.fetchall()
                ]

            stats["top_ssh_commands"] = get_top_commands("ssh")
            stats["top_telnet_commands"] = get_top_commands("telnet")
            stats["top_mysql_commands"] = get_top_commands("mysql")
            stats["top_http_commands"] = get_top_commands("http")
            stats["top_redis_commands"] = get_top_commands("redis")
            stats["top_mcp_commands"] = get_top_commands("mcp")

            # Top SSH Commands by Risk (Freq and unique IP counts)
            # Improved sorting: Risk first, then unique IPs, then total count
            query = f"""
                SELECT i.command, COALESCE(MAX(ca.risk_score), 0) as max_risk, COUNT(*) as count, COUNT(DISTINCT s.remote_ip) as unique_ips
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE i.timestamp > {time_filter} AND s.protocol = 'ssh' {interaction_ip_filter}
                GROUP BY i.command
                ORDER BY max_risk DESC, unique_ips DESC, count DESC
                LIMIT 50
            """
            cursor.execute(query, params)
            stats["top_ssh_risk"] = [
                {"command": r[0], "risk": r[1], "count": r[2], "ips": r[3]}
                for r in cursor.fetchall()
            ]

            # Recent Unique Commands
            query = f"""
                SELECT DISTINCT i.command 
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                WHERE s.start_time > {time_filter} {interaction_ip_filter}
                ORDER BY i.timestamp DESC LIMIT 20
            """
            cursor.execute(query, params)
            stats["recent_unique_commands"] = [r[0] for r in cursor.fetchall()]

            # Manual vs Bot
            query = f"""
                SELECT 
                    SUM(CASE WHEN command_count > 10 OR summary ILIKE '%manual%' THEN 1 ELSE 0 END) as manual_count,
                    SUM(CASE WHEN command_count <= 10 AND (summary IS NULL OR summary NOT ILIKE '%manual%') THEN 1 ELSE 0 END) as bot_count
                FROM (
                    SELECT s.session_id, s.summary, COUNT(i.id) as command_count
                    FROM sessions s
                    LEFT JOIN interactions i ON s.session_id = i.session_id
                    WHERE s.start_time > {time_filter} {interaction_ip_filter}
                    GROUP BY s.session_id, s.summary
                ) t
            """
            cursor.execute(query, params)
            row = cursor.fetchone()
            if row:
                stats["manual_vs_bot"] = {
                    "manual": int(row[0] or 0),
                    "bot": int(row[1] or 0),
                }

            # Top IPs Summary (for reference)
            query = f"""
                SELECT remote_ip, COUNT(*) as count 
                FROM sessions 
                WHERE start_time > {time_filter} {ip_filter}
                GROUP BY remote_ip 
                ORDER BY count DESC LIMIT 50
            """
            cursor.execute(query, params)
            stats["top_ips"] = [{"ip": r[0], "count": r[1]} for r in cursor.fetchall()]

        except Exception as e:
            log.error(f"[Postgres] Error fetching infographic stats: {e}")
        finally:
            conn.close()
        return stats

    def get_daily_session_counts(self, days=7):
        """Returns session counts for each of the last X days."""
        conn = self._get_conn()
        res = []
        try:
            cursor = conn.cursor()
            for i in range(days - 1, -1, -1):
                day_start = f"NOW() - INTERVAL '{i+1} days'"
                day_end = f"NOW() - INTERVAL '{i} days'"
                cursor.execute(
                    f"SELECT COUNT(*) FROM sessions WHERE start_time > {day_start} AND start_time <= {day_end}"
                )
                count = cursor.fetchone()[0] or 0

                # Get label like 'Jan 21'
                cursor.execute(f"SELECT TO_CHAR(NOW() - INTERVAL '{i} days', 'Mon DD')")
                label = cursor.fetchone()[0]
                res.append({"label": label, "count": count})
        except Exception as e:
            log.error(f"[Postgres] Error fetching daily session counts: {e}")
        finally:
            conn.close()
        return res

    def get_unanalyzed_sessions(self, limit=10):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT session_id FROM sessions WHERE (summary IS NULL OR summary = '') AND end_time IS NOT NULL ORDER BY start_time DESC LIMIT %s",
                (limit,),
            )
            return [r[0] for r in cursor.fetchall()]
        except Exception as e:
            log.error(f"[Postgres] Error fetching unanalyzed sessions: {e}")
            return []
        finally:
            conn.close()

    def save_analysis(self, cmd_hash, cmd_text, analysis):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO command_analysis 
                (command_hash, command_text, activity_type, stage, risk_score, explanation)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (command_hash) DO UPDATE SET
                    activity_type = EXCLUDED.activity_type,
                    stage = EXCLUDED.stage,
                    risk_score = EXCLUDED.risk_score,
                    explanation = EXCLUDED.explanation
                """,
                (
                    cmd_hash,
                    cmd_text,
                    analysis.get("type", "Unknown"),
                    analysis.get("stage", "Unknown"),
                    analysis.get("risk", 0),
                    analysis.get("explanation", ""),
                ),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error saving analysis: {e}")
        finally:
            conn.close()

    def get_analysis(self, cmd_hash):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM command_analysis WHERE command_hash = %s", (cmd_hash,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            log.error(f"[Postgres] Error fetching analysis: {e}")
            return None
        finally:
            conn.close()

    def inspect_path(self, ip, username, path):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM user_filesystem WHERE ip=%s AND username=%s AND path=%s",
                (ip, username, path),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            log.error(f"[Postgres] Error inspecting path: {e}")
            return None
        finally:
            conn.close()

    def inspect_dir(self, ip, username, directory):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM user_filesystem WHERE ip=%s AND username=%s AND parent_path=%s AND is_deleted=0",
                (ip, username, directory),
            )
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            log.error(f"[Postgres] Error inspecting dir: {e}")
            return []
        finally:
            conn.close()

    def add_malicious_payload(self, url, url_hash, session_id, ip, timestamp=None):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # 1. Insert/Get Payload ID
            cursor.execute(
                """
                INSERT INTO malicious_payloads (url, url_hash, session_id, ip, timestamp)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (url_hash) DO NOTHING
                RETURNING id
            """,
                (
                    url,
                    url_hash,
                    session_id,
                    ip,
                    timestamp or datetime.datetime.now(),
                ),
            )
            row = cursor.fetchone()
            conn.commit()
            return row is not None
            row = cursor.fetchone()

            if row:
                payload_id = row[0]
            else:
                # Assuming it exists, fetch it
                cursor.execute(
                    "SELECT id FROM malicious_payloads WHERE url_hash = %s", (url_hash,)
                )
                row = cursor.fetchone()
                payload_id = row[0] if row else None

            # 2. Track Request (Always)
            if payload_id:
                cursor.execute(
                    """
                    INSERT INTO payload_requests (payload_id, ip, session_id, timestamp)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (payload_id, ip, session_id, timestamp or datetime.datetime.now()),
                )

            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error adding malicious payload: {e}")
            conn.rollback()  # Ensure rollback on error
        finally:
            conn.close()

    def cleanup_malicious_payloads(self):
        """Removes duplicate URLs from the malicious_payloads table, keeping only the oldest."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                DELETE FROM malicious_payloads
                WHERE id NOT IN (
                    SELECT MIN(id)
                    FROM malicious_payloads
                    GROUP BY url_hash
                )
            """
            )
            deleted_count = cursor.rowcount
            conn.commit()
            if deleted_count > 0:
                log.info(
                    f"[Postgres] Cleaned up {deleted_count} duplicate malicious payloads."
                )
        except Exception as e:
            log.error(f"[Postgres] Error cleaning up payloads: {e}")
        finally:
            conn.close()

    def get_payload_by_hash(self, url_hash):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM malicious_payloads WHERE url_hash = %s", (url_hash,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            log.error(f"[Postgres] Error fetching payload by hash: {e}")
            return None
        finally:
            conn.close()

    def get_pending_payloads(self, limit=5):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM malicious_payloads WHERE status = 'pending' ORDER BY retry_count ASC, timestamp ASC LIMIT %s",
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            log.error(f"[Postgres] Error fetching pending payloads: {e}")
            return []
        finally:
            conn.close()

    def update_payload_status(
        self,
        payload_id,
        status,
        file_path=None,
        error=None,  # Changed from error_message to match call site
        payload_md5=None,
        payload_size=None,
    ):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            updates = ["status = %s"]
            params = [status]

            if file_path:
                updates.append("file_path = %s")
                params.append(file_path)
            if error:
                updates.append("error_message = %s")
                params.append(error)
            if payload_md5:
                updates.append("payload_md5 = %s")
                params.append(payload_md5)
            if payload_size is not None:
                updates.append("payload_size = %s")
                params.append(payload_size)

            # Increment retry count if failed
            if status == "failed":
                updates.append("retry_count = retry_count + 1")

            params.append(payload_id)

            sql = f"UPDATE malicious_payloads SET {', '.join(updates)} WHERE id = %s"
            cursor.execute(sql, tuple(params))
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error updating payload {payload_id}: {e}")
        finally:
            conn.close()

    def is_payload_host_rate_limited(self, hostname):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM malicious_payloads 
                WHERE url LIKE %s AND timestamp > NOW() - INTERVAL '1 hour'
                """,
                (f"%%//{hostname}/%%",),
            )
            count = cursor.fetchone()[0]
            return count >= 5
        except Exception as e:
            log.error(f"[Postgres] Error checking rate limit: {e}")
            return False
        finally:
            conn.close()

    def get_interactions_with_http(self):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM interactions WHERE command LIKE '%%http%%' OR command LIKE '%%wget%%' OR command LIKE '%%curl%%'"
            )
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            log.error(f"[Postgres] Error fetching HTTP interactions: {e}")
            return []
        finally:
            conn.close()

    def get_interactions_since_id(self, last_id, limit=100):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                """
                SELECT i.id, i.session_id, i.command, i.timestamp, s.remote_ip 
                FROM interactions i
                LEFT JOIN sessions s ON i.session_id = s.session_id
                WHERE i.id > %s AND (i.command LIKE '%%http%%' OR i.command LIKE '%%wget%%' OR i.command LIKE '%%curl%%')
                ORDER BY i.id ASC
                LIMIT %s
            """,
                (last_id, limit),
            )
            return cursor.fetchall() or []
        except Exception as e:
            log.error(f"[Postgres] Error fetching interactions since {last_id}: {e}")
            return []
        finally:
            conn.close()

    def clear_cache(self):
        self.sanitize_artifacts()

    def get_session(self, session_id):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM sessions WHERE session_id = %s", (session_id,)
            )
            row = cursor.fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None
        finally:
            conn.close()

    def get_session_protocol(self, session_id):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT protocol FROM sessions WHERE session_id = %s", (session_id,)
            )
            row = cursor.fetchone()
            if row:
                return row[0]
            return "unknown"
        finally:
            conn.close()

    def get_next_payload_for_analysis(self):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM malicious_payloads WHERE vt_scan_id IS NULL AND status = 'downloaded' LIMIT 1"
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            log.error(f"[Postgres] Error fetching next payload for analysis: {e}")
            return None
        finally:
            conn.close()

    def update_payload_vt_status(self, payload_id, result, scan_id=None):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE malicious_payloads SET vt_result = %s, vt_scan_id = %s WHERE id = %s",
                (result, scan_id, payload_id),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error updating payload VT status: {e}")
        finally:
            conn.close()

    def iter_interactions(self, batch_size=1000):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute("SELECT * FROM interactions ORDER BY timestamp ASC")
            while True:
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    break
                for row in rows:
                    yield dict(row)
        except Exception:
            pass
        finally:
            conn.close()

    def purge_poisoned_cache(self):
        """Purges cached responses containing AI Core error messages."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # Clear from command_cache
            cursor.execute(
                "DELETE FROM command_cache WHERE response LIKE %s",
                ("%AI Core Offline%",),
            )
            # Clear from interactions
            cursor.execute(
                "DELETE FROM interactions WHERE response LIKE %s",
                ("%AI Core Offline%",),
            )
            conn.commit()
            log.info("[Postgres] Purged poisoned cache entries.")
        except Exception as e:
            log.error(f"[Postgres] Error purging cache: {e}")
        finally:
            conn.close()

    def get_llm_response(self, prompt_hash):
        """Retrieves a cached LLM response by prompt hash if it exists and is fresh (30 days)."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # PostGres syntax: NOW() - INTERVAL '30 days'
            cursor.execute(
                """
                SELECT response FROM llm_response_cache 
                WHERE prompt_hash = %s AND created_at > NOW() - INTERVAL '30 days'
                """,
                (prompt_hash,),
            )
            row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            log.error(f"[Postgres] Error getting LLM cache: {e}")
            return None
        finally:
            conn.close()

    def save_llm_response(self, prompt_hash, prompt_text, response):
        """Caches an LLM response."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # Upsert in Postgres (ON CONFLICT)
            cursor.execute(
                """
                INSERT INTO llm_response_cache (prompt_hash, prompt_text, response)
                VALUES (%s, %s, %s)
                ON CONFLICT (prompt_hash) DO UPDATE SET
                    response = EXCLUDED.response,
                    updated_at = CURRENT_TIMESTAMP,
                    created_at = CURRENT_TIMESTAMP -- Reset expiry
                """,
                (prompt_hash, prompt_text, response),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error saving LLM cache: {e}")
        finally:
            conn.close()
