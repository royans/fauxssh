import sqlite3
import datetime
import hashlib
import os
import json
import time

try:
    from .db_interface import DatabaseBackend
    from .logging_setup import log
    from .config import get_data_dir
except ImportError:
    from db_interface import DatabaseBackend
    from ssh_honeypot.core.logging_setup import log
    from config_manager import get_data_dir

try:
    from .cache import cache
except ImportError:
    from ssh_honeypot.core.cache import cache
except:
    cache = None  # Fallback


# Use centralized data directory
DB_PATH = os.path.join(get_data_dir(), "honeypot.sqlite")


class SQLiteBackend(DatabaseBackend):
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.placeholder = "?"
        self._init_db()
        self.skeleton_cache = []
        self._load_skeleton()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

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

    def get_connection_info(self):
        return f"SQLite Backend (Path: {self.db_path})"

    def get_max_interaction_id(self):
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute("SELECT MAX(id) FROM interactions")
            row = c.fetchone()
            return row[0] if row and row[0] else 0
        except Exception as e:
            log.error(f"[DB] Error getting max interaction ID: {e}")
            return 0
        finally:
            conn.close()

    def _init_db(self):
        # Directory creation handled by get_data_dir()

        conn = sqlite3.connect(self.db_path)
        # Enable WAL mode for better concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")  # Faster writes in WAL mode
        conn.execute(
            "PRAGMA busy_timeout = 30000;"
        )  # Ensure persistent timeout setting
        c = conn.cursor()

        # Sessions Table
        c.execute(
            """CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            remote_ip TEXT,
            username TEXT,
            password TEXT,
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME,
            client_version TEXT,
            protocol TEXT DEFAULT 'ssh',
            summary TEXT,
            risk_score INTEGER
        )"""
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time)"
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(remote_ip)")

        # Migration: Add columns to existing sessions table if needed
        try:
            c.execute("ALTER TABLE sessions ADD COLUMN summary TEXT")
        except sqlite3.OperationalError:
            pass  # Already exists

        try:
            c.execute("ALTER TABLE sessions ADD COLUMN risk_score INTEGER")
        except sqlite3.OperationalError:
            pass  # Already exists

        try:
            c.execute("ALTER TABLE sessions ADD COLUMN protocol TEXT DEFAULT 'ssh'")
        except sqlite3.OperationalError:
            pass  # Already exists

        # Session Summaries Cache (LLM Optimization)
        c.execute(
            """CREATE TABLE IF NOT EXISTS session_summaries_cache (
            chain_hash TEXT PRIMARY KEY,
            summary TEXT,
            risk_score INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
        )

        # Interactions Log (Audit Trail)
        c.execute(
            """CREATE TABLE IF NOT EXISTS interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cwd TEXT,
            command TEXT,
            response TEXT,
            request_md5 TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        )"""
        )

        # Global Filesystem Table (Simulated File System)
        c.execute(
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
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_parent ON global_filesystem(parent_path)"
        )

        # User-Specific Filesystem (Isolated Uploads)
        # Scoped by IP and Username
        c.execute(
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
                last_accessed DATETIME,
                is_deleted BOOLEAN DEFAULT 0,
                PRIMARY KEY (ip, username, path)
            )
        """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_parent ON user_filesystem(ip, username, parent_path)"
        )

        # Cache Table (Simulated State)
        c.execute(
            """CREATE TABLE IF NOT EXISTS command_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cmd_hash TEXT UNIQUE,
            command TEXT,
            cwd TEXT,
            response TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
        )

        # Auth Events Log (Login Attempts)
        c.execute(
            """CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            username TEXT,
            auth_method TEXT,
            auth_data TEXT,
            success BOOLEAN,
            client_version TEXT,
            fingerprint TEXT,
            protocol TEXT DEFAULT 'ssh'
        )"""
        )

        # Threat Analysis Table
        c.execute(
            """CREATE TABLE IF NOT EXISTS command_analysis (
            command_hash TEXT PRIMARY KEY,
            command_text TEXT,
            activity_type TEXT,
            stage TEXT,
            risk_score INTEGER,
            explanation TEXT,
            analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
        )

        # Custom Migrations
        try:
            c.execute("ALTER TABLE sessions ADD COLUMN fingerprint TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            c.execute("ALTER TABLE auth_events ADD COLUMN fingerprint TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            c.execute("ALTER TABLE interactions ADD COLUMN source TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            c.execute("ALTER TABLE interactions ADD COLUMN request_md5 TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            c.execute("ALTER TABLE user_filesystem ADD COLUMN last_accessed DATETIME")
        except sqlite3.OperationalError:
            pass

        try:
            c.execute(
                "ALTER TABLE user_filesystem ADD COLUMN is_deleted BOOLEAN DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass

        # LLM Usage Tracking (Rate Limiting)
        c.execute(
            """CREATE TABLE IF NOT EXISTS llm_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source TEXT DEFAULT 'http'
        )"""
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_llm_usage_ip_time ON llm_usage(ip, timestamp)"
        )

        # LLM Response Cache (Jan 19)
        c.execute(
            """CREATE TABLE IF NOT EXISTS llm_response_cache (
            prompt_hash TEXT PRIMARY KEY,
            prompt_text TEXT,
            response TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"""
        )

        # Analytics: Response Tracking (Jan 3)
        try:
            c.execute("ALTER TABLE interactions ADD COLUMN response_md5 TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            c.execute("ALTER TABLE interactions ADD COLUMN response_head TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            c.execute("ALTER TABLE interactions ADD COLUMN response_size INTEGER")
        except sqlite3.OperationalError:
            pass

        # Protocol Support (Jan 7)
        try:
            c.execute("ALTER TABLE sessions ADD COLUMN protocol TEXT DEFAULT 'ssh'")
        except sqlite3.OperationalError:
            pass
        try:
            c.execute("ALTER TABLE auth_events ADD COLUMN protocol TEXT DEFAULT 'ssh'")
        except sqlite3.OperationalError:
            pass

        # Indexes (Jan 7) - Performance Optimization
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_interactions_session ON interactions(session_id)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_interactions_md5 ON interactions(request_md5)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_interactions_ts ON interactions(timestamp)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time)"
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(remote_ip)")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time)"
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(remote_ip)")

        # Requested URLs Log (Network Intelligence)
        c.execute(
            """CREATE TABLE IF NOT EXISTS requested_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            session_id TEXT,
            url TEXT,
            method TEXT,
            user_agent TEXT,
            command_text TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        )"""
        )

        # IP Intelligence (Jan 10)
        c.execute(
            """CREATE TABLE IF NOT EXISTS ip_intelligence (
            ip TEXT PRIMARY KEY,
            hostname TEXT,
            city TEXT,
            country TEXT,
            isp TEXT,
            org TEXT,
            asn TEXT,
            network_type TEXT,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            enriched BOOLEAN DEFAULT 0,
            raw_data TEXT,
            abuse_tags TEXT DEFAULT '[]'
        )"""
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_ip_intel_enriched ON ip_intelligence(enriched, last_seen)"
        )

        # Requested URLs Log (Network Intelligence)
        c.execute(
            """CREATE TABLE IF NOT EXISTS requested_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            session_id TEXT,
            url TEXT,
            method TEXT,
            user_agent TEXT,
            command_text TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        )"""
        )

        # Malicious Payloads (Jan 10)
        c.execute(
            """CREATE TABLE IF NOT EXISTS malicious_payloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            url_hash TEXT UNIQUE,
            session_id TEXT,
            ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            payload_md5 TEXT,
            payload_size INTEGER,
            file_path TEXT,
            retry_count INTEGER DEFAULT 0,

            error_message TEXT,
            virustotal_result TEXT,
            vt_last_scanned DATETIME,
            vt_scan_id TEXT
        )"""
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_payload_status ON malicious_payloads(status)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_payload_md5 ON malicious_payloads(payload_md5)"
        )

        try:
            c.execute(
                "ALTER TABLE malicious_payloads ADD COLUMN virustotal_result TEXT"
            )
        except:
            pass
        try:
            c.execute(
                "ALTER TABLE malicious_payloads ADD COLUMN vt_last_scanned DATETIME"
            )
        except:
            pass
        try:
            c.execute("ALTER TABLE malicious_payloads ADD COLUMN vt_scan_id TEXT")
        except:
            pass

        conn.commit()
        conn.close()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, timeout=30.0)

    def log_url_request(
        self, session_id, url, method="GET", user_agent=None, command_text=None
    ):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO requested_urls (session_id, url, method, user_agent, command_text)
                VALUES (?, ?, ?, ?, ?)
            """,
                (session_id, url, method, user_agent, command_text),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error logging URL request: {e}")
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
        conn = None
        try:
            fp_json = "{}"
            if fingerprint:
                fp_json = json.dumps(fingerprint)

            conn = self._get_conn()
            c = conn.cursor()
            c.execute(
                """
                INSERT INTO auth_events (client_ip, username, auth_method, auth_data, success, client_version, fingerprint, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
            log.error(f"[!] DB Error log_auth_event (Protocol: {protocol}): {e}")
        finally:
            if conn:
                conn.close()

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
        """Log the start of a new SSH session."""
        conn = self._get_conn()
        try:
            # Serialize Fingerprint
            fp_json = json.dumps(fingerprint) if fingerprint else None

            if start_time:
                conn.execute(
                    """INSERT INTO sessions
                    (session_id, remote_ip, username, password, client_version, fingerprint, protocol, start_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
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
                conn.execute(
                    """INSERT INTO sessions
                    (session_id, remote_ip, username, password, client_version, fingerprint, protocol)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
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

            # Record IP Visit for LLM Rate Limiting / Intelligence
            # (Optional, but good for tracking)
            self.log_ip_visit(ip)  # Keep original log_ip_visit call

        except sqlite3.IntegrityError:
            log.warning(f"Session {session_id} already exists (Duplicate).")
        except Exception as e:
            log.error(f"Error start_session: {e}")
        finally:
            conn.close()

    def end_session(self, session_id):
        conn = self._get_conn()
        try:
            # Check if we should log empty sessions
            log_empty = (
                str(os.getenv("FAUXSSH_LOG_EMPTY_SESSIONS", "false")).lower() == "true"
            )

            if not log_empty:
                # Check interaction count
                c = conn.cursor()
                c.execute(
                    "SELECT COUNT(*) FROM interactions WHERE session_id = ?",
                    (session_id,),
                )
                count = c.fetchone()[0]

                if count == 0:
                    # Delete session entirely
                    c.execute(
                        "DELETE FROM sessions WHERE session_id = ?", (session_id,)
                    )
                    log.debug(
                        f"[DB] Deleted empty session {session_id} (No interactions)"
                    )
                    conn.commit()
                    return

            conn.execute(
                "UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE session_id = ?",
                (session_id,),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[!] DB Error end_session: {e}")
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
        # Defensive Type Casting to prevent SQLite InterfaceError with dicts
        try:
            if isinstance(source, dict) or isinstance(source, list):
                log.warning(
                    f"[DB] Warning: 'source' param was {type(source)} (Val: {source}), casting to str."
                )
                source = (
                    str(source.get("source", str(source)))
                    if isinstance(source, dict)
                    else str(source)
                )
            else:
                source = str(source)

            if request_md5 and (
                isinstance(request_md5, dict) or isinstance(request_md5, list)
            ):
                log.warning(
                    f"[DB] Warning: 'request_md5' param was {type(request_md5)}, casting to str."
                )
                request_md5 = str(request_md5)
        except Exception as caste:
            log.error(f"[DB] Critical Cast Error: {caste}")
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
            conn.execute(
                """
                INSERT INTO interactions 
                (session_id, cwd, command, response, source, request_md5, response_md5, response_head, response_size) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            log.error(f"[DB] Error logging interaction: {e}")
        finally:
            conn.close()

        # Unified Logging Consolidation (Jan 16)
        # Instead of writing to a separate ad-hoc file, we route this through the EventLogger
        try:
            from .event_logger import EventLogger

            # Reconstruct legacy fields for backward compat in the data block
            # But mostly we want the standardized 'interaction' event
            EventLogger().log_interaction(
                session_id=session_id,
                ip=ip if "ip" in locals() else "unknown",
                input_cmd=command,
                output_content=response,
                protocol="ssh",  # We assume SSH here, maybe pass it in if available
                analysis={"cached": was_cached, "response_time_ms": duration_ms},
            )
        except Exception as e:
            log.error(f"Error logging to Unified EventLogger: {e}")

        # Payload Pipeline Hook (Restored)
        try:
            from .payload_manager import PayloadManager

            # Optimization: Only check if command looks suspicious
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
                        "SELECT remote_ip FROM sessions WHERE session_id = ?",
                        (session_id,),
                    )
                    row = cursor.fetchone()
                    conn.close()

                    remote_ip = row[0] if row else "unknown"

                    for url in urls:
                        pm.queue_payload(url, session_id, remote_ip)

        except Exception as e:
            log.error(f"[DB] Error in Payload Pipeline: {e}")

    def get_cached_response(self, command, cwd):
        if cache:
            val = cache.get_content(command, cwd)
            if val is not None:
                return val

        h = hashlib.sha256(f"{cwd}:{command}".encode()).hexdigest()
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("SELECT response FROM command_cache WHERE cmd_hash = ?", (h,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None

    def get_fs_node(self, path):
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM global_filesystem WHERE path = ?", (path,))
        row = c.fetchone()

        result = None
        if row:
            columns = [col[0] for col in c.description]
            result = dict(zip(columns, row))

        conn.close()
        return result

    def save_command_analysis(
        self, command_hash, command_text, activity_type, stage, risk_score, explanation
    ):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO command_analysis 
                (command_hash, command_text, activity_type, stage, risk_score, explanation)
                VALUES (?, ?, ?, ?, ?, ?)
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
            log.error(f"[DB] Error saving command analysis: {e}")
        finally:
            conn.close()

    def list_fs_dir(self, parent_path):
        conn = self._get_conn()
        c = conn.cursor()
        try:
            c.execute(
                "SELECT * FROM global_filesystem WHERE parent_path = ?", (parent_path,)
            )
            rows = c.fetchall()
            columns = [col[0] for col in c.description]
            result = [dict(zip(columns, r)) for r in rows]
            return result
        finally:
            conn.close()

    def update_fs_node(self, path, parent_path, type, metadata, content=None):
        conn = self._get_conn()

        # Ensure content is string (handle LLM returning dicts in generic handlers)
        if isinstance(content, (dict, list)):
            content = str(content)

        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO global_filesystem (path, parent_path, type, metadata, content)
                VALUES (?, ?, ?, ?, ?)
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

    def update_user_file(
        self, ip, username, path, parent_path, type, metadata, content=None
    ):
        conn = self._get_conn()

        # 0. GUARD: Prevent overwriting known directories with files
        # Only applies if we are trying to write a FILE to a path that should be a DIRECTORY
        if type == "file" and self.is_managed_directory(ip, username, path):
            # Check if it is EXACTLY a directory (is_managed checks parents too)
            # We need to know if 'path' ITSELF is a directory in Skeleton/Global
            # Quick heuristic: If is_managed_directory says true, verify if it's a DIR match

            # Logic: If path is in skeleton (dir) or Global (dir), reject FILE update
            is_known_dir = False

            # Check Skeleton
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
                    f"[FS Guard] Prevented overwriting directory '{path}' with file content: {str(content)[:50]}"
                )
                # We silently return success to avoid crashing LLM logic?
                # Or we save it as something else?
                # Let's save it to a "lost+found" or just drop it.
                # Dropping it is safer to preserve directory integrity.
                conn.close()
                return

        # Ensure content is string
        if isinstance(content, (dict, list)):
            content = str(content)

        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO user_filesystem (ip, username, path, parent_path, type, metadata, content, is_deleted)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
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

            # recursive directory creation
            if type == "file":
                self._ensure_parent_dirs(conn, ip, username, parent_path)
            elif type == "directory":
                # also ensure parents of this directory exist
                self._ensure_parent_dirs(conn, ip, username, parent_path)

            conn.commit()
        finally:
            conn.close()

    def record_llm_usage(self, ip, source="http"):
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT INTO llm_usage (ip, source) VALUES (?, ?)", (ip, source)
            )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error recording LLM usage: {e}")
        finally:
            conn.close()

    def check_llm_rate_limit(self, ip, rpm_limit, rph_limit, rpd_limit):
        """
        Checks if IP has exceeded RPM, RPH, or RPD limits.
        Returns (allowed: bool, reason: str)
        """
        # 0. Check Cache First
        if cache and cache.is_blocked(ip, "llm"):
            return False, "Rate Limit Exceeded (Cached)"

        conn = self._get_conn()
        try:
            c = conn.cursor()

            # Check RPM (Last 60 seconds)
            # SQLite 'now' is UTC. We assume usage stored as UTC (CURRENT_TIMESTAMP)
            c.execute(
                "SELECT COUNT(*) FROM llm_usage WHERE ip = ? AND timestamp > datetime('now', '-60 seconds')",
                (ip,),
            )
            rpm_count = c.fetchone()[0]
            if rpm_count >= rpm_limit:
                if cache:
                    cache.set_block(ip, "llm", ttl=60)
                return False, f"RPM Limit Exceeded ({rpm_count}/{rpm_limit})"

            # Check RPH (Last 1 hour)
            c.execute(
                "SELECT COUNT(*) FROM llm_usage WHERE ip = ? AND timestamp > datetime('now', '-1 hour')",
                (ip,),
            )
            rph_count = c.fetchone()[0]
            if rph_count >= rph_limit:
                if cache:
                    cache.set_block(ip, "llm", ttl=3600)
                return False, f"RPH Limit Exceeded ({rph_count}/{rph_limit})"

            # Check RPD (Last 24 hours)
            c.execute(
                "SELECT COUNT(*) FROM llm_usage WHERE ip = ? AND timestamp > datetime('now', '-24 hours')",
                (ip,),
            )
            rpd_count = c.fetchone()[0]
            if rpd_count >= rpd_limit:
                if cache:
                    cache.set_block(ip, "llm", ttl=86400)
                return False, f"RPD Limit Exceeded ({rpd_count}/{rpd_limit})"

            return True, "OK"
        except Exception as e:
            log.error(f"[DB] Error checking LLM limits: {e}")
            return (
                True,
                "Error check failed (Fail Open)",
            )  # Fail open to ensure service continuity? Or fail closed?
            # Fail open is usually safer for honeypots to avoid logging errors as blocks
        finally:
            conn.close()

    def get_user_node(self, ip, username, path):
        # 1. Check User DB (Modifications)
        conn = self._get_conn()
        c = conn.cursor()
        c.execute(
            "SELECT * FROM user_filesystem WHERE ip = ? AND username = ? AND path = ?",
            (ip, username, path),
        )
        row = c.fetchone()

        result = None
        if row:
            columns = [col[0] for col in c.description]
            result = dict(zip(columns, row))
        conn.close()

        if result:
            # Check for Tombstone
            if result.get("is_deleted"):
                return None

            # Touch access time for aggressive cleanup tracking
            self.touch_user_file(ip, username, path)
            return result

        # 2. Check Skeleton (COW Layer)
        # Resolve home dir
        home_dir = "/root" if username == "root" else f"/home/{username}"

        for item in self.skeleton_cache:
            skel_path = item["path"]
            # Dynamic Home Replacement
            if skel_path.startswith("~"):
                resolved_path = skel_path.replace("~", home_dir, 1)
            else:
                resolved_path = skel_path

            if resolved_path == path:
                # Found in skeleton! Return ephemeral node.
                # We need to construct a node dict similar to DB row
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
                    "created_at": datetime.datetime.now().isoformat(),  # Fake TS
                }

        # 3. Check Global DB (Slowest, Persistence for large static files)
        try:
            conn = self._get_conn()
            c = conn.cursor()
            c.execute("SELECT * FROM global_filesystem WHERE path = ?", (path,))
            row = c.fetchone()
            if row:
                columns = [col[0] for col in c.description]
                return dict(zip(columns, row))
        except Exception:
            pass
        finally:
            conn.close()

        return None

    def list_user_dir(self, ip, username, parent_path):
        """
        Lists directory contents by composing layers:
        1. Global (Base)
        2. Skeleton (Overlay)
        3. User (Modifications)
        Tombstones in User layer hide files from lower layers.
        """
        items_map = {}  # path -> item_dict

        # 1. Layer 1: Global Filesystem
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT * FROM global_filesystem WHERE parent_path = ?", (parent_path,)
            )
            rows = c.fetchall()
            columns = [col[0] for col in c.description]
            for r in rows:
                g_item = dict(zip(columns, r))
                items_map[g_item["path"]] = {
                    "ip": ip,
                    "username": username,
                    "path": g_item["path"],
                    "type": g_item["type"],
                    "metadata": g_item["metadata"],
                    "content": g_item["content"],
                    "created_at": g_item["created_at"],
                    "source_layer": "global",
                }
        except Exception as e:
            log.error(f"Error listing global FS: {e}")
        finally:
            conn.close()

        # 2. Layer 2: Skeleton Cache
        home_dir = "/root" if username == "root" else f"/home/{username}"

        for item in self.skeleton_cache:
            skel_path = item["path"]
            if skel_path.startswith("~"):
                resolved_path = skel_path.replace("~", home_dir, 1)
            else:
                resolved_path = skel_path

            # Normalize parent_path for matching (strip trailing slash)
            # This fixes mismatches where parent_path has slash but dirname does not
            check_parent = parent_path.rstrip("/")
            if not check_parent:
                check_parent = "/"

            if os.path.dirname(resolved_path) == check_parent:
                meta = item.get("metadata", {}).copy()
                if "owner" not in meta:
                    meta["owner"] = username
                if "group" not in meta:
                    meta["group"] = username

                # Overwrite Global
                items_map[resolved_path] = {
                    "ip": ip,
                    "username": username,
                    "path": resolved_path,
                    "type": item["type"],
                    "metadata": json.dumps(meta),
                    "content": item.get("content"),
                    "created_at": datetime.datetime.now().isoformat(),  # Mock time for skeleton
                    "source_layer": "skeleton",
                }
        # 3. Layer 3: User Filesystem
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT * FROM user_filesystem WHERE ip = ? AND username = ? AND parent_path = ?",
                (ip, username, check_parent),
            )
            rows = c.fetchall()
            columns = [col[0] for col in c.description]
            for r in rows:
                u_item = dict(zip(columns, r))
                path = u_item["path"]

                # Check for Tombstone
                if u_item.get("is_deleted"):
                    # Explicit deletion -> Remove from map if exists
                    if path in items_map:
                        del items_map[path]
                else:
                    # Overwrite Lower Layers
                    u_item["source_layer"] = "user"
                    items_map[path] = u_item
        except Exception as e:
            log.error(f"Error listing user FS: {e}")
        finally:
            conn.close()

        # Return values
        return list(items_map.values())

    def is_managed_directory(self, ip, username, path):
        """
        Returns True if the directory is 'managed' (i.e. we know it exists in DB, Skeleton, or Global).
        This helps command handlers decide whether to use local ls or fallback to LLM.
        """
        # 1. Check User Home (Always managed)
        home_dir = "/root" if username == "root" else f"/home/{username}"

        # DEBUG TRACE
        print(
            f"[DB MANAGED CHECK] User: {username}, Path: '{path}', Home: '{home_dir}'"
        )

        if path == home_dir or path.startswith(home_dir + "/"):
            print("[DB MANAGED] Matched Home Dir")
            return True

        # 2. Check User DB for exact path existence (as a directory or parent of items)
        conn = self._get_conn()
        try:
            c = conn.cursor()
            # Check if it exists as a directory itself
            c.execute(
                "SELECT 1 FROM user_filesystem WHERE ip=? AND username=? AND path=? AND type='directory' AND is_deleted=0",
                (ip, username, path),
            )
            if c.fetchone():
                return True

            # Check if it has children (implicit directory)
            c.execute(
                "SELECT 1 FROM user_filesystem WHERE ip=? AND username=? AND parent_path=? AND is_deleted=0",
                (ip, username, path),
            )
            if c.fetchone():
                return True
        finally:
            conn.close()

        # 3. Check Skeleton Cache
        for item in self.skeleton_cache:
            skel_path = item["path"]
            if skel_path.startswith("~"):
                skel_path = skel_path.replace("~", home_dir, 1)

            # If path matches a skeleton item (which is a dir)
            if skel_path == path and item["type"] == "directory":
                return True
            # If path is a parent of a skeleton item
            if os.path.dirname(skel_path) == path:
                return True

        # 4. Check Global DB
        # TODO: Add global DB check if needed. For now Global is static /etc mostly.

        return False

    def cache_response(self, command, cwd, response):
        if cache:
            cache.set_content(command, cwd, response)

        h = hashlib.sha256(f"{cwd}:{command}".encode()).hexdigest()
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO command_cache (cmd_hash, command, cwd, response) VALUES (?, ?, ?, ?)",
            (h, command, cwd, response),
        )
        conn.commit()
        conn.close()

    def get_ip_upload_usage(self, ip):
        conn = self._get_conn()
        c = conn.cursor()
        c.execute(
            "SELECT metadata FROM user_filesystem WHERE ip = ? AND is_deleted = 0",
            (ip,),
        )
        rows = c.fetchall()
        conn.close()

        total_size = 0
        for r in rows:
            try:
                meta = json.loads(r[0]) if isinstance(r[0], str) else (r[0] or {})
                total_size += int(meta.get("size", 0))
            except:
                pass

        return total_size

    def cleanup_http_cache(self, web_root="/var/www/html"):
        """
        Removes cached HTTP responses for files that exist on the local filesystem (VFS).
        This is typically run at startup to ensure local files override cached hallucinations.

        Args:
            web_root: The root directory to scan in the VFS (Global/User layers).
        """
        conn = self._get_conn()
        deleted_count = 0
        try:
            c = conn.cursor()

            # 1. Find all files in Global/User FS that look like web content
            # We check Global Filesystem mostly, as User FS is session specific,
            # but HTTP cache is currently global (HTTP_ROOT).
            # So we scan global_filesystem for overrides.

            # Note: We prioritize Global Filesystem (Persona) files.
            # Ideally we'd scan user_fs too if we had per-user cache,
            # but current cache key is just "HTTP <METHOD> <PATH>" + "HTTP_ROOT" cwd.

            # Get list of files in VFS under web_root
            # Using LIKE for prefix match
            c.execute(
                "SELECT path FROM global_filesystem WHERE path LIKE ? AND type='file'",
                (f"{web_root}%",),
            )
            rows = c.fetchall()

            for (path,) in rows:
                # /var/www/html/index.html -> /index.html
                if path.startswith(web_root):
                    rel_path = path[len(web_root) :]
                    if not rel_path.startswith("/"):
                        rel_path = "/" + rel_path

                    # Construct keys to invalidate
                    # 1. Exact match (GET/POST/HEAD)
                    # We use LIKE to match all methods: "HTTP % {rel_path}"
                    # But cache key might have extra args for POST.
                    # "HTTP % {rel_path}%"

                    pattern = f"HTTP % {rel_path}%"
                    c.execute(
                        "DELETE FROM command_cache WHERE command LIKE ? AND cwd='HTTP_ROOT'",
                        (pattern,),
                    )
                    deleted_count += c.rowcount

                    # 2. Index Logic
                    # If file is index.html/php/htm, also invalidate directory root
                    # e.g. /index.html -> /
                    filename = os.path.basename(rel_path)
                    if filename.lower() in ["index.html", "index.php", "index.htm"]:
                        dir_path = os.path.dirname(rel_path)
                        # Ensure dir_path ends with / or matches exactly?
                        # Cache key for root is usually "HTTP GET /"
                        # If dir_path is "/", pattern is "HTTP % /%"

                        # Handle Root specially
                        if dir_path == "/":
                            # Matches "HTTP GET /" and "HTTP GET / extra"
                            # But be careful not to match "/other"
                            # So we match "HTTP % /" exactly OR "HTTP % / %" (with body hash)
                            c.execute(
                                "DELETE FROM command_cache WHERE command LIKE 'HTTP % /' AND cwd='HTTP_ROOT'"
                            )
                            deleted_count += c.rowcount
                            c.execute(
                                "DELETE FROM command_cache WHERE command LIKE 'HTTP % / %' AND cwd='HTTP_ROOT'"
                            )
                            deleted_count += c.rowcount
                        else:
                            # For subdir /foo/index.html -> /foo/
                            # Remove trailing slash for uniformity in basic requests?
                            # Servers usually redirect /foo -> /foo/
                            # Let's clean both "/foo" and "/foo/"

                            # Clean "/foo"
                            p1 = f"HTTP % {dir_path}"
                            c.execute(
                                "DELETE FROM command_cache WHERE command LIKE ? AND cwd='HTTP_ROOT'",
                                (p1,),
                            )
                            deleted_count += c.rowcount

                            # Clean "/foo/"
                            if not dir_path.endswith("/"):
                                p2 = f"HTTP % {dir_path}/"
                                c.execute(
                                    "DELETE FROM command_cache WHERE command LIKE ? AND cwd='HTTP_ROOT'",
                                    (p2,),
                                )
                                deleted_count += c.rowcount

            if deleted_count > 0:
                conn.commit()
                log.info(
                    f"[HTTP] Startup Cache Cleanup: Invalidated {deleted_count} entries shadowing local files."
                )

        except Exception as e:
            log.error(f"[DB] Error cleaning HTTP cache: {e}")
        finally:
            conn.close()

    def prune_uploads(self, days=30):
        cutoff_time = datetime.datetime.now() - datetime.timedelta(days=days)

        conn = self._get_conn()
        c = conn.cursor()

        # Use COALESCE to fallback to created_at if last_accessed is NULL (never read)
        # This implements: "Assume NULL means it was last accessed at create time"
        # AND is_deleted = 0: Do NOT prune tombstones (which would cause ghost files to reappear from skeleton)
        c.execute(
            "SELECT ip, username, path FROM user_filesystem WHERE COALESCE(last_accessed, created_at) < ? AND is_deleted = 0",
            (cutoff_time,),
        )
        to_delete = c.fetchall()

        c.execute(
            "DELETE FROM user_filesystem WHERE COALESCE(last_accessed, created_at) < ? AND is_deleted = 0",
            (cutoff_time,),
        )
        conn.commit()
        conn.close()

        return [{"ip": r[0], "username": r[1], "path": r[2]} for r in to_delete]

    def touch_user_file(self, ip, username, path):
        """
        Updates the last_accessed timestamp for a user file to prevent cleanup.
        """
        try:
            conn = self._get_conn()
            conn.execute(
                """
                UPDATE user_filesystem 
                SET last_accessed = CURRENT_TIMESTAMP 
                WHERE ip=? AND username=? AND path=?
            """,
                (ip, username, path),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"[DB] Failed to touch user file {path}: {e}")

    def delete_user_file(self, ip, username, path):
        # Tombstone deletion: Mark as deleted instead of removing row
        # This ensures we shadow any skeleton file with the same path
        conn = self._get_conn()
        try:
            # We need parent path? It's not strictly needed for deletion lookup (PK is ip, user, path)
            # But if it's a new insert (shadowing skeleton), we might need it for completeness?
            # For now, let's just insert with is_deleted=1.
            # We might need to fetch parent_path from skeleton if it doesn't exist?
            # Or just allow NULLs for others? schema allows?
            # user_filesystem has no NOT NULL except PK?
            # PK is ip, username, path.

            parent_path = os.path.dirname(path)

            # Insert tombstone
            conn.execute(
                """
                INSERT OR REPLACE INTO user_filesystem (ip, username, path, parent_path, type, metadata, content, is_deleted)
                VALUES (?, ?, ?, ?, 'tombstone', '{}', NULL, 1)
             """,
                (ip, username, path, parent_path),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error deleting user file {path}: {e}")
        finally:
            conn.close()

    # --- IP Intelligence Methods ---

    def log_ip_visit(self, ip):
        """Records an IP visit. Inserts new record or updates last_seen."""
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO ip_intelligence (ip, first_seen, last_seen, enriched)
                VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0)
                ON CONFLICT(ip) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
            """,
                (ip,),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error logging IP visit {ip}: {e}")
        finally:
            conn.close()

    def get_unenriched_ips(self, limit=10):
        """Fetches IPs that haven't been enriched yet, prioritized by recent activity."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            # Priority: Most recently seen first
            c.execute(
                "SELECT ip FROM ip_intelligence WHERE enriched = 0 ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            )
            # Only need list of IP strings
            return [row[0] for row in c.fetchall()]
        except Exception as e:
            log.error(f"[DB] Error fetching unenriched IPs: {e}")
            return []
        finally:
            conn.close()

    def save_ip_intelligence(self, ip, intel_data):
        """Saves enriched data for an IP."""
        conn = self._get_conn()
        try:
            # intel_data is a dict with keys matching columns + 'raw_data'
            conn.execute(
                """
                UPDATE ip_intelligence 
                SET hostname=?, city=?, country=?, isp=?, org=?, asn=?, network_type=?, raw_data=?, enriched=1
                WHERE ip=?
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
        except Exception as e:
            log.error(f"[DB] Error saving IP intelligence {ip}: {e}")
        finally:
            conn.close()

    def add_ip_abuse_tag(self, ip, tag):
        """Adds an abuse tag to the IP's profile (e.g. 'BruteForce', 'Malware')."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute("SELECT abuse_tags FROM ip_intelligence WHERE ip = ?", (ip,))
            row = c.fetchone()
            if not row:
                # Create rudimentary entry if missing
                self.log_ip_visit(ip)
                current_tags = []
            else:
                try:
                    current_tags = json.loads(row[0]) if row[0] else []
                except:
                    current_tags = []

            if tag not in current_tags:
                current_tags.append(tag)
                conn.execute(
                    "UPDATE ip_intelligence SET abuse_tags = ? WHERE ip = ?",
                    (json.dumps(current_tags), ip),
                )
                conn.commit()
        except Exception as e:
            log.error(f"[DB] Error tagging abuse for {ip}: {e}")
        finally:
            conn.close()

            conn.close()

    def scan_and_repair_corruption(self, ip, username):
        """
        Scans User Filesystem for entries where a FILE overwrites a known DIRECTORY from Global/Skeleton layers.
        Deletes the corrupt file entry if found.
        """
        conn = self._get_conn()
        try:
            c = conn.cursor()
            # Find User Files that might be directories
            c.execute(
                "SELECT path, content FROM user_filesystem WHERE ip=? AND username=? AND type='file' AND is_deleted=0",
                (ip, username),
            )
            candidates = c.fetchall()

            home_dir = "/root" if username == "root" else f"/home/{username}"
            repaired_count = 0

            for path, content in candidates:
                # Check if this path IS a directory in Skeleton
                is_skel_dir = False
                for item in self.skeleton_cache:
                    skel_path = item["path"]
                    if skel_path.startswith("~"):
                        skel_path = skel_path.replace("~", home_dir, 1)
                    if skel_path == path and item["type"] == "directory":
                        is_skel_dir = True
                        break

                # Also check Global FS if needed (less likely for user pollution but possible)
                is_global_dir = False
                if not is_skel_dir:
                    node = self.get_fs_node(path)
                    if node and node["type"] == "directory":
                        is_global_dir = True

                if is_skel_dir or is_global_dir:
                    # HEURISTIC: Check if content looks like an error message
                    # Or just Nuke it because it shouldn't be a file shadowing a dir regardless of content?
                    # Safer to nuke it.
                    log.warning(
                        f"[FS Repair] Found corrupt FILE '{path}' shadowing a directory. Content: {str(content)[:50]}..."
                    )
                    c.execute(
                        "DELETE FROM user_filesystem WHERE ip=? AND username=? AND path=?",
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
        """Returns aggregate server statistics."""
        conn = self._get_conn()
        stats = {"sessions": 0, "total_commands": 0}
        try:
            c = conn.cursor()
            c.execute("SELECT count(*) FROM sessions")
            row = c.fetchone()
            if row:
                stats["sessions"] = row[0]

            c.execute("SELECT count(distinct remote_ip) FROM sessions")
            row = c.fetchone()
            if row:
                stats["unique_ips"] = row[0]

            c.execute("SELECT count(*) FROM interactions")
            row = c.fetchone()
            if row:
                stats["total_commands"] = row[0]
        except Exception as e:
            log.error(f"Error fetching global stats: {e}")
        finally:
            conn.close()
        return stats

    def get_active_sessions(self):
        """
        Returns a list of currently active sessions (end_time is NULL).
        Used for 'who' and 'w' commands.
        """
        conn = self._get_conn()
        sessions = []
        try:
            c = conn.cursor()
            # We treat any session without end_time as active.
            # In a real honeypot, we might want to filter out stale ones,
            # but for 'who' realism, showing what the DB thinks is active is correct.
            c.execute(
                """
                SELECT username, remote_ip, start_time, session_id 
                FROM sessions 
                WHERE end_time IS NULL
                ORDER BY start_time ASC
            """
            )
            rows = c.fetchall()
            for r in rows:
                sessions.append(
                    {
                        "user": r[0],
                        "ip": r[1],
                        "start_time": r[2],  # ISO 8601 string likely
                        "session_id": r[3],
                        # Simulate TTY based on session ID hash to be deterministic but varied
                        "tty": f"pts/{int(hashlib.md5(r[3].encode()).hexdigest(), 16) % 10}",
                    }
                )
        except Exception as e:
            log.error(f"[DB] Error fetching active sessions: {e}")
        finally:
            conn.close()
        return sessions

    def get_unique_creds_last_24h(self, ip):
        """
        Returns a list of (username, password) tuples that were successfully used
        by this IP in the last 24 hours.
        """
        conn = self._get_conn()
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        c = conn.cursor()
        c.execute(
            """
            SELECT username, password 
            FROM sessions 
            WHERE remote_ip = ? AND start_time > ?
        """,
            (ip, cutoff),
        )
        rows = c.fetchall()
        conn.close()
        return list(set(rows))  # Deduplicate

    def validate_anti_harvesting(self, ip, username, password):
        """
        Validates login against anti-harvesting rules.
        Returns: (passed: bool, failure_reason: str)
        """
        # Test Mode Check
        if os.getenv("FAUXSSH_TEST_MODE"):
            # In test mode, use in-memory DB or special logic if needed
            # For now, just allow all in test mode.
            return True, None

        try:
            existing_creds = self.get_unique_creds_last_24h(ip)

            # Allow exactly same credentials if previously successful
            if (username, password) in existing_creds:
                return True, None

            unique_users = set(u for u, p in existing_creds)

            # Rule 1: No credential stuffing for same user (Known User, New Password)
            if username in unique_users:
                return (
                    False,
                    f"Anti-Harvesting: Blocked {ip} for user '{username}' (Known user, new password denied)",
                )

            count = len(unique_users)
            from .config import config
            import random

            max_auth = (
                config.get("persona", "access_control", "max_auth_tries_per_ip") or 5
            )

            # Rule 2: Hard Limit
            if count >= max_auth:
                return (
                    False,
                    f"Anti-Harvesting: Blocked {ip} for user '{username}' (Limit Reached: {count})",
                )

            # Rule 3: Probabilistic Rejection
            prob = count / float(max_auth)
            if random.random() < prob:
                return (
                    False,
                    f"Anti-Harvesting: Randomly blocked {ip} for user '{username}' (Prob: {prob:.2f})",
                )

            return True, None

        except Exception as e:
            log.error(f"[!] Anti-Harvesting Check Error: {e}")
            return True, None

    def check_root_desperation(self, ip):
        """
        Checks for 'Root Desperation' scenario (SSH ONLY).
        Returns:
            - 'BLOCK': If IP has successful non-root login (SSH).
            - 'ALLOW': If IP has exactly 2 failed root attempts (SSH) and no successes.
            - 'NORMAL': Otherwise.
        """
        conn = self._get_conn()
        try:
            c = conn.cursor()

            # Check for ANY successful non-root login via SSH
            # We treat any success as "competence" or "intent" that disqualifies desperation
            c.execute(
                "SELECT count(*) FROM auth_events WHERE client_ip = ? AND success = 1 AND username != 'root' AND protocol = 'ssh'",
                (ip,),
            )
            if c.fetchone()[0] > 0:
                return "BLOCK"

            # Check for failed root attempts via SSH
            # We want to enable on the 3rd attempt, so we look for exactly 2 failures
            c.execute(
                "SELECT count(*) FROM auth_events WHERE client_ip = ? AND username = 'root' AND success = 0 AND protocol = 'ssh'",
                (ip,),
            )
            failures = c.fetchone()[0]

            # Also ensure no root successes yet? (Implicitly covered by logic, but good safeguards)
            c.execute(
                "SELECT count(*) FROM auth_events WHERE client_ip = ? AND username = 'root' AND success = 1 AND protocol = 'ssh'",
                (ip,),
            )
            root_successes = c.fetchone()[0]

            if failures == 2 and root_successes == 0:
                return "ALLOW"

            return "NORMAL"

        except Exception as e:
            log.error(f"[DB] Desperation Check Error: {e}")
            return "NORMAL"
        finally:
            conn.close()  # Fail open

    def get_recent_sessions(self, limit=20, protocol=None):
        """
        Returns recent sessions for 'last' command.
        protocol: Optional filter. If provided, filters session types.
        """
        conn = self._get_conn()
        sessions = []
        try:
            c = conn.cursor()
            query = """
                SELECT username, remote_ip, start_time, end_time, session_id, protocol, summary, risk_score 
                FROM sessions 
            """
            params = []

            if protocol:
                query += " WHERE protocol = ? "
                params.append(protocol)

            query += " ORDER BY start_time DESC LIMIT ? "
            params.append(limit)

            c.execute(query, tuple(params))
            rows = c.fetchall()
            for r in rows:
                sessions.append(
                    {
                        "user": r[0],
                        "ip": r[1],
                        "start_time": r[2],
                        "end_time": r[3],
                        "session_id": r[4],
                        "tty": f"pts/{int(hashlib.md5(r[4].encode()).hexdigest(), 16) % 10}",
                        "protocol": r[5],
                        "summary": r[6],
                        "risk_score": r[7],
                    }
                )
        except Exception as e:
            log.error(f"[DB] Error fetching recent sessions: {e}")
        finally:
            conn.close()
        return sessions

    # --- Session Summary & Caching Methods ---
    def get_session_interactions(self, session_id):
        """Returns ordered list of input commands for a session."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT command FROM interactions WHERE session_id=? ORDER BY id ASC",
                (session_id,),
            )
            return [r[0] for r in c.fetchall()]
        finally:
            conn.close()

    def get_cached_session_summary(self, chain_hash):
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT summary, risk_score FROM session_summaries_cache WHERE chain_hash=?",
                (chain_hash,),
            )
            return c.fetchone()
        finally:
            conn.close()

    def save_session_summary_cache(self, chain_hash, summary, risk_score):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO session_summaries_cache (chain_hash, summary, risk_score)
                VALUES (?, ?, ?)
            """,
                (chain_hash, summary, risk_score),
            )
            conn.commit()
        finally:
            conn.close()

    def update_session_summary(self, session_id, summary, risk_score):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                UPDATE sessions SET summary=?, risk_score=? WHERE session_id=?
            """,
                (summary, risk_score, session_id),
            )
            conn.commit()
        finally:
            conn.close()

    def sanitize_artifacts(self):
        """
        Automatically removes artifact files (filenames starting with '-') from both
        User and Global filesystems.
        Returns: Tuple (deleted_user_files, deleted_global_files)
        """
        conn = self._get_conn()
        deleted_user = 0
        deleted_global = 0
        try:
            c = conn.cursor()

            # 1. User Filesystem
            c.execute("SELECT ip, username, path FROM user_filesystem")
            rows = c.fetchall()
            for r in rows:
                if os.path.basename(r[2]).startswith("-"):
                    c.execute(
                        "DELETE FROM user_filesystem WHERE ip=? AND username=? AND path=?",
                        r,
                    )
                    deleted_user += 1

            # 2. Global Filesystem
            c.execute("SELECT path FROM global_filesystem")
            rows = c.fetchall()
            for r in rows:
                if os.path.basename(r[0]).startswith("-"):
                    c.execute("DELETE FROM global_filesystem WHERE path=?", (r[0],))
                    deleted_global += 1

            # 3. Clean Polluted /home/ from Global Filesystem (Migration Fix)
            c.execute("DELETE FROM global_filesystem WHERE path LIKE '/home/%'")
            deleted_home_pollution = c.rowcount
            if deleted_home_pollution > 0:
                log.info(
                    f"[DB] Cleaned {deleted_home_pollution} polluted user files from Global FS"
                )

            conn.commit()
            if deleted_user or deleted_global:
                log.info(
                    f"[DB] Auto-Sanitized Artifacts: {deleted_user} User, {deleted_global} Global"
                )
        except Exception as e:
            log.error(f"[DB] Error sanitizing artifacts: {e}")
        finally:
            conn.close()
        return (deleted_user, deleted_global)

    def is_path_deleted(self, ip, username, path):
        """Checks if a path has a tombstone (is_deleted=1) in the User DB."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT is_deleted FROM user_filesystem WHERE ip=? AND username=? AND path=?",
                (ip, username, path),
            )
            row = c.fetchone()
            if row and row[0]:
                return True
        except Exception:
            pass
        finally:
            conn.close()
        return False

    def _ensure_parent_dirs(self, conn, ip, username, path):
        """
        Recursively ensures that 'path' and all its parents exist as directories in user_filesystem.
        """
        if not path or path == "/" or path == ".":
            return

        # Check if exists and status
        c = conn.cursor()
        c.execute(
            "SELECT is_deleted FROM user_filesystem WHERE ip=? AND username=? AND path=?",
            (ip, username, path),
        )
        row = c.fetchone()
        if row:
            if row[0]:  # is_deleted == 1
                # Revive it
                c.execute(
                    "UPDATE user_filesystem SET is_deleted=0 WHERE ip=? AND username=? AND path=?",
                    (ip, username, path),
                )
                conn.commit()
            return  # Exists (now active)

        # Does not exist, create it
        parent_path = os.path.dirname(path)

        # Ensure parent exists first (recursion)
        self._ensure_parent_dirs(conn, ip, username, parent_path)

        # Create this directory
        now = datetime.datetime.now().strftime("%b %d %H:%M")
        meta = {
            "permissions": "drwxr-xr-x",  # Default dir perms
            "size": 4096,
            "owner": username,
            "group": username,
            "modified": now,
        }

        try:
            c.execute(
                """
                INSERT OR IGNORE INTO user_filesystem (ip, username, path, parent_path, type, metadata, content)
                VALUES (?, ?, ?, ?, 'directory', ?, NULL)
            """,
                (ip, username, path, parent_path, json.dumps(meta)),
            )
        except Exception as e:
            log.error(f"[DB] Error creating parent dir {path}: {e}")

    def get_unique_creds_last_24h(self, ip):
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        conn = self._get_conn()
        c = conn.cursor()
        creds = set()

        try:
            c.execute(
                "SELECT username, password FROM sessions WHERE remote_ip = ? AND start_time > ?",
                (ip, cutoff),
            )
            for row in c.fetchall():
                creds.add((row[0], row[1]))
        except Exception as e:
            log.error(f"Error querying sessions for creds: {e}")

        try:
            c.execute(
                "SELECT username, auth_data FROM auth_events WHERE client_ip = ? AND success = 1 AND auth_method='password' AND timestamp > ?",
                (ip, cutoff),
            )
            for row in c.fetchall():
                creds.add((row[0], row[1]))
        except Exception as e:
            log.error(f"Error querying auth_events for creds: {e}")

        conn.close()
        return creds

    def get_unanalyzed_commands(self, limit=10):
        """
        Returns distinct commands (hash, text, session_id, ip) from interactions that are NOT in command_analysis.
        Prioritizes most recent commands (by ID).
        """
        conn = self._get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        query = """
            SELECT i.request_md5, i.command, i.session_id, s.remote_ip
            FROM interactions i
            JOIN sessions s ON i.session_id = s.session_id
            WHERE i.request_md5 IS NOT NULL 
              AND i.request_md5 != 'unknown'
              AND i.request_md5 NOT IN (SELECT command_hash FROM command_analysis)
            GROUP BY i.request_md5
            ORDER BY MAX(i.id) DESC
            LIMIT ?
        """
        c.execute(query, (limit,))
        results = [dict(row) for row in c.fetchall()]
        conn.close()
        return results

    def save_analysis(self, cmd_hash, cmd_text, analysis):
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO command_analysis 
                (command_hash, command_text, activity_type, stage, risk_score, explanation)
                VALUES (?, ?, ?, ?, ?, ?)
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
            log.error(f"[DB] Error saving analysis: {e}")
        finally:
            conn.close()

    def get_analysis(self, cmd_hash):
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM command_analysis WHERE command_hash = ?", (cmd_hash,))
        row = c.fetchone()
        conn.close()
        if row:
            columns = [col[0] for col in c.description]
            result = dict(zip(columns, row))
            # Map legacy positional to dict keys if needed, but explicit dict is better
            return {
                "hash": row[0],
                "text": row[1],
                "type": row[2],
                "stage": row[3],
                "risk": row[4],
                "explanation": row[5],
                "analyzed_at": row[6],
            }
        return None

    def inspect_path(self, ip, username, path):
        """
        Debug method to inspect filesystem layers for a path across all layers.
        Returns a detailed string report.
        """
        report = []
        report.append(f"--- VFS Inspection Report for '{path}' ---")
        report.append(f"Context: IP={ip}, User={username}")

        # 1. User DB (Modifications)
        conn = self._get_conn()
        c = conn.cursor()
        c.execute(
            "SELECT * FROM user_filesystem WHERE ip=? AND username=? AND path=?",
            (ip, username, path),
        )
        row = c.fetchone()
        conn.close()

        if row:
            # is_deleted index 9 (based on schema)
            is_deleted = row[9] if len(row) > 9 else 0
            status = "DELETED (Tombstone)" if is_deleted else "ACTIVE"
            report.append(f"[LAYER 1 - User DB] FOUND: {status}")
            report.append(f"  Type: {row[4]}")
            report.append(f"  Metadata: {row[5]}")
            report.append(f"  Content Len: {len(row[6]) if row[6] else 0}")
        else:
            report.append("[LAYER 1 - User DB] NOT FOUND")

        # 2. Skeleton
        home_dir = "/root" if username == "root" else f"/home/{username}"
        found_skel = False
        for item in self.skeleton_cache:
            skel_path = item["path"]
            if skel_path.startswith("~"):
                resolved_path = skel_path.replace("~", home_dir, 1)
            else:
                resolved_path = skel_path

            if resolved_path == path:
                report.append(f"[LAYER 2 - Skeleton] FOUND: ACTIVE (COW Base)")
                report.append(f"  Original Path: {skel_path}")
                report.append(f"  Type: {item['type']}")
                found_skel = True
                break
        if not found_skel:
            report.append("[LAYER 2 - Skeleton] NOT FOUND")

        # 3. Global DB
        node = self.get_fs_node(path)
        if node:
            report.append(f"[LAYER 3 - Global DB] FOUND: ACTIVE")
            report.append(f"  Type: {node['type']}")
        else:
            report.append("[LAYER 3 - Global DB] NOT FOUND")

        # Conclusion
        final = self.get_user_node(ip, username, path)
        if final:
            report.append(f"==> RESOLVED: VISIBLE (Type: {final['type']})")
        else:
            report.append("==> RESOLVED: NOT VISIBLE")

        return "\n".join(report)

    def inspect_dir(self, ip, username, directory):
        """
        Debug method to list all potential files in a directory from all layers.
        """
        report = []
        if not directory:
            directory = "/"

        report.append(f"--- VFS Directory Inspection for '{directory}' ---")

        # 1. User Local Files
        conn = self._get_conn()
        c = conn.cursor()
        c.execute(
            "SELECT path, is_deleted FROM user_filesystem WHERE ip=? AND username=? AND parent_path=?",
            (ip, username, directory),
        )
        user_files = {os.path.basename(r[0]): r[1] for r in c.fetchall()}
        conn.close()

        # 2. Skeleton Files
        skel_files = set()
        home_dir = "/root" if username == "root" else f"/home/{username}"
        for item in self.skeleton_cache:
            skel_path = item["path"]
            if skel_path.startswith("~"):
                resolved_path = skel_path.replace("~", home_dir, 1)
            else:
                resolved_path = skel_path

            if os.path.dirname(resolved_path) == directory:
                skel_files.add(os.path.basename(resolved_path))

        # 3. Global Files
        global_files = set()
        g_list = self.list_fs_dir(directory)
        for g in g_list:
            global_files.add(os.path.basename(g["path"]))

        # Merge Keys
        all_names = set(user_files.keys()) | skel_files | global_files

        if not all_names:
            report.append("(Empty Directory)")
            return "\n".join(report)

        report.append(
            f"{'Filename':<30} | {'GlobalFS':<10} | {'Skeleton':<10} | {'TempFS':<10} | {'Result':<10}"
        )
        report.append("-" * 85)

        for name in sorted(all_names):
            user_status = "---"
            if name in user_files:
                user_status = "DELETED" if user_files[name] else "ACTIVE"

            skel_status = "YES" if name in skel_files else "---"
            global_status = "YES" if name in global_files else "---"

            # Logic
            result = "VISIBLE"
            if user_status == "DELETED":
                result = "HIDDEN"
            elif (
                user_status == "---" and skel_status == "---" and global_status == "---"
            ):
                # Should not happen as name came from one of them
                result = "ERROR"

            report.append(
                f"{name:<30} | {global_status:<10} | {skel_status:<10} | {user_status:<10} | {result:<10}"
            )

        return "\n".join(report)

    # --- Malicious Payload Methods (Jan 10) ---
    def add_malicious_payload(self, url, url_hash, session_id, ip, timestamp=None):
        conn = self._get_conn()
        try:
            ts = timestamp or datetime.datetime.now()
            conn.execute(
                """
                INSERT INTO malicious_payloads (url, url_hash, session_id, ip, timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (url, url_hash, session_id, ip, ts, "pending"),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Already exists distinct by url_hash
        except Exception as e:
            log.error(f"[DB] Error adding payload: {e}")
        finally:
            conn.close()

    def get_payload_by_hash(self, url_hash):
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM malicious_payloads WHERE url_hash = ?", (url_hash,)
            )
            return cur.fetchone()
        finally:
            conn.close()

    def get_pending_payloads(self, limit=5):
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Prioritize oldest pending
            cur.execute(
                "SELECT * FROM malicious_payloads WHERE status = 'pending' ORDER BY timestamp ASC LIMIT ?",
                (limit,),
            )
            # Convert to dicts
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def update_payload_status(
        self,
        payload_id,
        status,
        payload_md5=None,
        payload_size=None,
        file_path=None,
        error=None,
    ):
        conn = self._get_conn()
        try:
            sql = "UPDATE malicious_payloads SET status = ?"
            params = [status]

            if payload_md5:
                sql += ", payload_md5 = ?"
                params.append(payload_md5)
            if payload_size is not None:
                sql += ", payload_size = ?"
                params.append(payload_size)
            if file_path:
                sql += ", file_path = ?"
                params.append(file_path)
            if error:
                sql += ", error_message = ?"
                params.append(error)

            sql += " WHERE id = ?"
            params.append(payload_id)

            conn.execute(sql, params)
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error updating payload status: {e}")
        finally:
            conn.close()

    def is_payload_host_rate_limited(self, hostname):
        """
        Check if we have already queued/downloaded a URL from this hostname in the last 24 hours.
        """
        conn = self._get_conn()
        try:
            # Check for any entry from this host in last 24h
            # Since we store full URL, we key off the URL string matching hostname...
            # SQL LIKE is easiest: http://hostname/... or https://hostname/...
            # This is imperfect but functional for simple detection.
            one_day_ago = datetime.datetime.now() - datetime.timedelta(days=1)

            # Simple heuristic: Look for match in URL field
            # Note: storing 'hostname' in DB would be cleaner for future, currently parsing URL via LIKE
            c = conn.cursor()
            c.execute(
                """
                SELECT count(*) FROM malicious_payloads 
                WHERE (url LIKE ? OR url LIKE ?) 
                AND timestamp > ?
            """,
                (f"%://{hostname}%", f"%://www.{hostname}%", one_day_ago),
            )

            count = c.fetchone()[0]
            return count > 0
        finally:
            conn.close()

    def get_interactions_with_http(self):
        """Fetches interactions containing 'http' along with remote_ip from sessions."""
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute(
                """
                SELECT i.session_id, i.command, i.timestamp, s.remote_ip 
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                WHERE i.command LIKE '%http%'
            """
            )
            return [dict(row) for row in c.fetchall()]
        finally:
            conn.close()

    def get_interactions_since_id(self, last_id, limit=100):
        """Fetches interactions newer than last_id for incremental scanning."""
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            # Only fetch fields needed for payload extraction
            c.execute(
                """
                SELECT i.id, i.session_id, i.command, i.timestamp, s.remote_ip 
                FROM interactions i
                LEFT JOIN sessions s ON i.session_id = s.session_id
                WHERE i.id > ? AND (i.command LIKE '%http%' OR i.command LIKE '%wget%' OR i.command LIKE '%curl%')
                ORDER BY i.id ASC
                LIMIT ?
            """,
                (last_id, limit),
            )
            return [dict(row) for row in c.fetchall()]
        finally:
            conn.close()

    def clear_cache(self):
        """
        Clears dynamic filesystem changes and sessions. Preserves system tables.
        """
        try:
            conn = self.get_connection()
            c = conn.cursor()

            # Wiping session data and dynamic filesystem changes
            tables = [
                "sessions",
                "interactions",
                "global_filesystem",
                "downloads",
                "session_summaries_cache",
                "ip_intelligence",
                "malicious_payloads",
            ]

            for table in tables:
                c.execute(f"DELETE FROM {table}")

            conn.commit()
            log.info("[HoneyDB] Cache and Session Data Cleared.")
        except Exception as e:
            log.error(f"[HoneyDB] Failed to clear cache: {e}")

    def get_session(self, session_id):
        """
        Retrieves full session info as a dict.
        """
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
            row = c.fetchone()
            if row:
                columns = [col[0] for col in c.description]
                return dict(zip(columns, row))
            return None
        finally:
            conn.close()

    def get_session_protocol(self, session_id):
        """
        Retrieves the protocol for a given session.
        Returns: str (e.g., 'ssh', 'http') or 'unknown'
        """
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT protocol FROM sessions WHERE session_id = ?",
                (session_id,),
            )
            row = c.fetchone()
            if row:
                return row[0]
            return "unknown"
        except Exception as e:
            log.error(f"[DB] Error getting session protocol: {e}")
            return "unknown"
        finally:
            conn.close()

    def get_next_payload_for_analysis(self):
        """Fetch one payload that hasn't been scanned by VT yet."""
        conn = self._get_conn()

        # We assume 'virustotal_result' is NULL for unanalyzed.
        # Also ensure status is 'completed' (we have the file).
        try:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute(
                """
                SELECT * FROM malicious_payloads 
                WHERE status = 'completed' 
                AND virustotal_result IS NULL
                ORDER BY timestamp ASC
                LIMIT 1
             """
            )
            row = c.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()

    def update_payload_vt_status(self, payload_id, result, scan_id=None):
        conn = self._get_conn()
        try:
            timestamp = datetime.datetime.now().isoformat()
            if scan_id:
                conn.execute(
                    "UPDATE malicious_payloads SET virustotal_result = ?, vt_last_scanned = ?, vt_scan_id = ? WHERE id = ?",
                    (result, timestamp, scan_id, payload_id),
                )
            else:
                conn.execute(
                    "UPDATE malicious_payloads SET virustotal_result = ?, vt_last_scanned = ? WHERE id = ?",
                    (result, timestamp, payload_id),
                )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error updating VT status: {e}")
        finally:
            conn.close()

    def iter_interactions(self, batch_size=1000):
        """
        Yields all interactions as dictionaries.
        Useful for exporting data.
        """
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM interactions ORDER BY timestamp ASC")
            while True:
                rows = cursor.fetchmany(batch_size)
                if not rows:
                    break
                for row in rows:
                    yield dict(row)
        except Exception as e:
            log.error(f"[DB] Error iterating interactions: {e}")
        finally:
            conn.close()

    def purge_poisoned_cache(self):
        """Purges cached responses containing AI Core error messages."""
        conn = self._get_conn()
        try:
            # Clear from command_cache
            conn.execute(
                "DELETE FROM command_cache WHERE response LIKE '%AI Core Offline%'"
            )
            # Clear from interactions
            conn.execute(
                "DELETE FROM interactions WHERE response LIKE '%AI Core Offline%'"
            )
            conn.commit()
            log.info("[SQLite] Purged poisoned cache entries.")
        except Exception as e:
            log.error(f"[SQLite] Error purging cache: {e}")
        finally:
            conn.close()

    def get_llm_response(self, prompt_hash):
        """Retrieves a cached LLM response by prompt hash if it exists and is fresh (30 days)."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            # Check if exists and is younger than 30 days
            c.execute(
                """
                SELECT response FROM llm_response_cache 
                WHERE prompt_hash = ? AND created_at > datetime('now', '-30 days')
                """,
                (prompt_hash,),
            )
            row = c.fetchone()
            return row[0] if row else None
        except Exception as e:
            log.error(f"[SQLite] Error getting LLM cache: {e}")
            return None
        finally:
            conn.close()

    def save_llm_response(self, prompt_hash, prompt_text, response):
        """Caches an LLM response."""
        conn = self._get_conn()
        try:
            # Use REPLACE to update timestamp if it already exists (though hash collision unlikely different prompt)
            # Actually, we should update updated_at if we overwrite.
            # But REPLACE deletes and inserts new row, so created_at resets to CURRENT_TIMESTAMP which is what we want (refresh TTL)
            conn.execute(
                """
                INSERT OR REPLACE INTO llm_response_cache (prompt_hash, prompt_text, response)
                VALUES (?, ?, ?)
                """,
                (prompt_hash, prompt_text, response),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[SQLite] Error saving LLM cache: {e}")
        finally:
            conn.close()


# Backward Compatibility
class HoneyDB(SQLiteBackend):
    pass


# Factory
_DB_INSTANCE = None


def get_db_backend():
    global _DB_INSTANCE
    if _DB_INSTANCE is not None:
        return _DB_INSTANCE

    # Avoid circular imports if possible, but standard import here is fine
    from ssh_honeypot.core.config import config

    db_type = config.get("database", "type")
    if not db_type:
        db_type = "sqlite"

    if db_type == "postgres":
        try:
            from .db_postgres import PostgresBackend

            pg_config = config.get("database", "postgres") or {}
            _DB_INSTANCE = PostgresBackend(pg_config)
            return _DB_INSTANCE
        except ImportError as e:
            # Fallback or error? For now error is better so user knows configs are wrong
            log.error(f"Failed to import PostgresBackend: {e}")
            raise e

    _DB_INSTANCE = SQLiteBackend()
    return _DB_INSTANCE
