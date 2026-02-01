import sqlite3
import datetime
import hashlib
import os
import json
import time

try:
    from .db_interface import DatabaseBackend
    from .logging_setup import log
    from .config import get_data_dir, config
    from .utils import sanitize_path
    from .db_utils import sync_db_schema
except ImportError:
    from db_interface import DatabaseBackend
    from ssh_honeypot.core.logging_setup import log
    from config_manager import get_data_dir
    from ssh_honeypot.core.utils import sanitize_path

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
                f"[Core] Loaded {len(self.skeleton_cache)} skeleton items (COW Layer)"
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

    @property
    def is_postgres(self):
        return False

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
        sync_db_schema(self)

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        # Enable WAL mode and performance optimizations
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 30000;")
        return conn

    def log_url_request(
        self,
        session_id,
        url,
        method="GET",
        user_agent=None,
        command_text=None,
        created_at=None,
    ):
        conn = self._get_conn()
        try:
            if created_at:
                conn.execute(
                    """
                    INSERT INTO requested_urls (timestamp, session_id, url, method, user_agent, command_text)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (created_at, session_id, url, method, user_agent, command_text),
                )
            else:
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
        created_at=None,
    ):
        conn = None
        try:
            fp_json = "{}"
            if fingerprint:
                fp_json = json.dumps(fingerprint)

            conn = self._get_conn()
            c = conn.cursor()
            if created_at:
                c.execute(
                    """
                    INSERT INTO auth_events (timestamp, client_ip, username, auth_method, auth_data, success, client_version, fingerprint, protocol)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        created_at,
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
            else:
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
        created_at=None,
    ):
        if not request_md5 and command:
            request_md5 = hashlib.md5(command.encode("utf-8")).hexdigest()

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

        # Global Sanitization: Mask internal paths
        command = sanitize_path(command)
        response = sanitize_path(response)

        conn = self._get_conn()
        try:
            if created_at:
                conn.execute(
                    """
                    INSERT INTO interactions 
                    (timestamp, session_id, cwd, command, response, source, request_md5, response_md5, response_head, response_size, duration_ms) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        created_at,
                        session_id,
                        cwd,
                        command,
                        response,
                        source,
                        request_md5,
                        response_md5,
                        response_head,
                        response_size,
                        duration_ms,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO interactions 
                    (session_id, cwd, command, response, source, request_md5, response_md5, response_head, response_size, duration_ms) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        duration_ms,
                    ),
                )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error logging interaction: {e}")
        finally:
            conn.close()

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

    # Removed get_cached_response (Deprecated in favor of UniversalCache)

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
        self.batch_update_fs_nodes(
            [
                {
                    "path": path,
                    "parent_path": parent_path,
                    "type": type,
                    "metadata": metadata,
                    "content": content,
                }
            ]
        )

    def batch_update_fs_nodes(self, nodes):
        """
        Batch updates/inserts filesystem nodes for performance.
        'nodes' is a list of dicts with keys: path, parent_path, type, metadata, content
        """
        conn = self._get_conn()
        try:
            prepared_data = []
            for node in nodes:
                content = node.get("content")
                if isinstance(content, (dict, list)):
                    content = str(content)

                metadata = node.get("metadata")
                if isinstance(metadata, dict):
                    metadata = json.dumps(metadata)

                prepared_data.append(
                    (
                        node["path"],
                        node.get("parent_path"),
                        node["type"],
                        metadata,
                        content,
                    )
                )

            conn.executemany(
                """
                INSERT OR REPLACE INTO global_filesystem (path, parent_path, type, metadata, content)
                VALUES (?, ?, ?, ?, ?)
                """,
                prepared_data,
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

    def record_api_usage(self, service, identifier="GLOBAL"):
        """Records usage of an external API."""
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT INTO api_usage (service, identifier) VALUES (?, ?)",
                (service, identifier),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error recording API usage ({service}): {e}")
        finally:
            conn.close()

    def check_api_rate_limit(
        self, service, identifier, rpm_limit, rph_limit, rpd_limit
    ):
        """
        Generic rate limit checker for any service/identifier.
        Returns (allowed: bool, reason: str)
        """
        # Block caching
        cache_key = f"api_block:{service}:{identifier}"
        # We need a check in the cache specifically for this key prefix
        if cache and cache.is_blocked(identifier, cache_key):
            return False, f"Rate Limit Exceeded (Cached: {service})"

        conn = self._get_conn()
        try:
            c = conn.cursor()

            # Check RPM
            c.execute(
                "SELECT COUNT(*) FROM api_usage WHERE service = ? AND identifier = ? AND timestamp > datetime('now', '-60 seconds')",
                (service, identifier),
            )
            rpm_count = c.fetchone()[0]
            if rpm_count >= rpm_limit:
                if cache:
                    cache.set_block(identifier, cache_key, ttl=60)
                return False, f"RPM Limit Exceeded ({service}: {rpm_count}/{rpm_limit})"

            # Check RPH
            c.execute(
                "SELECT COUNT(*) FROM api_usage WHERE service = ? AND identifier = ? AND timestamp > datetime('now', '-1 hour')",
                (service, identifier),
            )
            rph_count = c.fetchone()[0]
            if rph_count >= rph_limit:
                if cache:
                    cache.set_block(identifier, cache_key, ttl=3600)
                return False, f"RPH Limit Exceeded ({service}: {rph_count}/{rph_limit})"

            # Check RPD
            c.execute(
                "SELECT COUNT(*) FROM api_usage WHERE service = ? AND identifier = ? AND timestamp > datetime('now', '-24 hours')",
                (service, identifier),
            )
            rpd_count = c.fetchone()[0]
            if rpd_count >= rpd_limit:
                if cache:
                    cache.set_block(identifier, cache_key, ttl=86400)
                return False, f"RPD Limit Exceeded ({service}: {rpd_count}/{rpd_limit})"

            return True, "OK"
        except Exception as e:
            log.error(f"[DB] Error checking API limits for {service}: {e}")
            return True, "Error check failed (Fail Open)"
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

        if path == home_dir:
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

    def log_ip_visit(self, ip, created_at=None):
        """Records an IP visit. Inserts new record or updates last_seen."""
        conn = self._get_conn()
        try:
            if created_at:
                conn.execute(
                    """
                    INSERT INTO ip_intelligence (ip, first_seen, last_seen, enriched)
                    VALUES (?, ?, ?, 0)
                    ON CONFLICT(ip) DO UPDATE SET last_seen = ?
                """,
                    (ip, created_at, created_at, created_at),
                )
            else:
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

    def get_infographic_stats(self, hours=24, ignore_ips=None):
        """Returns complex stats for the infographic dashboard."""
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
            "manual_vs_bot": {"manual": 0, "bot": 0},
            "recent_unique_commands": [],
            "top_ssh_commands": [],
            "top_telnet_commands": [],
            "top_mysql_commands": [],
            "top_http_commands": [],  # Added HTTP
            "top_redis_commands": [],
            "top_mcp_commands": [],
            "top_llm_models": [],  # Added LLM
            "top_llm_endpoints": [],  # Added LLM
            "top_passwords": [],
            "top_ssh_users": [],
            "top_ssh_risk": [],
            "total_payloads": 0,
            "protocol_activity": {},  # For sorting in UI
            "multi_window": {},  # Added for 24H, 48H, 1W, 2W
        }
        try:
            c = conn.cursor()
            time_filter = f"datetime('now', '-{hours} hours')"
            prev_time_filter = f"datetime('now', '-{hours*2} hours')"

            # IP Exclusion Filter
            ip_filter = ""
            params = []
            if ignore_ips:
                placeholders = ",".join(["?" for _ in ignore_ips])
                ip_filter = f"AND remote_ip NOT IN ({placeholders})"
                params = list(ignore_ips)

            # Helper for interactions (needs join with sessions to check remote_ip)
            interaction_ip_filter = ""
            if ignore_ips:
                placeholders = ",".join(["?" for _ in ignore_ips])
                interaction_ip_filter = f"AND s.remote_ip NOT IN ({placeholders})"

            # --- TOTALS & TRENDS ---
            def get_window_stats(start, end=None):
                e_part = f" AND start_time <= {end}" if end else ""
                c.execute(
                    f"SELECT COUNT(DISTINCT remote_ip), COUNT(*) FROM sessions WHERE start_time > {start} {e_part} {ip_filter}",
                    params,
                )
                ips, sessions = c.fetchone()

                ei_part = f" AND i.timestamp <= {end}" if end else ""
                c.execute(
                    f"""
                    SELECT COUNT(*) FROM interactions i
                    JOIN sessions s ON i.session_id = s.session_id
                    WHERE i.timestamp > {start} {ei_part} {interaction_ip_filter}
                """,
                    params,
                )
                commands = c.fetchone()[0] or 0

                # Count unique networks (ORGs)
                c.execute(
                    f"""
                    SELECT COUNT(DISTINCT intel.org) 
                    FROM sessions s
                    JOIN ip_intelligence intel ON s.remote_ip = intel.ip
                    WHERE s.start_time > {start} {e_part} {ip_filter}
                """,
                    params,
                )
                networks = c.fetchone()[0] or 0

                return {
                    "ips": ips or 0,
                    "sessions": sessions or 0,
                    "commands": commands,
                    "networks": networks,
                }

            # Multi-window Metrics (Task 3)
            windows = {"24H": 24, "48H": 48, "1W": 168, "2W": 336}
            for label, h in windows.items():
                w_filter = f"datetime('now', '-{h} hours')"
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

            # Total Payloads (Captured in last 24h)
            query = f"SELECT COUNT(*) FROM malicious_payloads WHERE timestamp > {time_filter}"
            c.execute(query)
            stats["total_payloads"] = c.fetchone()[0] or 0

            # --- PROTOCOL DISTRIBUTION ---
            query = f"""
                SELECT s.protocol, COUNT(DISTINCT s.session_id) as sess_count, COUNT(i.id) as cmd_count
                FROM sessions s
                LEFT JOIN interactions i ON s.session_id = i.session_id
                WHERE s.start_time > {time_filter} {ip_filter}
                GROUP BY s.protocol
                ORDER BY sess_count DESC
            """
            c.execute(query, params)
            for r in c.fetchall():
                proto = r[0]
                stats["service_dist"].append(
                    {"protocol": proto, "sessions": r[1], "commands": r[2]}
                )
                stats["protocol_activity"][proto] = r[
                    2
                ]  # Use command count for activity sorting

            # --- LLM ANALYTICS (Python-side Processing for robustness) ---
            # Fetch raw commands for 'llm-api'
            llm_query = f"""
                SELECT command FROM interactions 
                WHERE source = 'llm-api' AND timestamp > {time_filter}
            """
            c.execute(llm_query)
            llm_rows = c.fetchall()

            if llm_rows:
                from collections import Counter
                import json

                model_counts = Counter()
                endpoint_counts = Counter()

                for (cmd_text,) in llm_rows:
                    if not cmd_text:
                        continue

                    parts = cmd_text.split("\n", 1)
                    endpoint = parts[0].strip()
                    endpoint_counts[endpoint] += 1

                    if len(parts) > 1:
                        try:
                            payload = json.loads(parts[1])
                            model = payload.get("model", "unknown")
                            model_counts[model] += 1
                        except:
                            pass

                # Format for Chart.js/Table
                stats["top_llm_models"] = [
                    {"item": k, "count": v} for k, v in model_counts.most_common(10)
                ]
                stats["top_llm_endpoints"] = [
                    {"item": k, "count": v} for k, v in endpoint_counts.most_common(10)
                ]

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
            c.execute(query, params)
            stats["top_countries"] = [
                {"country": r[0] or "Unknown", "ips": r[1], "sessions": r[2]}
                for r in c.fetchall()
            ]

            # Top ISPs / Networks (Unique IPs and Sessions)
            query = f"""
                SELECT intel.org, intel.asn, COUNT(DISTINCT s.remote_ip) as unique_ips, COUNT(DISTINCT s.session_id) as sessions
                FROM sessions s 
                JOIN ip_intelligence intel ON s.remote_ip = intel.ip 
                WHERE s.start_time > {time_filter} {interaction_ip_filter}
                GROUP BY intel.org, intel.asn 
                ORDER BY unique_ips DESC LIMIT 50
            """
            c.execute(query, params)
            stats["top_isps"] = [
                {
                    "isp": r[0] or "Unknown",
                    "asn": r[1] or "-",
                    "ips": r[2],
                    "sessions": r[3],
                }
                for r in c.fetchall()
            ]

            # Top SSH Users
            query = f"""
                SELECT username, COUNT(*) as count, COUNT(DISTINCT remote_ip) as unique_ips
                FROM sessions 
                WHERE start_time > {time_filter} AND protocol = 'ssh' AND username IS NOT NULL AND username != '' {ip_filter}
                GROUP BY username 
                ORDER BY count DESC LIMIT 50
            """
            c.execute(query, params)
            stats["top_ssh_users"] = [
                {"username": r[0], "count": r[1], "ips": r[2]} for r in c.fetchall()
            ]

            # Top Passwords
            query = f"""
                SELECT password, COUNT(*) as count, COUNT(DISTINCT remote_ip) as unique_ips
                FROM sessions 
                WHERE start_time > {time_filter} AND protocol = 'ssh' AND password IS NOT NULL AND password != '' {ip_filter}
                GROUP BY password 
                ORDER BY count DESC LIMIT 50
            """
            c.execute(query, params)
            stats["top_passwords"] = [
                {"password": r[0], "count": r[1], "ips": r[2]} for r in c.fetchall()
            ]

            # Generic Top Command Fetcher
            def get_top_commands(proto, limit=50):
                q = f"""
                    SELECT i.command, COUNT(*) as count, COUNT(DISTINCT s.remote_ip) as unique_ips,
                           SUBSTR(MAX(i.response), 1, 1000) as sample_response
                    FROM interactions i
                    JOIN sessions s ON i.session_id = s.session_id
                    WHERE i.timestamp > {time_filter} AND s.protocol = ? {interaction_ip_filter}
                    GROUP BY i.command 
                    ORDER BY unique_ips DESC, count DESC LIMIT ?
                """
                c.execute(q, [proto] + params + [limit])
                return [
                    {"command": r[0], "count": r[1], "ips": r[2], "response": r[3]}
                    for r in c.fetchall()
                ]

            stats["top_ssh_commands"] = get_top_commands("ssh")
            stats["top_telnet_commands"] = get_top_commands("telnet")
            stats["top_mysql_commands"] = get_top_commands("mysql")
            stats["top_http_commands"] = get_top_commands("http")
            stats["top_redis_commands"] = get_top_commands("redis")
            stats["top_mcp_commands"] = get_top_commands("mcp")

            # --- KILL CHAIN STAGES (Approved Enhancement) ---
            query = f"""
                SELECT ca.stage, COUNT(*) as count, COUNT(DISTINCT s.remote_ip) as unique_ips
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE i.timestamp > {time_filter} {interaction_ip_filter}
                GROUP BY ca.stage
                ORDER BY count DESC
            """
            c.execute(query, params)
            stats["kill_chain"] = [
                {"stage": r[0], "count": r[1], "ips": r[2]} for r in c.fetchall()
            ]

            # Top SSH Commands by Risk (Freq and unique IP counts)
            # Improved sorting: Risk first, then unique IPs, then total count
            query = f"""
                SELECT i.command, COALESCE(MAX(ca.risk_score), 0) as max_risk, COUNT(*) as count, COUNT(DISTINCT s.remote_ip) as unique_ips,
                       SUBSTR(MAX(i.response), 1, 1000) as sample_response, MAX(i.session_id) as sample_session
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE i.timestamp > {time_filter} AND s.protocol = 'ssh' {interaction_ip_filter}
                GROUP BY i.command
                ORDER BY max_risk DESC, unique_ips DESC, count DESC
                LIMIT 50
            """
            c.execute(query, params)
            stats["top_ssh_risk"] = [
                {
                    "command": r[0],
                    "risk": r[1],
                    "count": r[2],
                    "ips": r[3],
                    "response": r[4],
                    "session_id": r[5],
                }
                for r in c.fetchall()
            ]

            # Recent Unique Commands (for log scrolling effects)
            query = f"""
                SELECT DISTINCT i.command 
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                WHERE s.start_time > {time_filter} {interaction_ip_filter}
                ORDER BY i.timestamp DESC LIMIT 20
            """
            c.execute(query, params)
            stats["recent_unique_commands"] = [r[0] for r in c.fetchall()]

            # Manual vs Bot (Classification)
            query = f"""
                SELECT 
                    SUM(CASE WHEN command_count > 10 OR summary LIKE '%manual%' THEN 1 ELSE 0 END) as manual_count,
                    SUM(CASE WHEN command_count <= 10 AND (summary IS NULL OR summary NOT LIKE '%manual%') THEN 1 ELSE 0 END) as bot_count
                FROM (
                    SELECT s.session_id, s.summary, COUNT(i.id) as command_count
                    FROM sessions s
                    LEFT JOIN interactions i ON s.session_id = i.session_id
                    WHERE s.start_time > {time_filter} {interaction_ip_filter}
                    GROUP BY s.session_id
                )
            """
            c.execute(query, params)
            row = c.fetchone()
            if row:
                stats["manual_vs_bot"] = {"manual": row[0] or 0, "bot": row[1] or 0}

            # Top IPs Summary (for reference)
            query = f"""
                SELECT remote_ip, COUNT(*) as count 
                FROM sessions 
                WHERE start_time > {time_filter} {ip_filter}
                GROUP BY remote_ip 
                ORDER BY count DESC LIMIT 50
            """
            c.execute(query, params)
            stats["top_ips"] = [{"ip": r[0], "count": r[1]} for r in c.fetchall()]

        except Exception as e:
            log.error(f"[SQLite] Error fetching infographic stats: {e}")
        finally:
            conn.close()
        return stats

    def get_daily_session_counts(self, days=7):
        """Returns session counts for each of the last X days."""
        conn = self._get_conn()
        res = []
        try:
            c = conn.cursor()
            for i in range(days - 1, -1, -1):
                day_start = f"datetime('now', '-{i+1} days')"
                day_end = f"datetime('now', '-{i} days')"
                c.execute(
                    f"SELECT protocol, COUNT(*) FROM sessions WHERE start_time > {day_start} AND start_time <= {day_end} GROUP BY protocol"
                )
                protocol_counts = {r[0]: r[1] for r in c.fetchall()}
                count = sum(protocol_counts.values())

                # Get label like 'Jan 21'
                c.execute(f"SELECT strftime('%b %d', 'now', '-{i} days')")
                label = c.fetchone()[0]
                res.append(
                    {"label": label, "count": count, "protocols": protocol_counts}
                )
        except Exception as e:
            log.error(f"[SQLite] Error fetching daily session counts: {e}")
        finally:
            conn.close()
        return res

    def get_hourly_session_counts(self, hours=24):
        """Returns session counts for each of the last X hours."""
        conn = self._get_conn()
        res = []
        try:
            c = conn.cursor()
            for i in range(hours - 1, -1, -1):
                hour_start = f"datetime('now', '-{i+1} hours')"
                hour_end = f"datetime('now', '-{i} hours')"
                c.execute(
                    f"SELECT protocol, COUNT(*) FROM sessions WHERE start_time > {hour_start} AND start_time <= {hour_end} GROUP BY protocol"
                )
                protocol_counts = {r[0]: r[1] for r in c.fetchall()}
                count = sum(protocol_counts.values())

                # Get label like '14:00'
                c.execute(f"SELECT strftime('%H:%M', 'now', '-{i} hours')")
                label = c.fetchone()[0]
                res.append(
                    {"label": label, "count": count, "protocols": protocol_counts}
                )
        except Exception as e:
            log.error(f"[SQLite] Error fetching hourly session counts: {e}")
        finally:
            conn.close()
        return res

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

    def get_unanalyzed_commands(self, limit=10, allowed_protocols=None):
        """
        Returns distinct commands (hash, text, session_id, ip) from interactions that are:
        1. NOT in command_analysis (New)
        2. OR in command_analysis but older than 3 weeks (Re-analysis)
        Prioritizes most recent commands (by ID).
        """
        conn = self._get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        protocol_filter = ""
        params = []
        if allowed_protocols:
            placeholders = ",".join(["?"] * len(allowed_protocols))
            protocol_filter = f"AND s.protocol IN ({placeholders})"
            params.extend(allowed_protocols)

        # Updated query to include re-analysis of old commands (> 3 weeks)
        query = f"""
            SELECT i.request_md5, i.command, i.session_id, s.remote_ip, MAX(i.timestamp) as last_seen
            FROM interactions i
            JOIN sessions s ON i.session_id = s.session_id
            LEFT JOIN command_analysis ca ON i.request_md5 = ca.command_hash
            WHERE i.request_md5 IS NOT NULL 
              AND i.request_md5 != 'unknown'
              AND (ca.command_hash IS NULL OR ca.analyzed_at < datetime('now', '-21 days'))
              {protocol_filter}
            GROUP BY i.request_md5
            ORDER BY MAX(i.id) DESC
            LIMIT ?
        """
        params.append(limit)
        c.execute(query, tuple(params))
        results = [dict(row) for row in c.fetchall()]
        conn.close()
        return results

    def get_unanalyzed_sessions(self, limit=10):
        conn = self._get_conn()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT session_id FROM sessions WHERE (summary IS NULL OR summary = '') AND end_time IS NOT NULL ORDER BY start_time DESC LIMIT ?",
            (limit,),
        )
        sessions = [row["session_id"] for row in c.fetchall()]
        conn.close()
        return sessions

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
    def add_malicious_payload(
        self,
        url,
        url_hash,
        session_id,
        ip,
        timestamp=None,
        status="pending",
        payload_md5=None,
        payload_size=None,
        file_path=None,
        snippet=None,
        **kwargs,
    ):
        conn = self._get_conn()
        try:
            ts = timestamp or datetime.datetime.now()
            cursor = conn.cursor()

            # Global Sanitization
            url = sanitize_path(url)

            # 1. Insert/Get Payload ID
            cursor.execute(
                """
                INSERT INTO malicious_payloads (
                    url, url_hash, session_id, ip, timestamp, status,
                    payload_md5, payload_size, file_path, snippet
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (url_hash) DO UPDATE SET
                    payload_md5 = excluded.payload_md5,
                    payload_size = excluded.payload_size,
                    file_path = excluded.file_path,
                    snippet = excluded.snippet,
                    status = excluded.status
            """,
                (
                    url,
                    url_hash,
                    session_id,
                    ip,
                    ts,
                    status,
                    payload_md5,
                    payload_size,
                    file_path,
                    snippet,
                ),
            )

            # Fetch the ID (either newly inserted or existing)
            cursor.execute(
                "SELECT id FROM malicious_payloads WHERE url_hash = ?", (url_hash,)
            )
            row = cursor.fetchone()
            payload_id = row[0] if row else None

            # 2. Track Request (Always)
            if payload_id:
                cursor.execute(
                    """
                    INSERT INTO payload_requests (payload_id, ip, session_id, timestamp)
                    VALUES (?, ?, ?, ?)
                """,
                    (payload_id, ip, session_id, ts),
                )

            conn.commit()
            return True
        except Exception as e:
            log.error(f"[DB] Error adding payload: {e}")
            return False
        finally:
            conn.close()

    def batch_add_malicious_payloads(self, payload_list):
        """
        Batch adds multiple malicious payloads and their requests.
        'payload_list' is a list of dicts: url, url_hash, session_id, ip, timestamp
        """
        if not payload_list:
            return
        conn = self._get_conn()
        try:
            ts_default = datetime.datetime.now()
            # 1. Insert into malicious_payloads
            # We must include status='pending' to match single-insert behavior if needed
            payload_data = [
                (
                    sanitize_path(p["url"]),
                    p["url_hash"],
                    p["session_id"],
                    p["ip"],
                    p.get("timestamp") or ts_default,
                    "pending",
                )
                for p in payload_list
            ]

            cursor = conn.cursor()
            cursor.executemany(
                """
                INSERT INTO malicious_payloads (url, url_hash, session_id, ip, timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (url_hash) DO NOTHING
                """,
                payload_data,
            )

            # 2. Fetch IDs
            hashes = [p["url_hash"] for p in payload_list]
            # Batch this if too large, but for backfill let's assume it's okay or needs chunking if > 999 (Sqlite limit)
            # Actually, let's just do it in chunks.
            id_map = {}
            for i in range(0, len(hashes), 900):
                chunk = hashes[i : i + 900]
                placeholders = ",".join(["?"] * len(chunk))
                cursor.execute(
                    f"SELECT id, url_hash FROM malicious_payloads WHERE url_hash IN ({placeholders})",
                    chunk,
                )
                for row in cursor.fetchall():
                    id_map[row[1]] = row[0]

            # 3. Insert Requests
            request_data = []
            for p in payload_list:
                payload_id = id_map.get(p["url_hash"])
                if payload_id:
                    request_data.append(
                        (
                            payload_id,
                            p["ip"],
                            p["session_id"],
                            p.get("timestamp") or ts_default,
                        )
                    )

            if request_data:
                cursor.executemany(
                    """
                    INSERT INTO payload_requests (payload_id, ip, session_id, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    request_data,
                )

            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error batch adding malicious payloads: {e}")
        finally:
            conn.close()

    def cleanup_malicious_payloads(self):
        """Removes duplicate URLs from the malicious_payloads table, keeping only the oldest."""
        conn = self._get_conn()
        try:
            # Step 1: Identify duplicates and keep the one with the smallest ID (oldest)
            # SQLite doesn't support complex DELETE JOINs as easily as Postgres
            # but we can use a subquery.
            cur = conn.cursor()
            cur.execute(
                """
                DELETE FROM malicious_payloads
                WHERE id NOT IN (
                    SELECT MIN(id)
                    FROM malicious_payloads
                    GROUP BY url_hash
                )
            """
            )
            deleted_count = cur.rowcount
            conn.commit()
            if deleted_count > 0:
                log.info(
                    f"[DB] Cleaned up {deleted_count} duplicate malicious payloads."
                )
        except Exception as e:
            log.error(f"[DB] Error cleaning up payloads: {e}")
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
            row = cur.fetchone()
            return dict(row) if row else None
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
        snippet=None,
        **kwargs,
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
                params.append(sanitize_path(file_path))
            if snippet:
                sql += ", snippet = ?"
                params.append(snippet)
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
        """Purges cached responses containing Internal Logic error messages."""
        conn = self._get_conn()
        try:
            # Purge legacy and new internal error markers
            c = conn.cursor()
            c.execute(
                "DELETE FROM command_cache WHERE response LIKE '%Internal Logic Offline%' OR response LIKE '%INTERNAL_ERROR%'"
            )
            c.execute(
                "DELETE FROM interactions WHERE response LIKE '%Internal Logic Offline%' OR response LIKE '%INTERNAL_ERROR%'"
            )
            conn.commit()
            log.info("[SQLite] Purged poisoned cache entries.")
        except Exception as e:
            log.error(f"[SQLite] Error purging cache: {e}")
        finally:
            conn.close()

    def get_cache_keys(self, service):
        """Returns all cache keys and their input texts for a given service."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT cache_key, input_text FROM universal_cache WHERE service = ?",
                (service,),
            )
            return [{"cache_key": row[0], "input_text": row[1]} for row in c.fetchall()]
        except Exception as e:
            log.error(f"[SQLite] Failed to get cache keys: {e}")
            return []
        finally:
            conn.close()

    def get_cache_item(self, cache_key):
        """Retrieves a cached item from universal_cache if it exists and is fresh."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            # We use datetime('now') to check expiry
            c.execute(
                """
                SELECT service, version, input_text, input_hash, output_text, output_hash, 
                       output_size, is_binary, risk_score, attack_stage, explanation, metadata,
                       hit_count, created_at, updated_at, expires_at
                FROM universal_cache 
                WHERE cache_key = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
                """,
                (cache_key,),
            )
            row = c.fetchone()
            if not row:
                return None

            # Update hit count asynchronously in real world, but here we do it sync
            c.execute(
                "UPDATE universal_cache SET hit_count = hit_count + 1, last_hit_at = datetime('now') WHERE cache_key = ?",
                (cache_key,),
            )
            conn.commit()

            return {
                "service": row[0],
                "version": row[1],
                "input_text": row[2],
                "input_hash": row[3],
                "output_text": row[4],
                "output_hash": row[5],
                "output_size": row[6],
                "is_binary": bool(row[7]),
                "risk_score": row[8],
                "attack_stage": row[9],
                "explanation": row[10],
                "metadata": row[11],
                "hit_count": row[12],
                "created_at": row[13],
                "updated_at": row[14],
                "expires_at": row[15],
            }
        except Exception as e:
            log.error(f"[SQLite] Error getting universal cache: {e}")
            return None
        finally:
            conn.close()

    def set_cache_item(
        self,
        cache_key,
        service,
        output_text,
        version=1,
        input_text=None,
        input_hash=None,
        output_hash=None,
        output_size=None,
        is_binary=False,
        risk_score=None,
        attack_stage=None,
        explanation=None,
        metadata=None,
        ttl_days=30,
    ):
        """Saves an item to universal_cache."""
        conn = self._get_conn()

    def set_cache_item(self, **kwargs):
        """Saves a detailed cache item to universal_cache."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                """
                INSERT OR REPLACE INTO universal_cache (
                    cache_key, service, version, input_text, input_hash, output_text, output_hash,
                    output_size, is_binary, risk_score, attack_stage, explanation, metadata,
                    hit_count, created_at, updated_at, expires_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), 
                    datetime('now', '+' || ? || ' days')
                )
                """,
                (
                    kwargs.get("cache_key"),
                    kwargs.get("service"),
                    kwargs.get("version", 1),
                    kwargs.get("input_text"),
                    kwargs.get("input_hash"),
                    kwargs.get("output_text"),
                    kwargs.get("output_hash"),
                    kwargs.get("output_size"),
                    kwargs.get("is_binary", False),
                    kwargs.get("risk_score"),
                    kwargs.get("attack_stage"),
                    kwargs.get("explanation"),
                    kwargs.get("metadata"),
                    0,  # initial hit count
                    kwargs.get("ttl_days", 30),
                ),
            )
            conn.commit()
            return True
        except Exception as e:
            log.error(f"[SQLite] Failed to save cache item: {e}")
            return False

    def delete_cache_item(self, cache_key):
        """Removes an item from universal_cache."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute("DELETE FROM universal_cache WHERE cache_key = ?", (cache_key,))
            conn.commit()
            return True
        except Exception as e:
            log.error(f"[SQLite] Failed to delete cache item: {e}")
            return False
        finally:
            conn.close()

    def get_llm_response(self, prompt_hash):
        """Legacy wrapper - redirected to get_cache_item."""
        item = self.get_cache_item(prompt_hash)
        return item["output_text"] if item else None

    def save_llm_response(self, prompt_hash, prompt_text, response):
        """Legacy wrapper - redirected to set_cache_item."""
        self.set_cache_item(
            cache_key=prompt_hash,
            service="llm",
            input_text=prompt_text,
            output_text=response,
            ttl_days=30,
        )

    def get_session_details(self, session_id):
        """Returns full transcript for a specific session."""
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT start_time, end_time, protocol, remote_ip, username FROM sessions WHERE session_id = ?",
                (session_id,),
            )
            sess = c.fetchone()
            if not sess:
                return None

            c.execute(
                "SELECT timestamp, command, response FROM interactions WHERE session_id = ? ORDER BY timestamp ASC",
                (session_id,),
            )
            interactions = [
                {"timestamp": r[0], "command": r[1], "response": r[2]}
                for r in c.fetchall()
            ]

            return {
                "id": session_id,  # Frontend expects "id"
                "session_id": session_id,  # Keep for compat
                "start_time": sess[0],
                "end_time": sess[1],
                "protocol": sess[2],
                "remote_ip": sess[3],
                "user": sess[4],  # Frontend expects "user"
                "username": sess[4],  # Keep for compat
                "history": interactions,  # Frontend expects "history"
                "interactions": interactions,  # Keep for compat
            }
        except Exception as e:
            log.error(f"[DB] Error fetching session details {session_id}: {e}")
            return None
        finally:
            conn.close()

    def get_recent_payloads(self, limit=10):
        """Fetches recent malicious payloads with analysis context."""
        conn = self._get_conn()
        results = []
        try:
            c = conn.cursor()
            c.execute(
                """
                SELECT p.id, p.timestamp, p.url, p.payload_md5, p.status, 
                       p.virustotal_result, s.protocol, p.snippet, p.session_id
                FROM malicious_payloads p
                LEFT JOIN sessions s ON p.session_id = s.session_id
                ORDER BY p.timestamp DESC LIMIT ?
                """,
                (limit,),
            )

            for row in c.fetchall():
                pid, ts, url, md5, status, vt_res, protocol, snippet, sid = row

                # Parse Analysis
                risk_score = 0
                explanation = "Pending Analysis"

                if vt_res and vt_res.startswith("{"):
                    try:
                        import json

                        vt_data = json.loads(vt_res)
                        # Try to extract risk if we stored it there, or default
                        # If we have a 'classification' or 'stats', we can infer risk
                        stats = vt_data.get("stats", {})
                        malicious = stats.get("malicious", 0)
                        if malicious > 0:
                            risk_score = min(malicious * 10, 100)
                            explanation = f"Flagged by {malicious} engines"
                        elif "error" in vt_data:
                            explanation = "Analysis Error"
                        elif "status" in vt_data and vt_data["status"] == "queued":
                            explanation = "Queued for Analysis"
                        else:
                            explanation = "Clean / Unknown"
                    except:
                        pass

                # Check Universal Cache for richer AI analysis if available
                # (We cache by file hash in payload manager)
                if md5:
                    from ssh_honeypot.core.universal_cache import universal_cache

                    # Try 'payload_analysis' service cache
                    cached = universal_cache.get("payload_analysis", md5)
                    if cached:
                        # If we have a cached analysis, it might be the JSON report
                        # Ideally we'd store a high level summary too.
                        # For now, let's trust the DB record or improve this logic later.
                        pass

                results.append(
                    {
                        "id": pid,
                        "timestamp": ts,
                        "url": url,
                        "md5": md5,
                        "status": status,
                        "protocol": protocol,  # Can be None if derived from interactions/upload
                        "risk_score": risk_score,  # Integer 0-100
                        "explanation": explanation,
                        "snippet": snippet if snippet else "",
                        "session_id": sid,
                    }
                )

            return results
        except Exception as e:
            from ssh_honeypot.core.logging_setup import log

            log.error(f"[DB] Error fetching recent payloads: {e}")
            return []
        finally:
            conn.close()

    def get_recent_high_risk_events(self, limit=10):
        """Fetches latest risky sessions and payloads for the ticker."""
        conn = self._get_conn()
        events = []
        try:
            c = conn.cursor()
            # 1. High Risk Commands
            c.execute(
                """
                SELECT i.timestamp, i.command, s.remote_ip, ca.risk_score, ca.explanation
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE ca.risk_score >= 80
                ORDER BY i.timestamp DESC LIMIT ?
                """,
                (limit,),
            )
            for r in c.fetchall():
                events.append(
                    {
                        "type": "command",
                        "time": r[0],
                        "command": r[1],
                        "ip": r[2],
                        "risk": r[3],
                        "reason": r[4],
                    }
                )

            # 2. Latest Payloads
            c.execute(
                "SELECT timestamp, url, ip FROM malicious_payloads ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            for r in c.fetchall():
                events.append(
                    {
                        "type": "payload",
                        "time": r[0],
                        "url": r[1],
                        "ip": r[2],
                        "risk": 100,
                        "reason": "Malware Download",
                    }
                )

            # Sort combined
            events.sort(key=lambda x: x["time"], reverse=True)
            return events[:limit]
        except Exception as e:
            log.error(f"[DB] Error fetching ticker events: {e}")
            return []
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
