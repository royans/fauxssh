import json
import time
import datetime
import hashlib
import os

from .db_interface import DatabaseBackend
from .logging_setup import log
from .db_utils import sync_db_schema
from .utils import sanitize_path

try:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import Json, execute_values
    import psycopg2.extras
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


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
            log.info("[Postgres] Initializing Connection Pool (min=1, max=100)...")
            self._pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1, maxconn=100, **self.conn_params
            )
        except Exception as e:
            log.error(f"[Postgres] Failed to initialize connection pool: {e}")
            raise e

    def get_connection_info(self):
        host = self.conn_params.get("host", "unknown")
        dbname = self.conn_params.get("dbname", "unknown")
        pool_status = "Active" if self._pool else "Inactive"
        return f"PostgreSQL Backend (Host: {host}, DB: {dbname}, Pool: {pool_status})"

    @property
    def is_postgres(self):
        return True

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
                from fs_seeder import get_skeleton_data  # pylint: disable=import-error

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

    def _clean_str(self, val):
        """
        Removes NUL characters and ensures value is a string or None.
        """
        if val is None:
            return None
        if not isinstance(val, str):
            val = str(val)
        return val.replace("\x00", "")

    def _init_db(self):
        """
        Initialize the database schema.
        """
        log.info("[Postgres] Initializing Database Schema...")
        sync_db_schema(self)

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
        created_at=None,
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
            if created_at:
                cursor.execute(
                    """
                    INSERT INTO interactions 
                    (session_id, cwd, command, response, source, request_md5, response_md5, response_head, response_size, timestamp) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                    (
                        session_id,
                        self._clean_str(cwd),
                        self._clean_str(command),
                        self._clean_str(response),
                        source,
                        request_md5,
                        response_md5,
                        self._clean_str(response_head),
                        response_size,
                        created_at,
                    ),
                )
            else:
                # Ensure session exists (handle race condition)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT 1 FROM sessions WHERE session_id = %s", (session_id,)
                )
                if not cursor.fetchone():
                    # Instead of skipping, insert a stub session to satisfy FK
                    try:
                        cursor.execute(
                            "INSERT INTO sessions (session_id, remote_ip, timestamp) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                            (session_id, "unknown", datetime.datetime.now()),
                        )
                        conn.commit()
                        cursor = conn.cursor()  # Refresh cursor after commit
                    except Exception as ex:
                        log.debug(f"[Postgres] Stub session creation failed: {ex}")
                        conn.rollback()
                        cursor = conn.cursor()

                query = """
                    INSERT INTO interactions (session_id, cwd, command, response, source, request_md5, response_md5, response_head, response_size, duration_ms, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(
                    query,
                    (
                        session_id,
                        self._clean_str(cwd),
                        self._clean_str(command),
                        self._clean_str(response),
                        source,
                        request_md5,
                        response_md5,
                        self._clean_str(response_head),
                        response_size,
                        duration_ms,
                        created_at if created_at else datetime.datetime.now(),
                    ),
                )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error logging interaction: {e}")
            conn.rollback()
        finally:
            conn.close()

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

    # Removed get_cached_response (Deprecated)

    # Removed cache_response (Deprecated)

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
            cursor = conn.cursor()
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

            psycopg2.extras.execute_values(
                cursor,
                """
                INSERT INTO global_filesystem (path, parent_path, type, metadata, content)
                VALUES %s
                ON CONFLICT (path) DO UPDATE SET
                    parent_path = EXCLUDED.parent_path,
                    type = EXCLUDED.type,
                    metadata = EXCLUDED.metadata,
                    content = EXCLUDED.content
                """,
                prepared_data,
            )
            conn.commit()
        finally:
            conn.close()

    def log_url_request(
        self,
        session_id,
        url,
        method="GET",
        user_agent=None,
        command_text=None,
        created_at=None,
    ):
        """
        Consolidated URL logging.
        Now redirects to add_malicious_payload to maintain a single source of truth.
        """
        import hashlib

        url_hash = hashlib.md5(url.encode()).hexdigest()

        # Try to resolve IP from session
        client_ip = "Unknown"
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ip FROM sessions WHERE session_id = %s", (session_id,)
            )
            row = cursor.fetchone()
            if row:
                client_ip = row[0]
        except:
            pass
        finally:
            conn.close()

        self.add_malicious_payload(
            url=url,
            url_hash=url_hash,
            session_id=session_id,
            ip=client_ip,
            timestamp=created_at,
            method=method,
            user_agent=user_agent,
            command_text=command_text,
            status="discovered",
            analysis_stage="Pending",
        )

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
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            fp_json = "{}"
            if fingerprint:
                fp_json = json.dumps(fingerprint)

            if created_at:
                cursor.execute(
                    """
                    INSERT INTO auth_events (client_ip, username, auth_method, auth_data, success, client_version, fingerprint, protocol, timestamp)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                        created_at,
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO auth_events (client_ip, username, auth_method, auth_data, success, client_version, fingerprint, protocol)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                    (
                        client_ip,
                        self._clean_str(username),
                        self._clean_str(auth_method),
                        (
                            self._clean_str(json.dumps(auth_data))
                            if isinstance(auth_data, dict)
                            else self._clean_str(auth_data)
                        ),
                        success,
                        self._clean_str(client_version),
                        self._clean_str(fp_json),
                        self._clean_str(protocol),
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

    def record_api_usage(self, service, identifier):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO api_usage (service, identifier) VALUES (%s, %s)",
                (service, identifier),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error recording API usage for {service}: {e}")
        finally:
            conn.close()

    def check_api_rate_limit(
        self, service, identifier, rpm_limit, rph_limit, rpd_limit
    ):
        """
        Generic rate limit checker for any service/identifier (Postgres implementation).
        Returns (allowed: bool, reason: str)
        """
        conn = self._get_conn()
        try:
            cursor = conn.cursor()

            # RPM
            cursor.execute(
                "SELECT COUNT(*) FROM api_usage WHERE service = %s AND identifier = %s AND timestamp > NOW() - INTERVAL '60 seconds'",
                (service, identifier),
            )
            rpm_count = cursor.fetchone()[0]
            if rpm_count >= rpm_limit:
                return False, f"RPM Limit Exceeded ({service}: {rpm_count}/{rpm_limit})"

            # RPH
            cursor.execute(
                "SELECT COUNT(*) FROM api_usage WHERE service = %s AND identifier = %s AND timestamp > NOW() - INTERVAL '1 hour'",
                (service, identifier),
            )
            rph_count = cursor.fetchone()[0]
            if rph_count >= rph_limit:
                return False, f"RPH Limit Exceeded ({service}: {rph_count}/{rph_limit})"

            # RPD
            cursor.execute(
                "SELECT COUNT(*) FROM api_usage WHERE service = %s AND identifier = %s AND timestamp > NOW() - INTERVAL '24 hours'",
                (service, identifier),
            )
            rpd_count = cursor.fetchone()[0]
            if rpd_count >= rpd_limit:
                return False, f"RPD Limit Exceeded ({service}: {rpd_count}/{rpd_limit})"

            return True, "OK"
        except Exception as e:
            log.error(f"[Postgres] Error checking API limits for {service}: {e}")
            return True, "Error check failed (Fail Open)"
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
                    "created_at": datetime.datetime.now(),
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
                    "created_at": datetime.datetime.now(),
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
        if path == home_dir:
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
            # Note: HTTP Cache is now handled by UniversalCache.delete_service("http_cache")
            # This method is kept for API compatibility but the legacy table is gone.
            log.info(f"[Postgres] HTTP Cache legacy cleanup skipped (Table gone)")
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

    def get_session_details(self, session_id):
        """Fetches full session details and interaction sequence for replay."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cursor.execute(
                "SELECT * FROM sessions WHERE session_id = %s", (session_id,)
            )
            session = cursor.fetchone()
            if not session:
                return None

            cursor.execute(
                "SELECT timestamp, command, response, source FROM interactions WHERE session_id = %s ORDER BY timestamp ASC, id ASC",
                (session_id,),
            )
            interactions = []
            for r in cursor.fetchall():
                row_dict = dict(r)
                if isinstance(
                    row_dict.get("timestamp"), (datetime.datetime, datetime.date)
                ):
                    row_dict["timestamp"] = row_dict["timestamp"].isoformat()
                interactions.append(row_dict)

            duration = 0
            if session["end_time"] and session["start_time"]:
                duration = (session["end_time"] - session["start_time"]).total_seconds()

            return {
                "id": session["session_id"],
                "session_id": session["session_id"],  # Compat
                "ip": session["remote_ip"],
                "remote_ip": session["remote_ip"],  # Compat
                "protocol": session["protocol"],
                "user": session["username"],
                "username": session["username"],  # Compat
                "start_time": (
                    session["start_time"].isoformat()
                    if hasattr(session["start_time"], "isoformat")
                    else str(session["start_time"])
                ),
                "duration": duration,
                "history": interactions,
                "interactions": interactions,  # Compat
            }
        finally:
            conn.close()

    def get_recent_high_risk_events(self, limit=10):
        """Fetches latest risky sessions and payloads for the ticker."""
        conn = self._get_conn()
        events = []
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            # 1. High Risk Commands
            cursor.execute(
                """
                SELECT i.timestamp, i.command, s.remote_ip, ca.risk_score, ca.explanation
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE ca.risk_score >= 80
                ORDER BY i.timestamp DESC LIMIT %s
                """,
                (limit,),
            )
            for r in cursor.fetchall():
                events.append(
                    {
                        "type": "command",
                        "time": (
                            r["timestamp"].isoformat()
                            if hasattr(r["timestamp"], "isoformat")
                            else str(r["timestamp"])
                        ),
                        "command": r["command"],
                        "ip": r["remote_ip"],
                        "risk": r["risk_score"],
                        "reason": r["explanation"],
                    }
                )

            # 2. Latest Payloads
            cursor.execute(
                "SELECT timestamp, url, ip FROM malicious_payloads ORDER BY timestamp DESC LIMIT %s",
                (limit,),
            )
            for r in cursor.fetchall():
                events.append(
                    {
                        "type": "payload",
                        "time": (
                            r["timestamp"].isoformat()
                            if hasattr(r["timestamp"], "isoformat")
                            else str(r["timestamp"])
                        ),
                        "url": r["url"],
                        "ip": r["ip"],
                        "risk": 100,
                        "reason": "Malware Download",
                    }
                )

            events.sort(key=lambda x: x["time"], reverse=True)
            return events[:limit]
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

    def get_unanalyzed_commands(self, limit=10, allowed_protocols=None):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

            protocol_filter = ""
            params = []

            if allowed_protocols:
                # Use ANY for cleaner array handling in PG
                protocol_filter = "AND s.protocol = ANY(%s)"
                params.append(allowed_protocols)

            params.append(limit)

            query = f"""
                SELECT i.id, i.session_id, i.command, i.request_md5, s.remote_ip
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                LEFT JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE ca.command_hash IS NULL
                AND i.request_md5 IS NOT NULL
                AND i.command != ''
                AND i.command NOT LIKE 'CONNECT %%'
                AND i.command NOT LIKE 'GET %%'
                {protocol_filter}
                ORDER BY i.id DESC
                LIMIT %s
                """

            cursor.execute(query, tuple(params))
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
            "top_http_commands": [],
            "top_redis_commands": [],
            "top_mcp_commands": [],
            "top_llm_models": [],
            "top_llm_endpoints": [],
            "total_payloads": 0,
            "protocol_activity": {},
            "kill_chain": [],
            "top_ssh_risk": [],
            "multi_window": {},
        }
        try:
            cursor = conn.cursor()
            time_filter = f"NOW() - INTERVAL '{hours} hours'"
            prev_time_filter = f"NOW() - INTERVAL '{hours*2} hours'"

            # IP Exclusion Filter
            log.debug("[Postgres] Stats: Starting IP Filter setup")
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

            # Helper for metrics
            def get_window_stats(start_expr, end_expr=None):
                e_part = f" AND start_time <= {end_expr}" if end_expr else ""
                cursor.execute(
                    f"SELECT COUNT(DISTINCT remote_ip), COUNT(*) FROM sessions WHERE start_time > {start_expr} {e_part} {ip_filter}",
                    params,
                )
                row = cursor.fetchone()
                ips, sessions = (
                    (row[0] or 0, row[1] or 0) if row and len(row) >= 2 else (0, 0)
                )

                ei_part = f" AND i.timestamp <= {end_expr}" if end_expr else ""
                cursor.execute(
                    f"""
                    SELECT COUNT(*) FROM interactions i
                    JOIN sessions s ON i.session_id = s.session_id
                    WHERE i.timestamp > {start_expr} {ei_part} {interaction_ip_filter}
                """,
                    params,
                )
                row = cursor.fetchone()
                commands = row[0] if row and row[0] is not None else 0

                cursor.execute(
                    f"""
                    SELECT COUNT(DISTINCT intel.org) 
                    FROM sessions s
                    JOIN ip_intelligence intel ON s.remote_ip = intel.ip
                    WHERE s.start_time > {start_expr} {e_part} {ip_filter}
                """,
                    params,
                )
                row = cursor.fetchone()
                networks = row[0] if row and row[0] is not None else 0

                return {
                    "ips": ips,
                    "sessions": sessions,
                    "commands": commands,
                    "networks": networks,
                }

            # Multi-window Metrics
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

            # Current window totals
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
            row = cursor.fetchone()
            stats["total_payloads"] = row[0] if row and row[0] is not None else 0

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
                if len(r) >= 3:
                    proto = r[0]
                    stats["service_dist"].append(
                        {"protocol": proto, "sessions": r[1], "commands": r[2]}
                    )
                    stats["protocol_activity"][proto] = r[2]

            # --- LLM ANALYTICS ---
            llm_query = f"""
                SELECT command FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                WHERE i.source = 'llm-api' AND i.timestamp > {time_filter} {interaction_ip_filter}
            """
            cursor.execute(llm_query, params)
            llm_rows = cursor.fetchall()
            if llm_rows:
                from collections import Counter

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
            cursor.execute(query, params)
            stats["top_countries"] = [
                {"country": r[0] or "Unknown", "ips": r[1], "sessions": r[2]}
                for r in cursor.fetchall()
                if len(r) >= 3
            ]

            # Top ISPs (Unique IPs and Sessions)
            query = f"""
                SELECT intel.org, intel.asn, COUNT(DISTINCT s.remote_ip) as unique_ips, COUNT(DISTINCT s.session_id) as sessions
                FROM sessions s 
                JOIN ip_intelligence intel ON s.remote_ip = intel.ip 
                WHERE s.start_time > {time_filter} {interaction_ip_filter}
                GROUP BY intel.org, intel.asn
                ORDER BY unique_ips DESC LIMIT 50
            """
            cursor.execute(query, params)
            stats["top_isps"] = [
                {
                    "isp": r[0] or "Unknown",
                    "asn": r[1] or "-",
                    "ips": r[2],
                    "sessions": r[3],
                }
                for r in cursor.fetchall()
                if len(r) >= 4
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
                if len(r) >= 3
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
                if len(r) >= 3
            ]

            # Generic Top Command Fetcher
            def get_top_commands(proto, limit=50):
                q = f"""
                    SELECT i.command, COUNT(*) as count, COUNT(DISTINCT s.remote_ip) as unique_ips,
                           SUBSTRING(MAX(i.response) FROM 1 FOR 1000) as sample_response
                    FROM interactions i
                    JOIN sessions s ON i.session_id = s.session_id
                    WHERE i.timestamp > {time_filter} AND s.protocol = %s {interaction_ip_filter}
                    GROUP BY i.command 
                    ORDER BY unique_ips DESC, count DESC LIMIT %s
                """
                cursor.execute(q, [proto] + params + [limit])
                res = []
                for r in cursor.fetchall():
                    if len(r) >= 4:
                        res.append(
                            {
                                "command": r[0],
                                "count": r[1],
                                "ips": r[2],
                                "response": r[3],
                            }
                        )
                    elif len(r) >= 3:
                        res.append(
                            {
                                "command": r[0],
                                "count": r[1],
                                "ips": r[2],
                                "response": "",
                            }
                        )
                return res

            stats["top_ssh_commands"] = get_top_commands("ssh")
            stats["top_telnet_commands"] = get_top_commands("telnet")
            stats["top_mysql_commands"] = get_top_commands("mysql")
            stats["top_http_commands"] = get_top_commands("http")
            stats["top_redis_commands"] = get_top_commands("redis")
            stats["top_mcp_commands"] = get_top_commands("mcp")

            # --- TOP SSH RISK ---
            query = f"""
                SELECT i.command, COALESCE(MAX(ca.risk_score), 0) as max_risk, COUNT(*) as count, COUNT(DISTINCT s.remote_ip) as unique_ips,
                       SUBSTRING(MAX(i.response) FROM 1 FOR 1000) as sample_response, MAX(i.session_id) as sample_session
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE i.timestamp > {time_filter} AND s.protocol = 'ssh' {interaction_ip_filter}
                GROUP BY i.command
                ORDER BY max_risk DESC, unique_ips DESC, count DESC
                LIMIT 50
            """
            cursor.execute(query, params)
            for r in cursor.fetchall():
                if len(r) >= 6:
                    stats["top_ssh_risk"].append(
                        {
                            "command": r[0],
                            "risk": r[1],
                            "count": r[2],
                            "ips": r[3],
                            "response": r[4],
                            "session_id": r[5],
                        }
                    )

            # --- KILL CHAIN STAGES ---
            query = f"""
                SELECT ca.stage, COUNT(*) as count, COUNT(DISTINCT s.remote_ip) as unique_ips
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE i.timestamp > {time_filter} {interaction_ip_filter}
                GROUP BY ca.stage
                ORDER BY count DESC
            """
            cursor.execute(query, params)
            stats["kill_chain"] = [
                {"stage": r[0], "count": r[1], "ips": r[2]}
                for r in cursor.fetchall()
                if len(r) >= 3
            ]

            # Recent Unique Commands
            query = f"""
                SELECT i.command 
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                WHERE s.start_time > {time_filter} {interaction_ip_filter}
                GROUP BY i.command
                ORDER BY MAX(i.timestamp) DESC LIMIT 20
            """
            cursor.execute(query, params)
            stats["recent_unique_commands"] = [
                r[0] for r in cursor.fetchall() if len(r) >= 1
            ]

            # Manual vs Bot
            query = f"""
                SELECT 
                    SUM(CASE WHEN command_count > 10 OR summary ILIKE %s THEN 1 ELSE 0 END) as manual_count,
                    SUM(CASE WHEN command_count <= 10 AND (summary IS NULL OR summary NOT ILIKE %s) THEN 1 ELSE 0 END) as bot_count
                FROM (
                    SELECT s.session_id, s.summary, COUNT(i.id) as command_count
                    FROM sessions s
                    LEFT JOIN interactions i ON s.session_id = i.session_id
                    WHERE s.start_time > {time_filter} {interaction_ip_filter}
                    GROUP BY s.session_id, s.summary
                ) t
            """
            # Copy params + manual filters safely
            cursor.execute(query, params + ["%manual%", "%manual%"])
            row = cursor.fetchone()
            if row and len(row) >= 2:
                stats["manual_vs_bot"] = {
                    "manual": int(row[0] or 0),
                    "bot": int(row[1] or 0),
                }

            # Top IPs Summary
            query = f"""
                SELECT remote_ip, COUNT(*) as count 
                FROM sessions 
                WHERE start_time > {time_filter} {ip_filter}
                GROUP BY remote_ip 
                ORDER BY count DESC LIMIT 50
            """
            cursor.execute(query, params)
            stats["top_ips"] = [
                {"ip": r[0], "count": r[1]} for r in cursor.fetchall() if len(r) >= 2
            ]

        except Exception as e:
            log.error(f"[Postgres] Error fetching infographic stats (Global): {e}")
            import traceback

            log.error(traceback.format_exc())
        finally:
            conn.close()
        return stats

    def get_recent_payloads(self, limit=10):
        """Fetches recent malicious payloads with analysis context."""
        conn = self._get_conn()
        results = []
        try:
            c = conn.cursor()
            c.execute(
                """
                SELECT p.id, p.timestamp, p.url, p.payload_md5, p.status, 
                       a.virustotal_result, s.protocol, p.snippet, p.session_id,
                       a.risk_score, a.analysis_summary
                FROM malicious_payloads p
                LEFT JOIN payload_analysis a ON p.payload_md5 = a.payload_md5
                LEFT JOIN sessions s ON p.session_id = s.session_id
                ORDER BY p.timestamp DESC LIMIT %s
                """,
                (limit,),
            )

            for row in c.fetchall():
                (
                    pid,
                    ts,
                    url,
                    md5,
                    status,
                    vt_res,
                    protocol,
                    snippet,
                    sid,
                    risk_score,
                    analysis_summary,
                ) = row

                # Parse Analysis
                final_risk_score = risk_score or 0
                explanation = analysis_summary or "Pending Analysis"

                if vt_res and vt_res.startswith("{") and not final_risk_score:
                    try:
                        import json

                        vt_data = json.loads(vt_res)
                        stats = vt_data.get("stats", {})
                        malicious = stats.get("malicious", 0)
                        if malicious > 0:
                            final_risk_score = min(malicious * 10, 100)
                            explanation = f"Flagged by {malicious} engines"
                        elif "error" in vt_data:
                            explanation = "Analysis Error"
                        elif "status" in vt_data and vt_data["status"] == "queued":
                            explanation = "Queued for Analysis"
                        else:
                            explanation = "Clean / Unknown"
                    except:
                        pass

                results.append(
                    {
                        "id": pid,
                        "timestamp": (
                            ts.isoformat() if ts else None
                        ),  # Ensure timestamp is ISO formatted
                        "url": url,
                        "md5": md5,
                        "status": status,
                        "protocol": protocol,
                        "risk_score": final_risk_score,
                        "explanation": explanation,
                        "snippet": snippet if snippet else "",
                        "session_id": sid,
                    }
                )

            return results
        except Exception as e:
            from ssh_honeypot.core.logging_setup import log

            log.error(f"[Postgres] Error fetching recent payloads: {e}")
            return []
        finally:
            conn.close()

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
                    f"SELECT protocol, COUNT(*) FROM sessions WHERE start_time > {day_start} AND start_time <= {day_end} GROUP BY protocol"
                )
                protocol_counts = {r[0]: r[1] for r in cursor.fetchall()}
                count = sum(protocol_counts.values())

                # Get label like 'Jan 21'
                cursor.execute(f"SELECT TO_CHAR(NOW() - INTERVAL '{i} days', 'Mon DD')")
                row_label = cursor.fetchone()
                label = row_label[0] if row_label else f"Day-{i}"
                res.append(
                    {"label": label, "count": count, "protocols": protocol_counts}
                )
        except Exception as e:
            log.error(f"[Postgres] Error fetching daily session counts: {e}")
        finally:
            conn.close()
        return res

    def get_hourly_session_counts(self, hours=24):
        """Returns session counts for each of the last X hours (Postgres)."""
        conn = self._get_conn()
        res = []
        try:
            cursor = conn.cursor()
            for i in range(hours - 1, -1, -1):
                hour_start = f"NOW() - INTERVAL '{i+1} hours'"
                hour_end = f"NOW() - INTERVAL '{i} hours'"
                cursor.execute(
                    f"SELECT protocol, COUNT(*) FROM sessions WHERE start_time > {hour_start} AND start_time <= {hour_end} GROUP BY protocol"
                )
                protocol_counts = {r[0]: r[1] for r in cursor.fetchall()}
                count = sum(protocol_counts.values())

                # Get label like '14:00'
                cursor.execute(
                    f"SELECT TO_CHAR(NOW() - INTERVAL '{i} hours', 'HH24:MI')"
                )
                row_label = cursor.fetchone()
                label = row_label[0] if row_label else f"H-{i}"
                res.append(
                    {"label": label, "count": count, "protocols": protocol_counts}
                )
        except Exception as e:
            log.error(f"[Postgres] Error fetching hourly session counts: {e}")
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

    def get_malicious_payload_by_hash(self, url_hash):
        """Fetches a payload record by its URL hash."""
        conn = self._get_conn()
        try:
            from psycopg2.extras import RealDictCursor

            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute(
                "SELECT * FROM malicious_payloads WHERE url_hash = %s", (url_hash,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
        except Exception as e:
            log.error(f"[Postgres] Error fetching payload by hash: {e}")
            return None
        finally:
            conn.close()

    def add_malicious_payload(
        self,
        url,
        url_hash,
        session_id,
        ip,
        timestamp=None,
        status="pending",
        analysis_stage="Downloading",
        payload_md5=None,
        payload_size=None,
        file_path=None,
        snippet=None,
        content=None,
        is_binary=False,
        method=None,
        user_agent=None,
        command_text=None,
        **kwargs,
    ):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # 1. Insert/Get Payload ID
            cursor.execute(
                """
                INSERT INTO malicious_payloads (
                    url, url_hash, session_id, ip, timestamp, status, analysis_stage,
                    payload_md5, payload_size, file_path, snippet, content, is_binary,
                    method, user_agent, command_text
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (url_hash) DO UPDATE SET
                    payload_md5 = COALESCE(EXCLUDED.payload_md5, malicious_payloads.payload_md5),
                    payload_size = COALESCE(EXCLUDED.payload_size, malicious_payloads.payload_size),
                    file_path = COALESCE(EXCLUDED.file_path, malicious_payloads.file_path),
                    snippet = COALESCE(EXCLUDED.snippet, malicious_payloads.snippet),
                    content = COALESCE(EXCLUDED.content, malicious_payloads.content),
                    is_binary = COALESCE(EXCLUDED.is_binary, malicious_payloads.is_binary),
                    status = EXCLUDED.status,
                    analysis_stage = EXCLUDED.analysis_stage,
                    timestamp = EXCLUDED.timestamp,
                    method = COALESCE(EXCLUDED.method, malicious_payloads.method),
                    user_agent = COALESCE(EXCLUDED.user_agent, malicious_payloads.user_agent),
                    command_text = COALESCE(EXCLUDED.command_text, malicious_payloads.command_text)
                RETURNING id
            """,
                (
                    url,
                    url_hash,
                    session_id,
                    ip,
                    timestamp or datetime.datetime.now(),
                    status,
                    analysis_stage,
                    payload_md5,
                    payload_size,
                    file_path,
                    snippet,
                    content,
                    is_binary,
                    method,
                    user_agent,
                    command_text,
                ),
            )
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
            return payload_id
        except Exception as e:
            log.error(f"[Postgres] Error adding malicious payload: {e}")
            return None
        finally:
            conn.close()

    def update_payload_analysis(
        self,
        payload_md5,
        virustotal_result=None,
        risk_score=None,
        analysis_summary=None,
        vt_last_scanned=None,
        payload_size=None,
        file_path=None,
    ):
        """Updates or inserts deduplicated payload analysis data."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO payload_analysis (
                    payload_md5, virustotal_result, risk_score, analysis_summary,
                    vt_last_scanned, payload_size, file_path, analyzed_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (payload_md5) DO UPDATE SET
                    virustotal_result = COALESCE(EXCLUDED.virustotal_result, payload_analysis.virustotal_result),
                    risk_score = COALESCE(EXCLUDED.risk_score, payload_analysis.risk_score),
                    analysis_summary = COALESCE(EXCLUDED.analysis_summary, payload_analysis.analysis_summary),
                    vt_last_scanned = COALESCE(EXCLUDED.vt_last_scanned, payload_analysis.vt_last_scanned),
                    payload_size = COALESCE(EXCLUDED.payload_size, payload_analysis.payload_size),
                    file_path = COALESCE(EXCLUDED.file_path, payload_analysis.file_path),
                    analyzed_at = CURRENT_TIMESTAMP
            """,
                (
                    payload_md5,
                    virustotal_result,
                    risk_score,
                    analysis_summary,
                    vt_last_scanned,
                    payload_size,
                    file_path,
                ),
            )
            conn.commit()
            return True
        except Exception as e:
            log.error(f"[Postgres] Error updating payload analysis: {e}")
            return False
        finally:
            conn.close()

    def get_payload_analysis(self, payload_md5):
        """Fetches deduplicated analysis data for a given file hash."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM payload_analysis WHERE payload_md5 = %s", (payload_md5,)
            )
            row = cursor.fetchone()
            if row:
                # Convert to dict
                from psycopg2.extras import RealDictCursor

                # Re-fetch with RealDictCursor for easier conversion if needed
                # OR just manually map
                columns = [column[0] for column in cursor.description]
                return dict(zip(columns, row))
            return None
        except Exception as e:
            log.error(f"[Postgres] Error fetching payload analysis: {e}")
            return None
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
            cursor = conn.cursor()

            payload_data = [
                (
                    p["url"],
                    p["url_hash"],
                    p["session_id"],
                    p["ip"],
                    p.get("timestamp") or ts_default,
                    "pending",
                )
                for p in payload_list
            ]

            psycopg2.extras.execute_values(
                cursor,
                """
                INSERT INTO malicious_payloads (url, url_hash, session_id, ip, timestamp, status)
                VALUES %s
                ON CONFLICT (url_hash) DO NOTHING
                """,
                payload_data,
            )

            # Fetch IDs
            hashes = [p["url_hash"] for p in payload_list]
            cursor.execute(
                "SELECT id, url_hash FROM malicious_payloads WHERE url_hash = ANY(%s)",
                (hashes,),
            )
            id_map = {row[1]: row[0] for row in cursor.fetchall()}

            # Insert Requests
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
                psycopg2.extras.execute_values(
                    cursor,
                    """
                    INSERT INTO payload_requests (payload_id, ip, session_id, timestamp)
                    VALUES %s
                    """,
                    request_data,
                )

            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error batch adding malicious payloads: {e}")
            conn.rollback()
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
            # Include 'pending' OR stuck 'downloading' (> 1 hour old)
            cursor.execute(
                """
                SELECT * FROM malicious_payloads 
                WHERE status IN ('pending', 'discovered') 
                   OR (status = 'downloading' AND timestamp < NOW() - INTERVAL '1 hour')
                ORDER BY timestamp ASC 
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            log.error(f"[Postgres] Error fetching pending payloads: {e}")
            return []
        finally:
            conn.close()

    # Legacy update_payload_status removed in favor of comprehensive version below

    def is_payload_host_rate_limited(self, hostname):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # Normalize hostname for search
            search_pattern = f"%//{hostname}/%"
            cursor.execute(
                """
                SELECT COUNT(*) FROM malicious_payloads 
                WHERE url LIKE %s AND timestamp > NOW() - INTERVAL '1 hour'
                """,
                (search_pattern,),
            )
            count = cursor.fetchone()[0]
            return (
                count >= 10
            )  # Increased limit slightly, or stick to 5? Plan said robust
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

    def delete_cache_by_pattern(self, pattern):
        """Removes items from universal_cache where output_text matches pattern. Returns list of (key, service)."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # Postgres supports DELETE RETURNING
            cursor.execute(
                "DELETE FROM universal_cache WHERE output_text LIKE %s RETURNING cache_key, service",
                (f"%{pattern}%",),
            )
            rows = cursor.fetchall()
            conn.commit()
            return [(r[0], r[1]) for r in rows]
        except Exception as e:
            log.error(f"[Postgres] Failed to delete cache by pattern: {e}")
            return []
        finally:
            conn.close()

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

    def get_pending_analysis_payloads(self, limit=5):
        """Fetches payloads that have been downloaded but not yet analyzed by VT."""
        conn = self._get_conn()
        try:
            from psycopg2.extras import RealDictCursor

            cursor = conn.cursor(cursor_factory=RealDictCursor)
            # We join with payload_analysis and find items where analysis is missing
            cursor.execute(
                """
                SELECT p.* FROM malicious_payloads p
                LEFT JOIN payload_analysis a ON p.payload_md5 = a.payload_md5
                WHERE p.status = 'completed' 
                AND p.payload_md5 IS NOT NULL
                AND a.payload_md5 IS NULL
                AND (p.vt_last_scanned IS NULL OR p.vt_last_scanned < NOW() - INTERVAL '15 minutes')
                ORDER BY p.timestamp DESC
                LIMIT %s
                """,
                (limit,),
            )
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            log.error(f"[Postgres] Error fetching pending analysis payloads: {e}")
            return []
        finally:
            conn.close()

    def get_next_payload_for_analysis(self):
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                "SELECT * FROM malicious_payloads WHERE vt_scan_id IS NULL AND status = 'completed' LIMIT 1"
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            log.error(f"[Postgres] Error fetching next payload for analysis: {e}")
            return None
        finally:
            conn.close()

    def update_payload_file_path(self, payload_id, file_path):
        """Updates the file_path for a payload (used by self-healing)."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE malicious_payloads SET file_path = %s WHERE id = %s",
                (file_path, payload_id),
            )
            conn.commit()
            return True
        except Exception as e:
            log.error(f"[Postgres] Error updating payload file path: {e}")
            return False
        finally:
            conn.close()

    def update_payload_status(
        self,
        payload_id,
        status,
        analysis_stage=None,
        payload_md5=None,
        payload_size=None,
        file_path=None,
        error=None,
        snippet=None,
        content=None,
        is_binary=None,
        vt_scan_id=None,
        vt_last_scanned=None,
        **kwargs,
    ):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            sql = "UPDATE malicious_payloads SET status = %s"
            params = [status]

            if analysis_stage:
                sql += ", analysis_stage = %s"
                params.append(analysis_stage)
            if payload_md5:
                sql += ", payload_md5 = %s"
                params.append(payload_md5)
            if payload_size is not None:
                sql += ", payload_size = %s"
                params.append(payload_size)
            if file_path:
                sql += ", file_path = %s"
                params.append(file_path)
            if snippet:
                sql += ", snippet = %s"
                params.append(snippet)
            if content:
                sql += ", content = %s"
                params.append(content)
            if is_binary is not None:
                sql += ", is_binary = %s"
                params.append(is_binary)
            if error:
                sql += ", error_message = %s"
                params.append(error)
            if vt_scan_id:
                sql += ", vt_scan_id = %s"
                params.append(vt_scan_id)
            if vt_last_scanned:
                sql += ", vt_last_scanned = %s"
                params.append(vt_last_scanned)

            sql += " WHERE id = %s"
            params.append(payload_id)

            cursor.execute(sql, tuple(params))
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error updating payload status: {e}")
            conn.rollback()
        finally:
            conn.close()

    def update_payload_vt_status(self, payload_id, result, scan_id=None):
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE malicious_payloads SET virustotal_result = %s, vt_scan_id = %s, vt_last_scanned = NOW() WHERE id = %s",
                (result, scan_id, payload_id),
            )
            conn.commit()
        except Exception as e:
            log.error(f"[Postgres] Error updating payload VT status: {e}")
            conn.rollback()
        finally:
            conn.close()

    def get_payload_summary(self, hours=24):
        """Returns unique payloads by MD5 with server and attacker counts."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute(
                f"""
                SELECT p.payload_md5, MAX(p.timestamp) as last_seen, 
                       COUNT(DISTINCT p.id) as server_count,
                       COUNT(DISTINCT pr.ip) as attacker_count,
                       MAX(p.status) as status, MAX(p.analysis_stage) as analysis_stage,
                       MAX(p.virustotal_result) as vt_res,
                       MAX(p.payload_size) as size,
                       MAX(p.url) as sample_url
                FROM malicious_payloads p
                LEFT JOIN payload_requests pr ON p.id = pr.payload_id
                WHERE p.payload_md5 IS NOT NULL AND p.timestamp > NOW() - INTERVAL '{hours} hours'
                GROUP BY p.payload_md5
                ORDER BY last_seen DESC
            """
            )
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            log.error(f"[Postgres] Error fetching payload summary: {e}")
            return []
        finally:
            conn.close()

    def get_payload_details(self, md5):
        """Returns detailed info for a specific MD5, including content and occurrences."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # Get the core payload info (from the oldest entry for this MD5)
            cursor.execute(
                "SELECT * FROM malicious_payloads WHERE payload_md5 = %s ORDER BY timestamp ASC LIMIT 1",
                (md5,),
            )
            base = cursor.fetchone()
            if not base:
                return None

            base_dict = dict(base)

            # If content is missing, try to read it from disk
            if (not base_dict.get("content")) and base_dict.get("file_path"):
                try:
                    fpath = base_dict["file_path"]
                    from ssh_honeypot.core.utils import (
                        get_data_dir,
                        PROJECT_ROOT,
                        get_storable_content,
                    )

                    actual_path = fpath.replace("<DATA_DIR>", get_data_dir()).replace(
                        "<ROOT>", PROJECT_ROOT
                    )

                    if os.path.exists(actual_path):
                        with open(actual_path, "rb") as f:
                            raw_content = f.read(1024 * 1024)  # 1MB limit
                            db_content, _ = get_storable_content(raw_content)
                            base_dict["content"] = db_content
                except Exception as e:
                    log.warning(
                        f"[Postgres] Failed to read payload file for details: {e}"
                    )

            # Get all occurrences/requests
            cursor.execute(
                """
                SELECT pr.timestamp, pr.ip, pr.session_id, s.protocol
                FROM payload_requests pr
                LEFT JOIN malicious_payloads p ON pr.payload_id = p.id
                LEFT JOIN sessions s ON pr.session_id = s.session_id
                WHERE p.payload_md5 = %s
                ORDER BY pr.timestamp DESC
            """,
                (md5,),
            )
            occurrences = [dict(row) for row in cursor.fetchall()]
            base_dict["occurrences"] = occurrences

            return base_dict
        except Exception as e:
            log.error(f"[Postgres] Error fetching payload details: {e}")
            return None
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
        """Purges cached responses containing Internal Logic error messages."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            # Purge internal error markers from active tables

            query_int = (
                "DELETE FROM interactions WHERE response LIKE %s OR response LIKE %s"
            )
            cursor.execute(query_int, ("%Internal Logic Offline%", "%INTERNAL_ERROR%"))
            conn.commit()
            log.info("[Postgres] Purged poisoned cache entries.")
        except Exception as e:
            log.error(f"[Postgres] Error purging cache: {e}")
            conn.rollback()
        finally:
            conn.close()

    def get_cache_keys(self, service):
        """Returns all cache keys and their input texts for a given service."""
        try:
            with self._get_conn() as conn:
                with conn.cursor() as c:
                    c.execute(
                        "SELECT cache_key, input_text FROM universal_cache WHERE service = %s",
                        (service,),
                    )
                    return [
                        {"cache_key": row[0], "input_text": row[1]}
                        for row in c.fetchall()
                    ]
        except Exception as e:
            log.error(f"[Postgres] Failed to get cache keys: {e}")
            return []

    def get_cache_item(self, cache_key):
        """Retrieves a cached item from universal_cache (Postgres)."""
        conn = self._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT service, version, input_text, input_hash, output_text, output_hash, 
                       output_size, is_binary, risk_score, attack_stage, explanation, metadata,
                       hit_count, created_at, updated_at, expires_at
                FROM universal_cache 
                WHERE cache_key = %s AND (expires_at IS NULL OR expires_at > NOW())
                """,
                (cache_key,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            # Update hit count
            cursor.execute(
                "UPDATE universal_cache SET hit_count = hit_count + 1, last_hit_at = NOW() WHERE cache_key = %s",
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
            log.error(f"[Postgres] Error getting universal cache: {e}")
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
        """Saves an item to universal_cache (Postgres)."""

    def set_cache_item(self, **kwargs):
        """Saves a detailed cache item to universal_cache."""
        try:
            with self._get_conn() as conn:
                with conn.cursor() as c:
                    c.execute(
                        """
                        INSERT INTO universal_cache (
                            cache_key, service, version, input_text, input_hash, output_text, output_hash,
                            output_size, is_binary, risk_score, attack_stage, explanation, metadata,
                            hit_count, created_at, updated_at, expires_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), 
                            NOW() + interval '%s days'
                        )
                        ON CONFLICT (cache_key) DO UPDATE SET
                            output_text = EXCLUDED.output_text,
                            output_hash = EXCLUDED.output_hash,
                            output_size = EXCLUDED.output_size,
                            updated_at = NOW(),
                            expires_at = EXCLUDED.expires_at,
                            metadata = EXCLUDED.metadata;
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
                            0,  # hit_count
                            kwargs.get("ttl_days", 30),
                        ),
                    )
            return True
        except Exception as e:
            log.error(f"[Postgres] Failed to save cache item: {e}")
            return False

    def delete_cache_item(self, cache_key):
        """Removes an item from universal_cache."""
        try:
            with self._get_conn() as conn:
                with conn.cursor() as c:
                    c.execute(
                        "DELETE FROM universal_cache WHERE cache_key = %s", (cache_key,)
                    )
            return True
        except Exception as e:
            log.error(f"[Postgres] Failed to delete cache item: {e}")
            return False

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
