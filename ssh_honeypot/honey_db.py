import sqlite3
import datetime
import hashlib
import os
import json
import time

try:
    from .db_interface import DatabaseBackend
    from .logger import log
    from .config_manager import get_data_dir
except ImportError:
    from db_interface import DatabaseBackend
    from logger import log
    from config_manager import get_data_dir

# Use centralized data directory
DB_PATH = os.path.join(get_data_dir(), "honeypot.sqlite")

class HoneyDB(DatabaseBackend):
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()
        self.skeleton_cache = []
        self._load_skeleton()

    def _load_skeleton(self):
        try:
            from .fs_seeder import get_skeleton_data
            self.skeleton_cache = get_skeleton_data()
            log.info(f"[*] Loaded {len(self.skeleton_cache)} skeleton items (COW Layer)")
        except ImportError:
            # Fallback for direct testing
            try:
                from fs_seeder import get_skeleton_data
                self.skeleton_cache = get_skeleton_data()
            except:
                log.warning("[!] Failed to load skeleton data")

    def _init_db(self):
        # Directory creation handled by get_data_dir()
            
        conn = sqlite3.connect(self.db_path)
        # Enable WAL mode for better concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        c = conn.cursor()
        
        # Sessions Table
        c.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            remote_ip TEXT,
            username TEXT,
            password TEXT,
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME,
            client_version TEXT
        )''')

        # Interactions Log (Audit Trail)
        c.execute('''CREATE TABLE IF NOT EXISTS interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cwd TEXT,
            command TEXT,
            response TEXT,
            request_md5 TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        )''')

        # Global Filesystem Table (Simulated File System)
        c.execute('''
            CREATE TABLE IF NOT EXISTS global_filesystem (
                path TEXT PRIMARY KEY,
                parent_path TEXT,
                type TEXT,
                metadata TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_parent ON global_filesystem(parent_path)')

        # User-Specific Filesystem (Isolated Uploads)
        # Scoped by IP and Username
        c.execute('''
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
        ''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_user_parent ON user_filesystem(ip, username, parent_path)')

        # Cache Table (Simulated State)
        c.execute('''CREATE TABLE IF NOT EXISTS command_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cmd_hash TEXT UNIQUE,
            command TEXT,
            cwd TEXT,
            response TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

        # Auth Events Log (Login Attempts)
        c.execute('''CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            username TEXT,
            auth_method TEXT,
            auth_data TEXT,
            success BOOLEAN,
            client_version TEXT,
            fingerprint TEXT
        )''')
        
        # Threat Analysis Table
        c.execute('''CREATE TABLE IF NOT EXISTS command_analysis (
            command_hash TEXT PRIMARY KEY,
            command_text TEXT,
            activity_type TEXT,
            stage TEXT,
            risk_score INTEGER,
            explanation TEXT,
            analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Custom Migrations
        try:
            c.execute("ALTER TABLE sessions ADD COLUMN fingerprint TEXT")
        except sqlite3.OperationalError: pass

        try:
            c.execute("ALTER TABLE auth_events ADD COLUMN fingerprint TEXT")
        except sqlite3.OperationalError: pass
            
        try:
            c.execute("ALTER TABLE interactions ADD COLUMN source TEXT")
        except sqlite3.OperationalError: pass

        try:
            c.execute("ALTER TABLE interactions ADD COLUMN request_md5 TEXT")
        except sqlite3.OperationalError: pass

        try:
            c.execute("ALTER TABLE user_filesystem ADD COLUMN last_accessed DATETIME")
        except sqlite3.OperationalError: pass

        try:
            c.execute("ALTER TABLE user_filesystem ADD COLUMN is_deleted BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError: pass

        # Requested URLs Log (Network Intelligence)
        c.execute('''CREATE TABLE IF NOT EXISTS requested_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            session_id TEXT,
            url TEXT,
            method TEXT,
            user_agent TEXT,
            command_text TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(session_id)
        )''')

        conn.commit()
        conn.close()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, timeout=30.0)
    
    def log_url_request(self, session_id, url, method="GET", user_agent=None, command_text=None):
        conn = self._get_conn()
        try:
            conn.execute('''
                INSERT INTO requested_urls (session_id, url, method, user_agent, command_text)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, url, method, user_agent, command_text))
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error logging URL request: {e}")
        finally:
            conn.close()
    
    def log_auth_event(self, client_ip, username, auth_method, auth_data, success, client_version, fingerprint=None):
        try:
            fp_json = "{}"
            if fingerprint:
                fp_json = json.dumps(fingerprint)

            conn = self._get_conn()
            c = conn.cursor()
            c.execute('''
                INSERT INTO auth_events (client_ip, username, auth_method, auth_data, success, client_version, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (client_ip, username, auth_method, auth_data, success, client_version, fp_json))
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"[!] DB Error log_auth_event: {e}")

    def start_session(self, session_id, ip, username, password, client_version, fingerprint=None):
        conn = self._get_conn()
        
        fp_json = "{}"
        if fingerprint:
             fp_json = json.dumps(fingerprint)
             
        conn.execute("INSERT INTO sessions (session_id, remote_ip, username, password, client_version, fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
                     (session_id, ip, username, password, client_version, fp_json))
        conn.commit()
        conn.close()

    def end_session(self, session_id):
        conn = self._get_conn()
        conn.execute("UPDATE sessions SET end_time = CURRENT_TIMESTAMP WHERE session_id = ?", (session_id,))
        conn.commit()
        conn.close()

    def log_interaction(self, session_id, cwd, command, response, source="unknown", was_cached=False, duration_ms=0, request_md5=None):
        # Defensive Type Casting to prevent SQLite InterfaceError with dicts
        try:
            if isinstance(source, dict) or isinstance(source, list):
                 log.warning(f"[DB] Warning: 'source' param was {type(source)} (Val: {source}), casting to str.")
                 source = str(source.get('source', str(source))) if isinstance(source, dict) else str(source)
            else:
                 source = str(source)

            if request_md5 and (isinstance(request_md5, dict) or isinstance(request_md5, list)):
                 log.warning(f"[DB] Warning: 'request_md5' param was {type(request_md5)}, casting to str.")
                 request_md5 = str(request_md5)
        except Exception as caste:
            log.error(f"[DB] Critical Cast Error: {caste}")
            source = "error_casting"

        conn = self._get_conn()
        try:
            conn.execute("INSERT INTO interactions (session_id, cwd, command, response, source, request_md5) VALUES (?, ?, ?, ?, ?, ?)",
                        (session_id, cwd, command, response, source, request_md5))
            conn.commit()
        except Exception as e:
            log.error(f"[DB] Error logging interaction: {e}")
        finally:
            conn.close()

        # Update JSON Log
        try:
            timestamp = time.time()
            user = "unknown"
            ip = "unknown"
            try:
                conn = self._get_conn()
                c = conn.cursor()
                c.execute("SELECT username, remote_ip FROM sessions WHERE session_id = ?", (session_id,))
                row = c.fetchone()
                if row:
                    user = row[0]
                    ip = row[1]
                conn.close()
            except: pass

            log_entry = {
                "timestamp": timestamp,
                "session_id": session_id,
                "ip": ip,
                "user": user,
                "cwd": cwd,
                "command": command,
                "response_len": len(response),
                "source": source,
                "cached": was_cached,
                "response_time_ms": duration_ms,
                "request_md5": request_md5
            }
            
            log_file = self.db_path.replace(".sqlite", ".json.log")
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            log.error(f"Error writing to JSON log: {e}")

    def get_cached_response(self, command, cwd):
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

    def list_fs_dir(self, parent_path):
        conn = self._get_conn()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM global_filesystem WHERE parent_path = ?", (parent_path,))
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
            conn.execute("""
                INSERT OR REPLACE INTO global_filesystem (path, parent_path, type, metadata, content)
                VALUES (?, ?, ?, ?, ?)
            """, (path, parent_path, type, json.dumps(metadata) if isinstance(metadata, dict) else metadata, content))
            conn.commit()
        finally:
            conn.close()

    def update_user_file(self, ip, username, path, parent_path, type, metadata, content=None):
        conn = self._get_conn()
        
        # Ensure content is string
        if isinstance(content, (dict, list)):
            content = str(content)
            
        try:
            conn.execute("""
                INSERT OR REPLACE INTO user_filesystem (ip, username, path, parent_path, type, metadata, content, is_deleted)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """, (ip, username, path, parent_path, type, json.dumps(metadata) if isinstance(metadata, dict) else metadata, content))
            conn.commit()
            
            # recursive directory creation
            if type == 'file':
                self._ensure_parent_dirs(conn, ip, username, parent_path)
            elif type == 'directory':
                 # also ensure parents of this directory exist
                 self._ensure_parent_dirs(conn, ip, username, parent_path)
                 
            conn.commit()
        finally:
            conn.close()

    def get_user_node(self, ip, username, path):
        # 1. Check User DB (Modifications)
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM user_filesystem WHERE ip = ? AND username = ? AND path = ?", (ip, username, path))
        row = c.fetchone()
        
        result = None
        if row:
            columns = [col[0] for col in c.description]
            result = dict(zip(columns, row))
        conn.close()
        
        if result:
            # Check for Tombstone
            if result.get('is_deleted'):
                return None

            # Touch access time for aggressive cleanup tracking
            self.touch_user_file(ip, username, path)
            return result

        # 2. Check Skeleton (COW Layer)
        # Resolve home dir
        home_dir = "/root" if username == "root" else f"/home/{username}"
        
        for item in self.skeleton_cache:
            skel_path = item['path']
            # Dynamic Home Replacement
            if skel_path.startswith('~'):
                resolved_path = skel_path.replace('~', home_dir, 1)
            else:
                resolved_path = skel_path
                
            if resolved_path == path:
                 # Found in skeleton! Return ephemeral node.
                 # We need to construct a node dict similar to DB row
                 meta = item.get('metadata', {}).copy()
                 if 'owner' not in meta: meta['owner'] = username
                 if 'group' not in meta: meta['group'] = username
                 
                 return {
                     'ip': ip,
                     'username': username,
                     'path': resolved_path,
                     'type': item['type'],
                     'metadata': json.dumps(meta),
                     'content': item.get('content'),
                     'created_at': datetime.datetime.now().isoformat() # Fake TS
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
        # 1. Fetch DB items
        conn = self._get_conn()
        c = conn.cursor()
        db_items = []
        try:
            c.execute("SELECT * FROM user_filesystem WHERE ip = ? AND username = ? AND parent_path = ?", (ip, username, parent_path))
            rows = c.fetchall()
            columns = [col[0] for col in c.description]
            db_items = [dict(zip(columns, r)) for r in rows]
        finally:
            conn.close()
            
        # 2. Merge Skeleton items
        # To avoid duplicates if user modified them (and they exist in DB), track known names
        known_names = set(os.path.basename(i['path']) for i in db_items)
        
        home_dir = "/root" if username == "root" else f"/home/{username}"
        
        for item in self.skeleton_cache:
            skel_path = item['path']
            if skel_path.startswith('~'):
                resolved_path = skel_path.replace('~', home_dir, 1)
            else:
                resolved_path = skel_path
            
            item_parent = os.path.dirname(resolved_path)
            if item_parent == parent_path:
                filename = os.path.basename(resolved_path)
                if filename not in known_names:
                     meta = item.get('metadata', {}).copy()
                     if 'owner' not in meta: meta['owner'] = username
                     if 'group' not in meta: meta['group'] = username
                     
                     db_items.append({
                         'ip': ip,
                         'username': username,
                         'path': resolved_path,
                         'type': item['type'],
                         'metadata': json.dumps(meta),
                         'content': item.get('content'),
                         'created_at': datetime.datetime.now().isoformat()
                     })
                     known_names.add(filename) # Update known names for subsequent layers

        # 3. Merge Global DB items (Layer 3)
        conn = self._get_conn()
        try:
            c = conn.cursor()
            c.execute("SELECT * FROM global_filesystem WHERE parent_path = ?", (parent_path,))
            rows = c.fetchall()
            columns = [col[0] for col in c.description]
            for r in rows:
                g_item = dict(zip(columns, r))
                filename = os.path.basename(g_item['path'])
                if filename not in known_names:
                    # Adapt global item to user node format
                    db_items.append({
                         'ip': ip,
                         'username': username,
                         'path': g_item['path'],
                         'type': g_item['type'],
                         'metadata': g_item['metadata'],
                         'content': g_item['content'],
                         'created_at': g_item['created_at']
                    })
                    known_names.add(filename)
        except Exception as e:
            log.error(f"Error merging global FS in list_user_dir: {e}")
        finally:
             conn.close()
                     
        # Final filter: remove any items where we found a tombstone (is_deleted=1) in DB items
        # Currently list_user_dir fetches ALL from DB.
        # We need to filter out the ones that are is_deleted=1 from the final list.
        # But wait, db_items contains them! 
        
        final_list = []
        deleted_paths = set()
        
        for item in db_items:
             if item.get('is_deleted'):
                 deleted_paths.add(item['path'])
             else:
                 final_list.append(item)
                 
        # Now check skeleton items
        # Currently skeleton logic simply appends if filename not in known_names.
        # known_names should INCLUDE deleted items so we don't re-add skeleton version of a deleted file.
        
        # Re-calc known names from ALL db items (including deleted)
        known_names = set(os.path.basename(i['path']) for i in db_items)
        
        # Wait, if I deleted 'foo', it is in db_items with is_deleted=1.
        # So 'foo' is in known_names.
        # The loop below: if filename not in known_names -> skips 'foo'.
        # This is CORRECT! The deleted record "shadows" the skeleton record.
        # And we filtered 'foo' (deleted) out of final_list above.
        # So 'foo' will not appear.
        
        # We just need to replace db_items with final_list + valid skeleton items
        
        db_items = final_list 
                     
        return db_items

    def cache_response(self, command, cwd, response):
        h = hashlib.sha256(f"{cwd}:{command}".encode()).hexdigest()
        conn = self._get_conn()
        conn.execute("INSERT OR REPLACE INTO command_cache (cmd_hash, command, cwd, response) VALUES (?, ?, ?, ?)",
                     (h, command, cwd, response))
        conn.commit()
        conn.close()

    def get_ip_upload_usage(self, ip):
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("SELECT metadata FROM user_filesystem WHERE ip = ? AND is_deleted = 0", (ip,))
        rows = c.fetchall()
        conn.close()
        
        total_size = 0
        for r in rows:
            try:
                meta = json.loads(r[0]) if isinstance(r[0], str) else (r[0] or {})
                total_size += int(meta.get('size', 0))
            except: pass
            
        return total_size

    def prune_uploads(self, days=30):
        cutoff_time = datetime.datetime.now() - datetime.timedelta(days=days)
        
        conn = self._get_conn()
        c = conn.cursor()
        
        # Use COALESCE to fallback to created_at if last_accessed is NULL (never read)
        # This implements: "Assume NULL means it was last accessed at create time"
        # AND is_deleted = 0: Do NOT prune tombstones (which would cause ghost files to reappear from skeleton)
        c.execute("SELECT ip, username, path FROM user_filesystem WHERE COALESCE(last_accessed, created_at) < ? AND is_deleted = 0", (cutoff_time,))
        to_delete = c.fetchall()
        
        c.execute("DELETE FROM user_filesystem WHERE COALESCE(last_accessed, created_at) < ? AND is_deleted = 0", (cutoff_time,))
        conn.commit()
        conn.close()
        
        return [{'ip': r[0], 'username': r[1], 'path': r[2]} for r in to_delete]

    def touch_user_file(self, ip, username, path):
        """
        Updates the last_accessed timestamp for a user file to prevent cleanup.
        """
        try:
            conn = self._get_conn()
            conn.execute("""
                UPDATE user_filesystem 
                SET last_accessed = CURRENT_TIMESTAMP 
                WHERE ip=? AND username=? AND path=?
            """, (ip, username, path))
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
             # Or just insert minimal info.
             
             # If we just allow NULLs for others? schema allows?
             # user_filesystem has no NOT NULL except PK?
             # PK is ip, username, path.
             
             parent_path = os.path.dirname(path)
             conn.execute("""
                INSERT OR REPLACE INTO user_filesystem (ip, username, path, parent_path, is_deleted)
                VALUES (?, ?, ?, ?, 1)
             """, (ip, username, path, parent_path))
             conn.commit()
         except Exception as e:
             log.error(f"[DB] Error deleting user file (tombstone) {path}: {e}")
         finally:
             conn.close()

    def get_global_stats(self):
        """Returns aggregate server statistics."""
        conn = self._get_conn()
        stats = {
            "sessions": 0,
            "unique_ips": 0,
            "total_commands": 0
        }
        try:
            c = conn.cursor()
            c.execute("SELECT count(*) FROM sessions")
            row = c.fetchone()
            if row: stats["sessions"] = row[0]

            c.execute("SELECT count(distinct remote_ip) FROM sessions")
            row = c.fetchone()
            if row: stats["unique_ips"] = row[0]

            c.execute("SELECT count(*) FROM interactions")
            row = c.fetchone()
            if row: stats["total_commands"] = row[0]
        except Exception as e:
            log.error(f"Error fetching global stats: {e}")
        finally:
            conn.close()
        return stats

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
                if os.path.basename(r[2]).startswith('-'):
                    c.execute("DELETE FROM user_filesystem WHERE ip=? AND username=? AND path=?", r)
                    deleted_user += 1

            # 2. Global Filesystem
            c.execute("SELECT path FROM global_filesystem")
            rows = c.fetchall()
            for r in rows:
                if os.path.basename(r[0]).startswith('-'):
                    c.execute("DELETE FROM global_filesystem WHERE path=?", (r[0],))
                    deleted_global += 1

            conn.commit()
            if deleted_user or deleted_global:
                log.info(f"[DB] Auto-Sanitized Artifacts: {deleted_user} User, {deleted_global} Global")
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
            c.execute("SELECT is_deleted FROM user_filesystem WHERE ip=? AND username=? AND path=?", (ip, username, path))
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
        if not path or path == '/' or path == '.':
            return
            
        # Check if exists
        c = conn.cursor()
        c.execute("SELECT 1 FROM user_filesystem WHERE ip=? AND username=? AND path=?", (ip, username, path))
        if c.fetchone():
            return # Exists
            
        # Does not exist, create it
        parent_path = os.path.dirname(path)
        
        # Ensure parent exists first (recursion)
        self._ensure_parent_dirs(conn, ip, username, parent_path)
        
        # Create this directory
        now = datetime.datetime.now().strftime("%b %d %H:%M")
        meta = {
            'permissions': 'drwxr-xr-x', # Default dir perms
            'size': 4096,
            'owner': username,
            'group': username,
            'modified': now
        }
        
        try:
            c.execute("""
                INSERT OR IGNORE INTO user_filesystem (ip, username, path, parent_path, type, metadata, content)
                VALUES (?, ?, ?, ?, 'directory', ?, NULL)
            """, (ip, username, path, parent_path, json.dumps(meta)))
        except Exception as e:
            log.error(f"[DB] Error creating parent dir {path}: {e}")

    def get_unique_creds_last_24h(self, ip):
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        conn = self._get_conn()
        c = conn.cursor()
        creds = set()
        
        try:
             c.execute("SELECT username, password FROM sessions WHERE remote_ip = ? AND start_time > ?", (ip, cutoff))
             for row in c.fetchall():
                 creds.add((row[0], row[1]))
        except Exception as e:
             log.error(f"Error querying sessions for creds: {e}")

        try:
             c.execute("SELECT username, auth_data FROM auth_events WHERE client_ip = ? AND success = 1 AND auth_method='password' AND timestamp > ?", (ip, cutoff))
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
            conn.execute("""
                INSERT OR IGNORE INTO command_analysis 
                (command_hash, command_text, activity_type, stage, risk_score, explanation)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                cmd_hash, 
                cmd_text, 
                analysis.get('type', 'Unknown'),
                analysis.get('stage', 'Unknown'),
                analysis.get('risk', 0),
                analysis.get('explanation', '')
            ))
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
                'hash': row[0],
                'text': row[1],
                'type': row[2],
                'stage': row[3],
                'risk': row[4],
                'explanation': row[5],
                'analyzed_at': row[6]
            }
        return None
