import sqlite3
import datetime
import hashlib
import os
import json
import time

try:
    from .db_interface import DatabaseBackend
except ImportError:
    from db_interface import DatabaseBackend

# Resolve absolute path relative to this file (ssh_honeypot/honey_db.py -> ssh_honeypot/../data/honeypot.sqlite)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "honeypot.sqlite")

class HoneyDB(DatabaseBackend):
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
            
        conn = sqlite3.connect(self.db_path)
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
                PRIMARY KEY (ip, username, path)
            )
        ''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_user_parent ON user_filesystem(ip, username, parent_path)')

        # Cache Table (Simulated State)
        # We assume command output depends on: The Command itself + Current Working Directory
        # This is a simplification. A real shell depends on much more, but this is a honeypot.
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
            client_version TEXT
        )''')
        
        # Custom Migration for Fingerprint
        try:
            print("Attempting migration: Adding fingerprint column")
            c.execute("ALTER TABLE sessions ADD COLUMN fingerprint TEXT")
        except sqlite3.OperationalError as e:
            # print(f"Migration note: {e}")
            pass

        # Custom Migration for auth_events fingerprint
        try:
            c.execute("ALTER TABLE auth_events ADD COLUMN fingerprint TEXT")
        except sqlite3.OperationalError:
            pass

        conn.commit()
        conn.close()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)
    
    def log_auth_event(self, client_ip, username, auth_method, auth_data, success, client_version, fingerprint=None):
        """
        Logs an authentication attempt.
        auth_data: password (if method='password') or key fingerprint/type
        """
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
            print(f"[!] DB Error log_auth_event: {e}")

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

    def log_interaction(self, session_id, cwd, command, response, source="unknown", was_cached=False):
        conn = self._get_conn()
        conn.execute("INSERT INTO interactions (session_id, cwd, command, response) VALUES (?, ?, ?, ?)",
                     (session_id, cwd, command, response))
        conn.commit()
        conn.close()

        # Update JSON Log
        try:
            timestamp = time.time()
            # Try to get extra session info for log
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
                "cached": was_cached
            }
            
            # Append to log file (assume data/honeypot.json.log based on DB Path)
            log_file = self.db_path.replace(".sqlite", ".json.log")
            
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Error writing to JSON log: {e}")

    def get_cached_response(self, command, cwd):
        # We hash cmd + cwd to create a unique key
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
        try:
            conn.execute("""
                INSERT OR REPLACE INTO user_filesystem (ip, username, path, parent_path, type, metadata, content)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip, username, path, parent_path, type, json.dumps(metadata) if isinstance(metadata, dict) else metadata, content))
            conn.commit()
        finally:
            conn.close()

    def get_user_node(self, ip, username, path):
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("SELECT * FROM user_filesystem WHERE ip = ? AND username = ? AND path = ?", (ip, username, path))
        row = c.fetchone()
        result = None
        if row:
            columns = [col[0] for col in c.description]
            result = dict(zip(columns, row))
        conn.close()
        return result

    def list_user_dir(self, ip, username, parent_path):
        conn = self._get_conn()
        c = conn.cursor()
        try:
            c.execute("SELECT * FROM user_filesystem WHERE ip = ? AND username = ? AND parent_path = ?", (ip, username, parent_path))
            rows = c.fetchall()
            columns = [col[0] for col in c.description]
            return [dict(zip(columns, r)) for r in rows]
        finally:
            conn.close()

    def cache_response(self, command, cwd, response):
        h = hashlib.sha256(f"{cwd}:{command}".encode()).hexdigest()
        conn = self._get_conn()
        # UPSERT logic (replace if exists)
        conn.execute("INSERT OR REPLACE INTO command_cache (cmd_hash, command, cwd, response) VALUES (?, ?, ?, ?)",
                     (h, command, cwd, response))
        conn.commit()
        conn.close()

    def get_ip_upload_usage(self, ip):
        """Calculates total bytes uploaded by an IP address."""
        conn = self._get_conn()
        c = conn.cursor()
        c.execute("SELECT metadata FROM user_filesystem WHERE ip = ?", (ip,))
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
        """
        Removes user uploads older than X days.
        Returns: List of details (ip, username, path) to help clean up vfs/disk if needed.
        """
        import time
        cutoff_time = datetime.datetime.now() - datetime.timedelta(days=days)
        
        conn = self._get_conn()
        c = conn.cursor()
        
        # Select files to be deleted
        c.execute("SELECT ip, username, path FROM user_filesystem WHERE created_at < ?", (cutoff_time,))
        to_delete = c.fetchall()
        
        # Delete them
        c.execute("DELETE FROM user_filesystem WHERE created_at < ?", (cutoff_time,))
        conn.commit()
        conn.close()
        
        return [{'ip': r[0], 'username': r[1], 'path': r[2]} for r in to_delete]

    def delete_user_file(self, ip, username, path):
         conn = self._get_conn()
         conn.execute("DELETE FROM user_filesystem WHERE ip=? AND username=? AND path=?", (ip, username, path))
         conn.commit()
         conn.close()
