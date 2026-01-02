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
            
        # Custom Migration for interactions source
        try:
            c.execute("ALTER TABLE interactions ADD COLUMN source TEXT")
        except sqlite3.OperationalError:
            pass

        # Custom Migration for interactions request_md5
        try:
            c.execute("ALTER TABLE interactions ADD COLUMN request_md5 TEXT")
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

    def log_interaction(self, session_id, cwd, command, response, source="unknown", was_cached=False, duration_ms=0, request_md5=None):
        conn = self._get_conn()
        conn.execute("INSERT INTO interactions (session_id, cwd, command, response, source) VALUES (?, ?, ?, ?, ?)",
                     (session_id, cwd, command, response, source))
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
                "cached": was_cached,
                "response_time_ms": duration_ms,
                "request_md5": request_md5
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

    def get_unique_creds_last_24h(self, ip):
        """
        Returns a set of unique (username, password) tuples that successfully logged in from this IP in the last 24 hours.
        Considers both 'sessions' (active/completed) and 'auth_events' (successful logins).
        """
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        
        conn = self._get_conn()
        c = conn.cursor()
        
        creds = set()
        
        # 1. Check sessions table (successfully established sessions)
        try:
             c.execute("SELECT username, password FROM sessions WHERE remote_ip = ? AND start_time > ?", (ip, cutoff))
             for row in c.fetchall():
                 creds.add((row[0], row[1]))
        except Exception as e:
             print(f"Error querying sessions for creds: {e}")

        # 2. Check auth_events (successful auths might not always result in a full session record depending on flow)
        try:
             c.execute("SELECT username, auth_data FROM auth_events WHERE client_ip = ? AND success = 1 AND auth_method='password' AND timestamp > ?", (ip, cutoff))
             for row in c.fetchall():
                 creds.add((row[0], row[1]))
        except Exception as e:
             print(f"Error querying auth_events for creds: {e}")
             
        conn.close()
        return creds

    # [NEW] Analysis Methods
    def get_unanalyzed_commands(self, limit=10):
        """
        Returns distinct commands (hash, text) from interactions that are NOT in command_analysis.
        This drives the async background thread.
        """
        conn = self._get_conn()
        c = conn.cursor()
        
        # We join on request_md5 to avoid re-hashing in Python if possible, 
        # but interactions has request_md5 column.
        # We want commands where request_md5 IS NOT NULL AND request_md5 NOT IN command_analysis
        
        query = """
            SELECT DISTINCT i.request_md5, i.command
            FROM interactions i
            WHERE i.request_md5 IS NOT NULL 
              AND i.request_md5 != 'unknown'
              AND i.request_md5 NOT IN (SELECT command_hash FROM command_analysis)
            LIMIT ?
        """
        c.execute(query, (limit,))
        results = c.fetchall()
        conn.close()
        return results

    def save_analysis(self, cmd_hash, cmd_text, analysis):
        """
        Saves LLM analysis.
        analysis = {'type':..., 'stage':..., 'risk':..., 'explanation':...}
        """
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
            print(f"[DB] Error saving analysis: {e}")
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
