import pytest
from unittest.mock import MagicMock
from ssh_honeypot.command_handler import CommandHandler
import os

class TestVFSPopulation:
    @pytest.fixture
    def mock_db(self):
        # Use Real DB in memory for persistence check
        from ssh_honeypot.honey_db import HoneyDB
        import sqlite3
        
        # Shared connection for :memory: persistence
        shared_conn = sqlite3.connect(':memory:')
        
        # Patch _get_conn to return shared_conn
        # We need to ensure it doesn't close the shared connection on .close()
        # So we wrap it or just accept that HoneyDB calls close() and we might need to prevent it?
        # HoneyDB calls conn.close(). 
        # If we return the same object, it will be closed.
        # We need a cursor-like wrapper or just a check?
        # Easiest: Use a file-based DB for test (tempfile) OR monkeypatch close.
        
        class SharedConnDB(HoneyDB):
            def __init__(self):
                self.shared = shared_conn
                # Manually init schema on shared conn
                super().__init__(':memory:') # overrides db_path but we hijack connection
                
            def _get_conn(self):
                # Return a proxy that ignores close()
                class ConnProxy:
                    def __init__(self, real_conn):
                        self.real = real_conn
                    def cursor(self): return self.real.cursor()
                    def execute(self, *args, **kwargs): return self.real.execute(*args, **kwargs)
                    def commit(self): return self.real.commit()
                    def close(self): pass # No-op
                    @property
                    def row_factory(self): return self.real.row_factory
                    @row_factory.setter
                    def row_factory(self, val): self.real.row_factory = val
                    
                return ConnProxy(self.shared)
                
            def _init_db(self):
                # Init on shared conn
                conn = self._get_conn()
                # Copy schema logic from HoneyDB._init_db or rely on inheritance if we mock _get_conn first?
                # _init_db calls _get_conn? No, it calls sqlite3.connect(self.db_path).
                # So we must override _init_db to use our shared conn too.
                # Actually, simpler:
                # 1. Create HoneyDB
                # 2. Patch ._get_conn
                # 3. Call ._init_db() manually (schema creation)
                pass

        # Let's try simpler patching approach
        db = HoneyDB(':memory:')
        
        # Re-initialize properly with shared connection logic
        # 1. Create shared connection
        shared_conn = sqlite3.connect(':memory:')
        
        # 2. Apply Schema manually or via helper
        # We can reuse the SQL from HoneyDB._init_db but it's hardcoded.
        # Better: Instantiate HoneyDB, then replace _get_conn.
        # BUT _init_db runs in __init__.
        # So we must MonkeyPatch sqlite3.connect?
        
        # Easier: Use a temporary file instead of :memory:
        # This avoids all sharing issues.
        import tempfile
        import os
        
        fd, path = tempfile.mkstemp(suffix='.sqlite')
        os.close(fd)
        
        db = HoneyDB(path)
        # Auto-init works because it's a file
        
        yield db
        
        # Cleanup
        if os.path.exists(path):
            os.remove(path)

    @pytest.fixture
    def mock_llm(self):
        return MagicMock()

    @pytest.fixture
    def handler(self, mock_llm, mock_db):
        return CommandHandler(mock_llm, mock_db)

    def test_ls_shows_vfs_files(self, handler):
        user = "royans"
        cwd = f"/home/{user}"
        vfs = {
            cwd: ["default_file.txt", "secret.key"]
        }
        
        context = {
            'cwd': cwd,
            'user': user,
            'vfs': vfs,
            'client_ip': '1.2.3.4'
        }
        
        resp, updates, meta = handler.process_command("ls", context)
        assert "default_file.txt" in resp
        assert "secret.key" in resp

    def test_ensure_user_home_persistence(self, handler, mock_db):
        from ssh_honeypot.utils import ensure_user_home
        
        user = "newuser"
        ip = "1.1.1.1"
        cwd = f"/home/{user}"
        
        # 1. Ensure empty initially
        files = mock_db.list_user_dir(ip, user, cwd)
        assert len(files) == 0
        
        # 1b. Simulate Pre-existing user file (Regression for "ABORT if not empty" bug)
        mock_db.update_user_file(ip, user, f"{cwd}/existing", cwd, 'file', {'size': 0}, "content")
        
        # 2. Call Seeder
        ensure_user_home(mock_db, ip, user)
        
        # 3. Check DB
        files = mock_db.list_user_dir(ip, user, cwd)
        assert len(files) > 1 # Should include 'existing' AND default files
        filenames = [f['path'].split('/')[-1] for f in files]
        assert "existing" in filenames
        assert "aws_keys.txt" in filenames
        assert ".bash_history" in filenames
        
        # 4. Check Handler Integration (mimic normal flow)
        context = {
            'cwd': cwd,
            'user': user,
            'client_ip': ip,
            'vfs': {} # Empty VFS, relies on DB
        }
        resp, _, _ = handler.process_command("ls", context)
        assert "aws_keys.txt" in resp
