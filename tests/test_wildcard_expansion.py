
import pytest
from unittest.mock import MagicMock
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB

class TestWildcardExpansion:

    @pytest.fixture
    def db(self, tmp_path):
        db_file = tmp_path / "test_wildcard.sqlite"
        db = HoneyDB(str(db_file))
        return db

    @pytest.fixture
    def handler(self, db):
        mock_llm = MagicMock()
        return CommandHandler(mock_llm, db)

    def test_rm_wildcard(self, handler, db):
        ip = "1.2.3.4"
        user = "tester"
        cwd = "/home/tester"
        
        # 1. Create files that match pattern
        db.update_user_file(ip, user, f"{cwd}/test1.sql", cwd, 'file', {}, "content")
        db.update_user_file(ip, user, f"{cwd}/test2.sql", cwd, 'file', {}, "content")
        db.update_user_file(ip, user, f"{cwd}/other.txt", cwd, 'file', {}, "content")
        
        # 2. Run rm *.sql
        context = {'cwd': cwd, 'user': user, 'client_ip': ip}
        resp, _, _ = handler.process_command("rm *.sql", context)
        
        # 3. Verify files are gone
        items = db.list_user_dir(ip, user, cwd)
        filenames = [os.path.basename(i['path']) for i in items]
        
        if "test1.sql" in filenames:
             pytest.fail(f"Wildcard 'rm *.sql' failed to delete test1.sql. Response: {resp}")
             
        assert "test1.sql" not in filenames
        assert "test2.sql" not in filenames
        assert "other.txt" in filenames # Should NOT be deleted
        
    # test_ls_wildcard moved to tests/test_command_handler_ls.py

