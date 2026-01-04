
import pytest
from unittest.mock import MagicMock
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.command_handler import CommandHandler
from ssh_honeypot.honey_db import HoneyDB

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
        
    def test_ls_wildcard(self, handler, db):
        ip = "1.2.3.4"
        user = "tester"
        cwd = "/home/tester"
        
        # 1. Create files
        db.update_user_file(ip, user, f"{cwd}/doc1.txt", cwd, 'file', {}, "content")
        db.update_user_file(ip, user, f"{cwd}/doc2.txt", cwd, 'file', {}, "content")
        db.update_user_file(ip, user, f"{cwd}/img1.png", cwd, 'file', {}, "content")
        
        # 2. Run ls *.txt
        context = {'cwd': cwd, 'user': user, 'client_ip': ip}
        resp, _, _ = handler.process_command("ls *.txt", context)
        
        # 3. Verify output
        assert "doc1.txt" in resp
        assert "doc2.txt" in resp
        assert "img1.png" not in resp
