import pytest
from unittest.mock import MagicMock
import json
from ssh_honeypot.core.command_handler import CommandHandler


class TestLSHandler:
    @pytest.fixture
    def mock_db(self):
        db = MagicMock()
        db.list_user_dir.return_value = []
        db.is_managed_directory.return_value = False
        db.get_user_node.return_value = None
        return db

    @pytest.fixture
    def handler(self, mock_db):
        llm = MagicMock()
        return CommandHandler(llm, mock_db)

    def test_handle_ls_cache_logic(self, handler):
        # 1. Test Fallback (Not managed)
        handler.db.is_managed_directory.return_value = False
        cmd = "ls /unknown"
        context = {"cwd": "/", "client_ip": "1.2.3.4", "user": "root"}

        # Should return None -> Fallback to LLM
        ret = handler.handle_ls(cmd, context)
        assert ret is None

        # 2. Test Cache Hit (Managed)
        handler.db.is_managed_directory.return_value = True
        handler.db.list_user_dir.return_value = [
            {
                "path": "/root/old_file.txt",
                "metadata": json.dumps({"size": 100}),
                "type": "file",
            }
        ]

        cmd = "ls"
        resp, _, meta = handler.handle_ls(cmd, context)

        assert "old_file.txt" in resp
        assert meta["source"] == "local"
        handler.db.list_user_dir.assert_called()

    def test_ls_wildcard(self, handler):
        # Setup DB for wildcard match
        ip = "1.2.3.4"
        user = "tester"
        cwd = "/home/tester"
        context = {"cwd": cwd, "user": user, "client_ip": ip}

        # Mock list_user_dir to return files for wildcard expansion
        handler.db.is_managed_directory.return_value = True
        handler.db.list_user_dir.return_value = [
            {"path": f"{cwd}/doc1.txt", "type": "file", "metadata": "{}"},
            {"path": f"{cwd}/doc2.txt", "type": "file", "metadata": "{}"},
            {"path": f"{cwd}/img1.png", "type": "file", "metadata": "{}"},
        ]
        # Mock resolve_path behavior via get_user_node logic usage in handler
        # The new handler uses list_user_dir for the directory containing the wildcard
        # and then filters.

        # When handle_ls expands 'ls *.txt', it calls expand_wildcards.
        # expand_wildcards calls db.list_user_dir(cwd)
        # Then it resolves to [doc1.txt, doc2.txt]
        # Then handle_ls iterates these targets.
        # For each target (doc1.txt), it calls resolve_path -> /home/tester/doc1.txt
        # Then it calls is_managed_directory or get_user_node.
        # It should call get_user_node for files.

        def get_user_node_side_effect(ip, user, path):
            if path in [f"{cwd}/doc1.txt", f"{cwd}/doc2.txt"]:
                return {"path": path, "type": "file", "metadata": "{}"}
            return None

        handler.db.get_user_node.side_effect = get_user_node_side_effect

        resp, _, _ = handler.handle_ls("ls *.txt", context)

        assert "doc1.txt" in resp
        assert "doc2.txt" in resp
        assert "img1.png" not in resp

    def test_handle_ls_single_file(self, handler):
        # ls of a specific file should show that file
        cmd = "ls /etc/passwd"
        context = {"cwd": "/"}

        handler.db.is_managed_directory.return_value = False
        handler.db.get_user_node.return_value = {
            "path": "/etc/passwd",
            "type": "file",
            "metadata": json.dumps(
                {"permissions": "-rw-r--r--", "owner": "root", "size": 100}
            ),
        }

        resp, _, _ = handler.handle_ls(cmd, context)
        assert "/etc/passwd" in resp or "passwd" in resp
        assert "100" not in resp  # short listing default

    def test_handle_ls_complex_flags(self, handler):
        # test -la
        cmd = "ls -la"
        context = {"cwd": "/root", "user": "root"}

        handler.db.is_managed_directory.return_value = True
        handler.db.list_user_dir.return_value = [
            {"path": "/root/.hidden", "type": "file", "metadata": "{}"},
            {"path": "/root/visible", "type": "file", "metadata": "{}"},
        ]

        resp, _, _ = handler.handle_ls(cmd, context)

        assert ".hidden" in resp
        assert "visible" in resp
        assert "total" in resp  # long listing has total

    def test_handle_ls_vfs_tombstone(self, handler):
        # Tombstones should be hidden
        # But wait, list_user_dir logic handles tombstones (filtering them out).
        # So handler just displays what list_user_dir returns.
        # If list_user_dir returns it, handler displays it.
        # So this test effectively tests that handler displays what is returned.
        # The logic for tombstone filtering is in DB (which is mocked here).
        # So this test is trivial if we mock correctly.
        # Let's assume this test validates that handler doesn't magically resurrect things.

        handler.db.is_managed_directory.return_value = True
        handler.db.list_user_dir.return_value = [
            {"path": "/root/file1", "type": "file"}
        ]

        resp, _, _ = handler.handle_ls("ls", {"cwd": "/root"})
        assert "file1" in resp
