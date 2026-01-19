import unittest
import os
import shutil
import json
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB
from unittest.mock import patch


class MockLLM:
    def generate_response(self, *args, **kwargs):
        return "MOCKED Response", {}


class TestRegressionFixes(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_regression.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.db = HoneyDB(self.db_path)
        self.llm = MockLLM()
        self.handler = CommandHandler(self.llm, self.db)
        self.context = {
            "cwd": "/home/royans",
            "user": "royans",
            "client_ip": "127.0.0.1",
            "env": {"HOME": "/home/royans"},
        }

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    # --- Feature: Tilde Redirection (Fix for ~ path redirection) ---
    def test_tilde_redirection(self):
        # clean
        path = "/home/royans/.ssh/authorized_keys"
        # ensure parent exists (initially empty)

        cmd = "echo 'ssh-rsa AAA' > ~/.ssh/authorized_keys"
        resp, updates, meta = self.handler.process_command(cmd, self.context)

        # Check in DB
        node = self.db.get_user_node("127.0.0.1", "royans", path)
        self.assertIsNotNone(node, "File should exist after redirection to ~ path")
        self.assertIn("ssh-rsa AAA", node.get("content", ""))

    # --- Bug: debug_vfs crash (Fix for None dir and crash handling) ---
    def test_debug_vfs_robustness(self):
        # 1. Test None handling (should default to root)
        report = self.db.inspect_dir("127.0.0.1", "root", None)
        self.assertIn("--- VFS Directory Inspection", report)

        # 2. Test empty string
        report = self.db.inspect_dir("127.0.0.1", "root", "")
        self.assertIn("--- VFS Directory Inspection", report)

        # 3. Test debug_vfs command via handler (crash prevention)
        # Should catch exceptions if any logic fails inner db call
        # (We mocked db so it won't crash, but validation logic is in handler too)

        # We must patch get_ignored_ips to allow 127.0.0.1 access to debug_* commands
        with patch(
            "ssh_honeypot.core.command_handler.get_ignored_ips",
            return_value=["127.0.0.1"],
        ):
            resp, _, _ = self.handler.process_command("debug_vfs", self.context)

        self.assertIn("VFS Directory Inspection", resp)

    # --- Bug: Deleted Directory Revival (Fix for _ensure_parent_dirs) ---
    def test_revive_deleted_directory(self):
        ip = "127.0.0.1"
        user = "testuser"
        path = "/home/testuser/subdir"
        conn = self.db._get_conn()

        try:
            # 1. Create directory manually via ensure_parents
            self.db._ensure_parent_dirs(conn, ip, user, path)

            # 2. Mark as deleted (Simulate 'rm -rf')
            conn.execute(
                "UPDATE user_filesystem SET is_deleted=1 WHERE path=?", (path,)
            )
            conn.commit()

            # Verify deleted
            cur = conn.cursor()
            cur.execute("SELECT is_deleted FROM user_filesystem WHERE path=?", (path,))
            self.assertEqual(cur.fetchone()[0], 1)

            # 3. Create a child file (requiring parent revival)
            child = "/home/testuser/subdir/file"
            self.db._ensure_parent_dirs(conn, ip, user, child)

            # 4. Verify parent revived
            cur.execute("SELECT is_deleted FROM user_filesystem WHERE path=?", (path,))
            self.assertEqual(cur.fetchone()[0], 0, "Directory should be revived")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
