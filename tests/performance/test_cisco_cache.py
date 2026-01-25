import time
import unittest
from unittest.mock import MagicMock
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB
import os


class TestCiscoPerformance(unittest.TestCase):
    def setUp(self):
        # Use in-memory DB or temporary file
        self.db_path = "/tmp/test_perf_cisco.sqlite"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.db = HoneyDB(self.db_path)

        self.llm = MagicMock()
        self.handler = CommandHandler(self.llm, self.db)

        # Mock Persona Config for Cisco
        self.context = {
            "persona_config": {
                "name": "cisco_ios_test",
                "system": {"handler_type": "cisco_ios"},
                "defaults": {"running_config": "version 15.0\nhostname Router\nend"},
            },
            "env": {"privilege_level": 15},
            "cwd": "/",
            "vfs": {},
            "db": self.db,
            "llm": self.llm,
        }

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_show_version_caching(self):
        cmd = "show version"

        # 1. First Call (Miss)
        start = time.time()
        resp1, _, meta1 = self.handler.process_command(cmd, self.context)
        duration1 = time.time() - start

        print(
            f"\n[Perf] First '{cmd}' took {duration1*1000:.2f}ms (Source: {meta1['source']})"
        )

        # 2. Second Call (Hit)
        start = time.time()
        resp2, _, meta2 = self.handler.process_command(cmd, self.context)
        duration2 = time.time() - start

        print(
            f"[Perf] Second '{cmd}' took {duration2*1000:.2f}ms (Source: {meta2['source']})"
        )

        self.assertEqual(resp1, resp2)
        self.assertEqual(meta2["source"], "handler-cache")
        self.assertTrue(
            duration2 < duration1 or duration2 < 0.05
        )  # Cache should be very fast

    def test_show_run_persistent_caching(self):
        cmd = "show running-config"

        # Setup LLM to return a config (if not provided in defaults)
        # We'll remove defaults to force LLM
        self.context["persona_config"]["defaults"] = {}
        self.llm.generate_response.return_value = "hostname LLM_ROUTER\nversion 15.0"

        # 1. First Call (LLM Generate)
        resp1, _, _ = self.handler.process_command(cmd, self.context)
        self.llm.generate_response.assert_called_once()

        # 2. Second Call in NEW context (Simulate new session)
        new_context = self.context.copy()
        new_context["env"] = {"privilege_level": 15}  # Reset env

        resp2, _, _ = self.handler.process_command(cmd, new_context)

        # LLM should NOT be called again
        self.llm.generate_response.assert_called_once()
        self.assertIn("LLM_ROUTER", resp2)


if __name__ == "__main__":
    unittest.main()
