import unittest
from unittest.mock import MagicMock
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB
import os
import time


class TestCachingIntegration(unittest.TestCase):
    def setUp(self):
        self.db_path = "/tmp/test_caching_integ.sqlite"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.db = HoneyDB(self.db_path)
        self.llm = MagicMock()

        # Clear global cache to prevent pollution from other tests
        from ssh_honeypot.core.cache import cache

        cache._fallback_cache = {}

        self.handler = CommandHandler(self.llm, self.db)
        self.context = {
            "cwd": "/",
            "vfs": {"/tmp": []},
            "env": {},
            "db": self.db,
            "llm": self.llm,
            "persona_config": {"name": "test_persona"},
        }

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_url_exclusion(self):
        # Command with URL should not be cached
        cmd = "echo http://example.com"

        # First call
        _, _, meta1 = self.handler.process_command(cmd, self.context)
        self.assertFalse(meta1.get("cached"))

        # Second call
        _, _, meta2 = self.handler.process_command(cmd, self.context)
        self.assertFalse(meta2.get("cached"), "Command with URL was cached!")

    def test_chain_cache_metadata(self):
        # 1. Warm up cache for individual commands
        self.handler.process_command("echo 1", self.context)
        self.handler.process_command("whoami", self.context)

        # 2. Test chain-cache (100% hits)
        cmd_full = "echo 1; whoami"
        _, _, meta_full = self.handler.process_command(cmd_full, self.context)
        self.assertEqual(meta_full["source"], "chain-cache")
        self.assertTrue(meta_full["cached"])

        # 3. Test chain-pcache (partial hits)
        cmd_partial = "echo 1; uname -a"  # uname -a not cached yet
        _, _, meta_partial = self.handler.process_command(cmd_partial, self.context)
        self.assertEqual(meta_partial["source"], "chain-pcache")
        self.assertFalse(meta_partial["cached"])

    def test_conditional_chain_cache(self):
        # Warm up 'echo 1'
        self.handler.process_command("echo 1", self.context)

        # 1. Successful && chain (all cached)
        self.handler.process_command("echo 2", self.context)
        cmd_succ = "echo 1 && echo 2"
        _, _, meta_succ = self.handler.process_command(cmd_succ, self.context)
        self.assertEqual(meta_succ["source"], "chain-cache")

        # 2. Short-circuited && chain
        # 'false' is not a local handler, so it goes to LLM (cached permanently in DB)
        self.llm.generate_response.return_value = "bash: false: command not found"
        self.handler.process_command("false", self.context)

        cmd_short = "false && echo 1"
        _, _, meta_short = self.handler.process_command(cmd_short, self.context)
        # 'false' was cached, 'echo 1' was never executed
        self.assertEqual(meta_short["source"], "chain-cache")
        self.assertTrue(meta_short["cached"])


if __name__ == "__main__":
    unittest.main()
