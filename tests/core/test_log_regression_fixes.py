import os
import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.db_postgres import PostgresBackend


class TestLogRegressionFixes(unittest.TestCase):
    def test_none_persona_fix(self):
        # Mock dependencies
        llm = MagicMock()
        db = MagicMock()
        handler = CommandHandler(llm, db)

        # This used to crash when persona_config was None
        context = {"persona_config": None, "user": "root", "cwd": "/"}
        try:
            # We don't care about the result, just that it doesn't crash
            handler.process_command("ls", context)
        except AttributeError as e:
            self.fail(f"process_command crashed with None persona_config: {e}")
        except Exception:
            # Other exceptions are fine (mocked DB etc)
            pass

    @patch("ssh_honeypot.core.db_postgres.PostgresBackend.__init__", return_value=None)
    @patch("ssh_honeypot.core.db_postgres.PostgresBackend._init_pool")
    def test_postgres_clean_str(self, mock_init_pool, mock_init):
        # We don't need a real connection for this helper test
        db = PostgresBackend({})

        # Test NUL character removal
        dirty = "admin\x00user"
        clean = db._clean_str(dirty)
        self.assertEqual(clean, "adminuser")

        # Test None handling
        self.assertIsNone(db._clean_str(None))

        # Test non-string handling
        self.assertEqual(db._clean_str(123), "123")


if __name__ == "__main__":
    unittest.main()
