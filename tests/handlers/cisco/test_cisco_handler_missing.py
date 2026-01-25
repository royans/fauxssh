import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.command_handler import CommandHandler


class TestMissingHelper(unittest.TestCase):
    def test_missing_handler_fallback(self):
        # Mock LLM/DB
        mock_llm = MagicMock()
        mock_db = MagicMock()

        # Initialize
        handler = CommandHandler(mock_llm, mock_db)

        # Patch the MODULE level variable in command_handler
        # 'ssh_honeypot.core.command_handler.cisco_handlers'
        with patch("ssh_honeypot.core.command_handler.cisco_handlers", None):
            context = {
                "persona_config": {"system": {"handler_type": "cisco_ios"}},
                "env": {},
                "cwd": "/",
            }

            out, updates, meta = handler.process_command("enable", context)

            self.assertIn("% Error: System configuration issue", out)
            self.assertEqual(meta["source"], "handler")


if __name__ == "__main__":
    unittest.main()
