import unittest
from unittest.mock import MagicMock
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.llm import LLMInterface
import logging

# Disable logging for tests to avoid noise


class TestPersonaRobustness(unittest.TestCase):
    def test_command_handler_none_system(self):
        """Regression test for 'NoneType' object has no attribute 'get' in CommandHandler"""
        llm = MagicMock()
        db = MagicMock()
        handler = CommandHandler(llm, db)

        bad_config = {"system": None, "prompts": None}

        context = {
            "persona_config": bad_config,
            "env": {},
            "cwd": "/",
            "user": "root",
            "client_ip": "1.2.3.4",
        }

        # This should not raise AttributeError
        try:
            handler.process_command("ls", context)
        except AttributeError:
            self.fail("CommandHandler crashed on None system config")
        except Exception:
            # Other errors (Mock related) are fine, as long as it's not the AttributeError
            pass

    def test_llm_interface_none_prompts(self):
        """Regression test for None prompts in LLMInterface"""
        llm = LLMInterface("fake-key")
        llm._call_api = MagicMock(return_value=('{"output": "ok"}', 200))

        bad_config = {"prompts": None, "system": None}

        # Should proceed to use default template and NOT crash (or return Internal Error)
        # With the fix, it should fallback gracefully.

        resp = llm.generate_response("ls", "/", persona_config=bad_config)
        self.assertNotIn(
            "Error: Internal System Error",
            resp,
            "LLM fell back to error catch block instead of graceful handling",
        )


if __name__ == "__main__":
    unittest.main()
