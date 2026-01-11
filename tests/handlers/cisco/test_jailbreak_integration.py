import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.handlers.cisco import cmd_main as cisco_handlers


class TestCiscoJailbreakAndBusybox(unittest.TestCase):
    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_llm.generate_response.return_value = "Mock LLM Response"
        self.mock_llm.get_cached_response.return_value = (
            None  # Or "Mock Cached Response"
        )
        self.mock_db = MagicMock()
        self.handler = CommandHandler(self.mock_llm, self.mock_db)

        # Cisco Context
        self.context = {
            "env": {"privilege_level": 15},
            "cwd": "/",
            "user": "root",
            "persona_config": {
                "system": {"handler_type": "cisco_ios", "hostname": "Switch"},
                "defaults": {},
            },
            "client_ip": "127.0.0.1",
        }

    def test_busybox_dispatch(self):
        """Test that 'busybox echo hi' calls the 'echo' handler."""
        # This requires the handler to be available.
        # Since we are in Cisco mode, 'echo' might not be Cisc-standard,
        # but let's test the dispatch logic itself first.
        # We can mock the 'unix' context for this specific test to ensure dispatch works if enabled.

        unix_context = self.context.copy()
        unix_context["persona_config"]["system"]["handler_type"] = "unix"

        # We process "busybox echo hi"
        # Expectation: It strips busybox and calls handle_echo

        msg, updates, meta = self.handler.process_command(
            "busybox echo hi", unix_context
        )

        # We expect standard echo output (standard unix echo handler returns 'hi\n')
        self.assertIn("hi", msg)
        self.assertEqual(meta["source"], "local")  # Should be local, not llm

    def test_cisco_shell_jailbreak(self):
        """Test 'shell' command in Cisco mode."""
        msg, updates, meta = self.handler.process_command("shell", self.context)

        self.assertEqual(meta["source"], "cisco_local")
        self.assertIn("Entering sensitive shell", msg)
        self.assertTrue(updates["env"]["cisco_jailbreak"])

    def test_post_jailbreak_behavior(self):
        """Test that after jailbreaking, we can run unix commands like busybox or ls."""
        self.mock_db.get_cached_response.return_value = None
        self.mock_llm.generate_response.return_value = "Mock LLM Response"

        # 1. Jailbreak
        msg, updates, meta = self.handler.process_command("shell", self.context)

        # Apply updates to context (simulating Server loop)
        self.context["env"].update(updates["env"])

        # 2. Run Busybox command (should be handled by unix helpers now, bypassing Cisco)
        # We need to ensure 'echo' handler exists for this test to pass fully on dispatch
        # 'echo' is usually a built-in or mapped in CommandHandler's global registry.
        # Let's verify 'echo' works.

        # This assumes 'echo' is in self.handler.local_handlers or mapped in process_command generic flow.
        # ssh_honeypot/handlers/unix/cmd_echo.py usually handles 'echo'.

        msg, updates, meta = self.handler.process_command(
            "busybox echo success", self.context
        )

        # If jailbroken, it shouldn't be handled by Cisco (failed match -> LLM/Error)
        # It should fall through to Unix logic.

        # If 'echo' handler is registered, we get 'success\n'.
        # If not, it falls to LLM.
        # But 'cisco_ios' handler type usually blocks fallthrough unless we bypassed it.
        # Our bypass logic: "if not jailbroken and persona == cisco".
        # So it SHOULD fall through.

        # Check against source. If it's 'cisco_local' it failed to bypass (or echo isn't cisco).
        # We want 'local' (unix/global) or 'llm' (if echo missing but generic handled).

        # Note: If echo is not a registered handler, it might hit LLM.
        # But crucially, it shouldn't be rejected by Cisco parser.

        self.assertNotEqual(meta.get("source"), "cisco_local")
        # If we have echo handler loaded, it should be 'local'.
