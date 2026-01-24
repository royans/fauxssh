import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.core.llm import LLMInterface


class TestLLMHeuristics(unittest.TestCase):
    def setUp(self):
        # We need to mock _call_api to ensure it's NOT called for heuristics
        self.llm = LLMInterface(api_key="TEST_KEY")
        self.llm._call_api = MagicMock(
            return_value='{"error": "API should not be called"}'
        )

    def test_discovery_heuristic_ls(self):
        # ls -> should be handled by heuristic
        commands = ["ls"]
        result = self.llm.generate_session_summary(commands)

        self.assertIsNotNone(result)
        self.assertIn("basic discovery", result["summary"])
        self.assertEqual(result["risk_score"], 10)
        self.llm._call_api.assert_not_called()

    def test_discovery_heuristic_multiple(self):
        # ls, whoami, pwd -> should be handled by heuristic
        commands = ["ls", "whoami", "pwd"]
        result = self.llm.generate_session_summary(commands)

        self.assertIsNotNone(result)
        self.assertIn("whoami", result["summary"])
        self.assertEqual(result["risk_score"], 10)
        self.llm._call_api.assert_not_called()

    def test_non_heuristic_command(self):
        # cat /etc/shadow -> NOT in heuristic
        # We expect it to try calling API (which we mocked to return error JSON)
        commands = ["cat /etc/shadow"]
        self.llm._call_api.return_value = (
            '{"summary": "Attacker tried to read shadow", "risk_score": 70}'
        )

        result = self.llm.generate_session_summary(commands)

        self.llm._call_api.assert_called_once()
        self.assertEqual(result["risk_score"], 70)

    def test_too_many_commands_for_heuristic(self):
        # heuristic only for <= 3 commands
        commands = ["ls", "pwd", "id", "uname"]
        self.llm._call_api.return_value = (
            '{"summary": "Discovery batch", "risk_score": 15}'
        )

        result = self.llm.generate_session_summary(commands)

        self.llm._call_api.assert_called_once()
        self.assertEqual(result["risk_score"], 15)


if __name__ == "__main__":
    unittest.main()
