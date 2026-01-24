import unittest
from unittest.mock import MagicMock, patch
import os
import sys
import hashlib

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.core.session_analyzer import analyze_session
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.llm import LLMInterface


class TestSessionAnalyzerV2(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=HoneyDB)
        self.mock_llm = MagicMock(spec=LLMInterface)
        self.session_id = "sess_123"
        # Default to cache miss
        self.mock_db.get_cached_session_summary.return_value = None

    def test_empty_session(self):
        # 0 commands -> "Analyzed (Empty)"
        self.mock_db.get_session_interactions.return_value = []
        status = analyze_session(self.session_id, db=self.mock_db, llm=self.mock_llm)
        self.assertEqual(status, "Analyzed (Empty)")
        self.mock_db.update_session_summary.assert_called()
        summary = self.mock_db.update_session_summary.call_args[0][1]
        self.assertIn("no commands", summary)
        self.mock_llm.generate_session_summary.assert_not_called()

    def test_one_command_reuse(self):
        # 1 command with existing analysis -> "Analyzed (Command Reuse)"
        commands = ["whoami"]
        self.mock_db.get_session_interactions.return_value = commands
        cmd_hash = hashlib.md5(commands[0].encode()).hexdigest()

        # Existing analysis found
        self.mock_db.get_analysis.return_value = {
            "explanation": "Targeted recon explanation",
            "risk_score": 7,
        }
        self.mock_db.get_cached_session_summary.return_value = None

        status = analyze_session(self.session_id, db=self.mock_db, llm=self.mock_llm)

        self.assertEqual(status, "Analyzed (Command Reuse)")
        self.mock_db.update_session_summary.assert_called()
        args = self.mock_db.update_session_summary.call_args[0]
        self.assertIn("Targeted recon explanation", args[1])
        self.assertEqual(args[2], 7)
        self.mock_llm.generate_session_summary.assert_not_called()

    def test_cache_hit_consistency(self):
        # Verify consistent hashing for empty sessions
        self.mock_db.get_session_interactions.return_value = []

        # First call creates cache
        analyze_session(self.session_id, db=self.mock_db, llm=self.mock_llm)
        self.mock_db.save_session_summary_cache.assert_called()
        chain_hash = self.mock_db.save_session_summary_cache.call_args[0][0]

        # Reset mocks
        self.mock_db.reset_mock()
        self.mock_db.get_session_interactions.return_value = []
        self.mock_db.get_cached_session_summary.return_value = ("Cached Empty", 0)

        # Second call hits cache
        status = analyze_session("sess_456", db=self.mock_db, llm=self.mock_llm)
        self.assertEqual(status, "Analyzed (Cache Hit)")
        self.mock_db.get_cached_session_summary.assert_called_with(chain_hash)

    def test_llm_analysis_with_mitre(self):
        # Standard multi-command session
        commands = ["ls -la", "cat /etc/passwd"]
        self.mock_db.get_session_interactions.return_value = commands
        self.mock_db.get_cached_session_summary.return_value = None
        self.mock_db.get_session.return_value = {
            "remote_ip": "1.2.3.4",
            "protocol": "ssh",
        }

        llm_result = {
            "summary": "Attacker probed files.",
            "risk_score": 45,
            "mitre_codes": ["T1083"],
        }
        self.mock_llm.generate_session_summary.return_value = llm_result

        status = analyze_session(self.session_id, db=self.mock_db, llm=self.mock_llm)

        self.assertEqual(status, "Analyzed (LLM)")
        expected_summary = "Attacker probed files. [MITRE: T1083]"
        self.mock_db.update_session_summary.assert_called_with(
            self.session_id, expected_summary, 45
        )


if __name__ == "__main__":
    unittest.main()
