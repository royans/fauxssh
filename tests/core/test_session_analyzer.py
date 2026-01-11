import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.core.session_analyzer import analyze_session
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.llm import LLMInterface


class TestSessionAnalyzer(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=HoneyDB)
        self.mock_llm = MagicMock(spec=LLMInterface)
        self.session_id = "sess_123"

    def test_short_session_skipped(self):
        # 1 command -> skipped
        self.mock_db.get_session_interactions.return_value = ["ping"]
        status = analyze_session(self.session_id, db=self.mock_db, llm=self.mock_llm)
        self.assertEqual(status, "Skipped (Short Session)")
        self.mock_llm.generate_session_summary.assert_not_called()

    def test_cache_hit(self):
        # Commands
        commands = ["ls", "pwd"]
        self.mock_db.get_session_interactions.return_value = commands

        # Cache returns existing summary
        self.mock_db.get_cached_session_summary.return_value = ("Cached Summary", 8)

        status = analyze_session(self.session_id, db=self.mock_db, llm=self.mock_llm)

        # Expect
        self.assertEqual(status, "Analyzed (Cache Hit)")
        self.mock_db.update_session_summary.assert_called_with(
            self.session_id, "Cached Summary", 8
        )
        self.mock_llm.generate_session_summary.assert_not_called()

    def test_llm_analysis(self):
        # Commands
        commands = ["ls -la", "cat /etc/passwd"]
        self.mock_db.get_session_interactions.return_value = commands

        # Cache Miss
        self.mock_db.get_cached_session_summary.return_value = None

        # LLM Result
        llm_result = {
            "summary": "Attacker exfiltrated passwd.",
            "risk_score": 9,
            "mitre_codes": ["T1005"],
        }
        self.mock_llm.generate_session_summary.return_value = llm_result

        status = analyze_session(self.session_id, db=self.mock_db, llm=self.mock_llm)

        # Expect
        self.assertEqual(status, "Analyzed (LLM)")
        # Summary should include MITRE
        expected_summary = "Attacker exfiltrated passwd. [MITRE: T1005]"

        # Check Cache Save
        self.mock_db.save_session_summary_cache.assert_called()
        args = self.mock_db.save_session_summary_cache.call_args[0]
        # args[0] is hash, args[1] is summary, args[2] is risk
        self.assertEqual(args[1], expected_summary)
        self.assertEqual(args[2], 9)

        # Check Session Update
        self.mock_db.update_session_summary.assert_called_with(
            self.session_id, expected_summary, 9
        )


if __name__ == "__main__":
    unittest.main()
