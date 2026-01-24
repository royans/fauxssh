import unittest
from unittest.mock import MagicMock, patch
import os
import sys

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.core.background_tasks import run_session_analysis_batch
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.llm import LLMInterface


class TestBackgroundTasksV2(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=HoneyDB)
        self.mock_llm = MagicMock(spec=LLMInterface)

    @patch("ssh_honeypot.core.session_analyzer.analyze_session")
    def test_run_session_analysis_batch(self, mock_analyze):
        # Setup: 2 unanalyzed sessions
        self.mock_db.get_unanalyzed_sessions.return_value = ["sess_1", "sess_2"]

        run_session_analysis_batch(self.mock_db, self.mock_llm)

        # Expect analyze_session to be called twice
        self.assertEqual(mock_analyze.call_count, 2)
        mock_analyze.assert_any_call("sess_1", db=self.mock_db, llm=self.mock_llm)
        mock_analyze.assert_any_call("sess_2", db=self.mock_db, llm=self.mock_llm)

    @patch("ssh_honeypot.core.session_analyzer.analyze_session")
    def test_run_session_analysis_batch_empty(self, mock_analyze):
        # Setup: No unanalyzed sessions
        self.mock_db.get_unanalyzed_sessions.return_value = []

        run_session_analysis_batch(self.mock_db, self.mock_llm)

        # Expect analyze_session not to be called
        mock_analyze.assert_not_called()


if __name__ == "__main__":
    unittest.main()
