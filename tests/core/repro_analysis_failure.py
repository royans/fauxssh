import unittest
from unittest.mock import MagicMock
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from ssh_honeypot.core.background_tasks import run_analysis_batch


class TestAnalysisFailure(unittest.TestCase):
    def test_batch_miss_on_empty_results(self):
        db = MagicMock()
        llm = MagicMock()
        alert = MagicMock()

        # 1. Setup 2 unanalyzed commands
        commands = [
            {
                "request_md5": "hash1",
                "command": "ls",
                "session_id": "s1",
                "remote_ip": "1.1.1.1",
            },
            {
                "request_md5": "hash2",
                "command": "whoami",
                "session_id": "s1",
                "remote_ip": "1.1.1.1",
            },
        ]
        db.get_unanalyzed_commands.return_value = commands

        # 2. Simulate LLM failure (returns empty results)
        llm.analyze_batch.return_value = {}

        # 3. Run analysis
        run_analysis_batch(db, llm, alert)

        # 4. Verify that they were NOT marked as "Batch Miss" (Retry allowed)
        self.assertEqual(db.save_analysis.call_count, 0)


if __name__ == "__main__":
    unittest.main()
