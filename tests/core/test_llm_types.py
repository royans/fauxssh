import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.session_analyzer import analyze_session
from ssh_honeypot.core.llm import LLMInterface
from ssh_honeypot.core.alert_manager import AlertManager


class TestLLMTypeSafety(unittest.TestCase):
    def test_risk_score_string_handling(self):
        """
        Test that session analyzer handles string risk scores from LLM without crashing.
        """
        # Mock DB
        mock_db = MagicMock()
        mock_db.get_session_interactions.return_value = ["ls", "pwd"]
        mock_db.get_cached_session_summary.return_value = None
        mock_db.get_session.return_value = {"remote_ip": "1.2.3.4", "protocol": "ssh"}

        # Mock LLM returning string risk score
        mock_llm = MagicMock()
        mock_llm.generate_session_summary.return_value = {
            "summary": "Bad guy",
            "risk_score": "85",  # String!
            "mitre_codes": [],
        }

        # Mock AlertManager to catch the error if it propagates
        # We need to spy on check_risk_score or just run it and see if it raises

        # In session_analyzer.py, it instantiates AlertManager locally inside the function
        # inside the try/except block (lines 102-123).
        # So connection to AlertManager is effectively tested via the function call.

        # To truly test the TypeError, we need to bypass the catch-all in session_analyzer
        # or mock AlertManager to assert it receives an int.

        # Since AlertManager is imported inside the function, we patch the source where it comes from
        with patch("ssh_honeypot.core.alert_manager.AlertManager") as MockAlertManager:
            mock_am_instance = MockAlertManager.return_value

            # Let's mock check_risk_score to assert the type
            def side_effect(session_id, ip, score, explanation, protocol):
                if not isinstance(score, (int, float)):
                    raise TypeError(f"Score must be int/float, got {type(score)}")

            mock_am_instance.check_risk_score.side_effect = side_effect

            # Run analyzer
            result = analyze_session("sess1", db=mock_db, llm=mock_llm)

            # Output calls to see what happened
            # print(mock_am_instance.check_risk_score.call_args_list)

            # We want to fix the code so it DOES cast it.
            # So we expect mock_am_instance.check_risk_score to be called with INT.

            mock_am_instance.check_risk_score.assert_called()
            args = mock_am_instance.check_risk_score.call_args
            score_arg = args[0][2]  # session_id, ip, score

            self.assertIsInstance(
                score_arg,
                int,
                f"Risk score passed to AlertManager was not an int: {score_arg}",
            )


if __name__ == "__main__":
    unittest.main()
