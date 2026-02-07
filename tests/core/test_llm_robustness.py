import unittest
import json
import logging
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.llm import LLMInterface

# Disable logging propogation to avoid noise during tests,
# but we will capture logs in assertions
logger = logging.getLogger("ssh_honeypot")


class TestLLMRobustness(unittest.TestCase):
    def setUp(self):
        self.llm = LLMInterface(api_key="fake_test_key")
        # Mock dependencies to avoid real API/DB calls
        self.llm.universal_cache = MagicMock()
        self.llm.universal_cache.get.return_value = None

    def test_repair_truncated_json_list(self):
        """
        Verify that a JSON list truncated mid-stream is repaired
        by closing the last valid object and the list itself.
        """
        # Scenario: A list of 2 objects, but the 2nd one is cut off.
        # The repair logic should salvage the first object.
        truncated_json = '[{"hash": "valid_hash_1", "analysis": {"type": "Execution", "risk": 90}}, {"hash": "valid_hash_2", "analysis": {"type": "Exfil'

        # 1. Test the internal repair method directly
        repaired = self.llm._repair_json_list(truncated_json)

        # Should result in a valid list with 1 item
        data = json.loads(repaired)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["hash"], "valid_hash_1")

    def test_analyze_batch_with_truncation(self):
        """
        Verify that analyze_batch handles truncation gracefully
        and logs a warning instead of crashing.
        """
        # Mock inputs
        commands = [("hash1", "curl evil.com"), ("hash2", "wget malware.sh")]

        # Mock return value from _call_api (via _handle_provider_response etc)
        # We simulate the provider returning a truncated string for the batch.
        truncated_response = '[{"hash": "hash1", "analysis": {"type": "Execution", "risk": 90}}, {"hash": "hash2", "analysis": {"type": "Exfil'

        with patch.object(self.llm, "_call_api", return_value=truncated_response):
            with self.assertLogs(level="WARNING") as cm:
                results = self.llm.analyze_batch(commands)

            # Verify warning log
            self.assertTrue(
                any("Successfully repaired truncated JSON" in o for o in cm.output)
            )

            # Verify we got the first result
            self.assertIn("hash1", results)
            self.assertEqual(results["hash1"]["risk"], 90)

            # Verify we missed the second one (expected due to truncation)
            self.assertNotIn("hash2", results)


if __name__ == "__main__":
    unittest.main()
