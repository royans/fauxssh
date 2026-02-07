import unittest
from unittest.mock import MagicMock, patch
import json
import logging
from ssh_honeypot.core.llm import LLMInterface
from ssh_honeypot.core.universal_cache import UniversalCache


class TestLLMResourceExhaustion(unittest.TestCase):
    def setUp(self):
        self.llm = LLMInterface(api_key="fake_key")
        self.llm.universal_cache = MagicMock()

    @patch("ssh_honeypot.core.llm.universal_cache")
    def test_cache_invalidation_on_error(self, mock_cache):
        # Setup: Cache returns a tainted response
        tainted_json = '{"output": "Error: System resources exhausted"}'
        mock_cache.get.return_value = {"output_text": tainted_json}

        # We need to mock _call_api to avoid actual network call after cache miss
        with patch.object(
            self.llm, "_call_google", return_value='{"output": "Fresh Response"}'
        ) as mock_google:
            # Execute
            res = self.llm._call_api("test prompt", return_source=False)

            # Verify:
            # 1. Cache should have been checked
            mock_cache.get.assert_called()

            # 2. Delete should be called for the tainted key
            # (We don't know the exact hash here easily without calculating, but we can check if delete was called)
            mock_cache.delete.assert_called()

            # 3. Method should have proceeded to call provider (Cache Miss path)
            mock_google.assert_called()

            # 4. Result should be the fresh response
            self.assertEqual(res, '{"output": "Fresh Response"}')

    @patch("ssh_honeypot.core.llm.universal_cache")
    def test_fresh_error_returns_signal(self, mock_cache):
        # Setup: Cache miss
        mock_cache.get.return_value = None

        # Setup: Provider returns Resource Exhaustion
        # NOTE: We mock _call_google to return the string because that's what the real method does
        # when it calls _handle_provider_response and gets an error.
        with patch.object(
            self.llm, "_call_google", return_value="Error: System resources exhausted"
        ):
            res = self.llm._call_api("test prompt", return_source=False)

            # Verify:
            # Should return the internal error signal
            self.assertIn("INTERNAL_ERROR", res)

            # Should NOT cache this error (or at least the guard in set() prevents it,
            # but our code returns early so set() might not even be called if we did it right)
            # In my implementation:
            # if "System resources exhausted" in final_text: return INTERNAL_ERROR
            # So universal_cache.set should NOT be called
            mock_cache.set.assert_not_called()


if __name__ == "__main__":
    unittest.main()
