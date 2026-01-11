
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Mock google.generativeai for the entire module before import
# This ensures that when LLMInterfaceV2 imports it, it gets the mock
sys.modules['google.generativeai'] = MagicMock()
import google.generativeai as genai

from ssh_honeypot.core.llm_v2 import LLMInterfaceV2

class TestLLMv2(unittest.TestCase):
    def setUp(self):
        self.llm = LLMInterfaceV2(api_key="TEST_KEY")
        # Ensure model is mocked correctly (Adapter Pattern)
        if hasattr(self.llm, 'provider') and self.llm.provider:
            self.llm.provider.model = MagicMock()
        
    def test_generate_response(self):
        # Setup Mock Return
        mock_resp = MagicMock()
        mock_resp.text = '{"output": "Output from V2 SDK"}'
        
        # Access the provider's model
        if self.llm.provider and self.llm.provider.model:
            self.llm.provider.model.generate_content.return_value = mock_resp
        
        resp = self.llm.generate_response("echo test", "/")
        # print(f"Response: {resp}")
        
        self.assertIn("Output from V2 SDK", resp)
        if self.llm.provider and self.llm.provider.model:
             self.llm.provider.model.generate_content.assert_called_once()
        
    def test_analyze_command(self):
        mock_resp = MagicMock()
        mock_resp.text = '{"type": "Recon", "risk": 5}'
        
        if self.llm.provider and self.llm.provider.model:
            self.llm.provider.model.generate_content.return_value = mock_resp
        
        res = self.llm.analyze_command("ls -la")
        # print(f"Analysis: {res}")
        self.assertEqual(res['type'], "Recon")

if __name__ == "__main__":
    unittest.main()
