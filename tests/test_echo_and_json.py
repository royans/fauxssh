
import pytest
from unittest.mock import MagicMock
import sys
import os
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.command_handler import CommandHandler

class TestEchoAndJson:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        mock_db = MagicMock()
        h = CommandHandler(mock_llm, mock_db)
        return h

    def test_echo_exemption(self, handler):
        """
        Regression Test: Ensure 'echo' with a very long string (>150 chars plus valid syntax)
        is NOT offloaded to the LLM. It must remain local.
        """
        # Create a long command that would normally trigger complexity logic
        # length > 150
        cmd = "echo " + "A" * 200
        
        # Mock handle_generic (The LLM path)
        handler.handle_generic = MagicMock(return_value=("llm_response", {}, {'source': 'llm'}))
        
        # Mock handle_echo (The Local path) - normally this happens dynamically via getattr
        # But since we want to verify it DOES dispatch to it, we can spy on it.
        # Actually simplest is to ensure handle_generic is NOT called.
        
        # We need to make sure handle_echo actually runs or is mocked
        orig_echo = handler.handle_echo 
        handler.handle_echo = MagicMock(return_value=("local_echo", {}, {'source': 'local'}))
        
        resp, _, meta = handler.process_command(cmd, {})
        
        # Assertions
        handler.handle_generic.assert_not_called()
        handler.handle_echo.assert_called_once()
        assert resp == "local_echo"

    def test_json_extraction_logic(self, handler):
        """
        Regression Test: Verify _extract_json_or_text robustly handles
        malformed or single-quoted JSON from LLMs without using eval().
        """
        
        # Case 1: Standard JSON (Double Quotes)
        raw = '{"output": "standard"}'
        j, t = handler._extract_json_or_text(raw)
        assert j['output'] == "standard"
        
        # Case 2: Python Dict / Single Quotes (Fixes the Bug)
        raw = "{'output': 'python_style'}"
        j, t = handler._extract_json_or_text(raw)
        assert j['output'] == "python_style"
        
        # Case 3: Embedded Code Block
        raw = "Here is json:\n```json\n{'output': 'inside_block'}\n```"
        j, t = handler._extract_json_or_text(raw)
        assert j['output'] == "inside_block"
        
        # Case 4: Long SSH Key simulation (Single Quotes) escaping check
        # This was a specific failure mode content
        key_content = "ssh-rsa " + "A"*50 + " user@host"
        raw = "{'output': '" + key_content + "'}"
        j, t = handler._extract_json_or_text(raw)
        assert j['output'] == key_content

        # Case 5: Escaped quotes inside content
        val = "I'm good"
        # LLM output might look like: {'output': 'I\'m good'}
        raw = "{'output': 'I\\'m good'}"
        j, t = handler._extract_json_or_text(raw)
        assert j['output'] == "I'm good"

        # Case 6: Trailing Comma (Common LLM error)
        raw = '{"output": "valid", "file_modifications": [],}'
        j, t = handler._extract_json_or_text(raw)
        assert j['output'] == "valid"
