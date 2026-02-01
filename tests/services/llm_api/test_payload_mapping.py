import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.slogging import SloggingProcessor


class TestSloggingMapping(unittest.TestCase):
    def test_interaction_mapping_input_to_db_command(self):
        """
        Verify that SloggingProcessor maps data['input'] to db.log_interaction(command=...).
        This confirms that 'input' is the primary field for persistence in the 'command' column.
        """
        # Mock DB Backend
        mock_db = MagicMock()

        processor = SloggingProcessor()
        processor._db = mock_db  # Inject mock DB

        # Scenario: OllamaHandler sends separated command (endpoint) and input (payload)
        event_data = {
            "cwd": "API_ROOT",
            "command": "POST /api/chat",  # Endpoint (might be lost if not mapped!)
            "input": '{"prompt":"bad"}',  # Payload
            "response": "ok",
            "source": "llm-api",
        }

        event = {
            "type": "interaction",
            "data": event_data,
            "session_id": "123",
            "timestamp": "2023-01-01T00:00:00Z",
        }

        # Act
        processor.handle_event(event)

        # Assert
        # We expect db.log_interaction to be called
        mock_db.log_interaction.assert_called_once()

        # Check arguments
        call_kwargs = mock_db.log_interaction.call_args.kwargs

        # Crucial Check: Does the DB 'command' column receive the payload?
        self.assertEqual(
            call_kwargs["command"],
            '{"prompt":"bad"}',
            "DB 'command' column should contain the input payload.",
        )

        # Crucial Check 2: Is the endpoint ('POST /api/chat') preserved anywhere?
        # Based on code reading, we expect it to be LOST if not merged.
        # So we assert it is MISSING to prove the need for the fix.
        # If it was somehow merged magicallly, this assertion would fail (which is good info).
        self.assertNotIn(
            "POST /api/chat",
            call_kwargs["command"],
            "Endpoint info was strictly expected to be missing/lost with current logic.",
        )


if __name__ == "__main__":
    unittest.main()
