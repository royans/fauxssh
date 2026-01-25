import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.slogging import SloggingProcessor


class TestSlogging(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        # Patch get_db_backend to return our mock
        self.db_patcher = patch(
            "ssh_honeypot.core.slogging.get_db_backend", return_value=self.mock_db
        )
        self.db_patcher.start()

        self.processor = SloggingProcessor()

    def tearDown(self):
        self.db_patcher.stop()

    def test_handle_auth_event(self):
        event = {
            "type": "auth",
            "source": "hp-1",
            "remote_ip": "1.2.3.4",
            "protocol": "ssh",
            "data": {
                "username": "root",
                "method": "password",
                "password": "123",
                "success": True,
                "client_version": "v1",
                "fingerprint": {"key": "val"},
            },
        }
        self.processor.handle_event(event)

        self.mock_db.log_auth_event.assert_called_once_with(
            client_ip="1.2.3.4",
            username="root",
            auth_method="password",
            auth_data="123",
            success=True,
            client_version="v1",
            fingerprint={"key": "val"},
            protocol="ssh",
            created_at=None,
        )
        # Should also trigger IP enrichment
        self.mock_db.log_ip_visit.assert_called_once_with("1.2.3.4")

    def test_handle_interaction_event(self):
        event = {
            "type": "interaction",
            "source": "hp-1",
            "remote_ip": "1.2.3.4",
            "protocol": "ssh",
            "session_id": "sess-99",
            "data": {
                "cwd": "/root",
                "input": "ls -la",
                "response": "total 0",
                "request_md5": "abc",
                "duration_ms": 15.5,
            },
        }
        self.processor.handle_event(event)

        self.mock_db.log_interaction.assert_called_once_with(
            session_id="sess-99",
            cwd="/root",
            command="ls -la",
            response="total 0",
            source="hp-1",
            duration_ms=15.5,
            request_md5="abc",
            created_at=None,
        )

    def test_handle_session_start_end(self):
        start_event = {
            "type": "session_start",
            "source": "hp-1",
            "remote_ip": "1.2.3.4",
            "session_id": "sess-99",
            "data": {
                "username": "root",
                "password": "123",
                "client_version": "v1",
                "fingerprint": "fp",
            },
        }
        self.processor.handle_event(start_event)
        self.mock_db.start_session.assert_called_once()

        end_event = {
            "type": "session_end",
            "session_id": "sess-99",
        }
        self.processor.handle_event(end_event)
        self.mock_db.end_session.assert_called_once_with("sess-99")

    def test_handle_event_with_timestamp(self):
        # Regression test for "created_at" argument mismatch
        ts = "2025-01-01 12:00:00"
        event = {
            "type": "interaction",
            "source": "hp-1",
            "remote_ip": "1.2.3.4",
            "protocol": "ssh",
            "session_id": "sess-ts",
            "timestamp": ts,
            "data": {
                "input": "date",
                "response": "now",
            },
        }
        self.processor.handle_event(event)

        # Verify created_at is passed from "timestamp" field
        self.mock_db.log_interaction.assert_called_once()
        args, kwargs = self.mock_db.log_interaction.call_args
        self.assertEqual(kwargs["created_at"], ts)


if __name__ == "__main__":
    unittest.main()
