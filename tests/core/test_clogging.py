import os
import json
import time
import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.clogging import ClientLogger


class TestClogging(unittest.TestCase):
    def setUp(self):
        # Override config for testing
        self.config_patcher = patch("ssh_honeypot.core.clogging.config")
        self.mock_config = self.config_patcher.start()
        self.mock_config.get.side_effect = self._mock_config_get

        # Mock EventLogger
        self.el_patcher = patch("ssh_honeypot.core.clogging.EventLogger")
        self.mock_el_class = self.el_patcher.start()
        self.mock_event_logger = MagicMock()
        self.mock_el_class.return_value = self.mock_event_logger

        # Mode both, small batch
        self.clogger = ClientLogger()
        self.clogger.log_mode = "both"
        self.clogger.settings["batch_size"] = 2
        self.clogger.settings["batch_timeout"] = 3600  # Prevent accidental flushes
        self.clogger.server_name = "test-server"

    def tearDown(self):
        self.clogger.stop()
        self.config_patcher.stop()
        self.el_patcher.stop()

    def _mock_config_get(self, *args):
        mapping = {
            ("logging", "centralized", "enabled"): True,
            ("logging", "centralized", "mode"): "both",
            ("logging", "centralized", "server_name"): "test-server",
            ("logging", "centralized", "batch_size"): 2,
            ("logging", "centralized", "batch_timeout"): 1,
            ("logging", "centralized", "compression"): True,
        }
        return mapping.get(args)

    def test_immediate_local_logging(self):
        """Verify that clogging writes to the filesystem immediately on log_event."""
        test_data = {"cmd": "ls", "resp": "ok"}
        self.clogger.log_event("interaction", test_data, session_id="sess123")

        # Verify EventLogger was used
        self.mock_event_logger._logger.info.assert_called_once()
        log_call = self.mock_event_logger._logger.info.call_args[0][0]
        event = json.loads(log_call)

        self.assertEqual(event["type"], "interaction")
        self.assertEqual(event["data"], test_data)
        self.assertEqual(event["source"], "test-server")
        self.assertEqual(event["ver"], "2.0")

    @patch("ssh_honeypot.core.slogging.slogger.handle_batch")
    def test_batching_and_dispatch(self, mock_slogger_handle):
        """Verify that batching works and dispatches when size is reached."""
        # Reset mock to clear any noise from other tests
        mock_slogger_handle.reset_mock()

        self.clogger.log_event("auth", {"user": "root"}, session_id="sess1")
        mock_slogger_handle.assert_not_called()

        self.clogger.log_event("auth", {"user": "admin"}, session_id="sess2")
        # Should flush now because batch_size=2
        time.sleep(0.1)  # Small buffer for thread

        # Verify our events are in the calls
        found = False
        for call in mock_slogger_handle.call_args_list:
            batch = call[0][0]
            if any(ev["data"].get("user") == "root" for ev in batch):
                found = True
                break
        self.assertTrue(found, "Expected batch containing 'root' was not found")

    @patch("ssh_honeypot.core.slogging.slogger.handle_batch")
    def test_timeout_flush(self, mock_slogger_handle):
        """Verify that batch flushes after timeout even if not full."""
        # Reset mock to clear any noise from other tests
        mock_slogger_handle.reset_mock()

        self.clogger.settings["batch_timeout"] = 0.5
        self.clogger.log_event("interaction", {"input": "whoami"})

        # Wait for flusher thread
        time.sleep(1.5)

        # Verify our whoami event is in the calls
        found = False
        for call in mock_slogger_handle.call_args_list:
            batch = call[0][0]
            if any(ev["data"].get("input") == "whoami" for ev in batch):
                found = True
                break
        self.assertTrue(found, "Expected batch containing 'whoami' was not found")


if __name__ == "__main__":
    unittest.main()
