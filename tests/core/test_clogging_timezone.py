import unittest
from datetime import datetime, timezone, timedelta
from ssh_honeypot.core.clogging import ClientLogger
import logging

# Disable logging for tests
# Logging enabled for tests (was disabled globally causing issues)


class TestCloggingTimezone(unittest.TestCase):
    def test_timestamp_is_utc(self):
        """
        Verify that ClientLogger generates timestamps with UTC timezone information.
        This prevents local timezone leaks and ensures consistent analytics.
        """
        logger = ClientLogger()

        # Configure logger to buffer events instead of flushing immediately
        logger.enabled = True
        logger.settings["batch_size"] = 100

        # Log a sample event
        logger.log_event("test_event", {"foo": "bar"})

        # Inspect the buffer directly
        with logger._lock:
            if not logger._buffer:
                self.fail("Buffer empty, could not capture event")
            event = logger._buffer[0]

        ts_str = event["timestamp"]

        # Parse timestamp
        dt = datetime.fromisoformat(ts_str)

        # Check if it has timezone info
        self.assertIsNotNone(dt.tzinfo, "Timestamp should have timezone info")

        # Check if it is UTC (offset 0)
        self.assertEqual(dt.tzinfo, timezone.utc, "Timestamp should be UTC")


if __name__ == "__main__":
    unittest.main()
