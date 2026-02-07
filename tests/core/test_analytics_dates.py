import unittest
from datetime import datetime
from ssh_honeypot.core.analytics_engine import AnalyticsEngine


class MockDB:
    def __init__(self):
        self.is_postgres = False


class TestAnalyticsDates(unittest.TestCase):
    def test_standardize_dates(self):
        engine = AnalyticsEngine(MockDB())

        # Test Case 1: Naive String (SQLite style)
        data = [{"start_time": "2023-10-27 10:00:00"}]
        engine._standardize_dates(data)
        self.assertEqual(data[0]["start_time"], "2023-10-27 10:00:00Z")

        # Test Case 2: Already ISO with Z
        data = [{"start_time": "2023-10-27T10:00:00Z"}]
        engine._standardize_dates(data)
        self.assertEqual(data[0]["start_time"], "2023-10-27T10:00:00Z")

        # Test Case 3: Datetime object (Naive)
        dt = datetime(2023, 10, 27, 10, 0, 0)
        data = [{"timestamp": dt}]
        engine._standardize_dates(data)
        # Should be ISO formatted with an offset (since it's now local-aware)
        # We don't hardcode the offset but check it's not naive and has a T
        self.assertIn("T", data[0]["timestamp"])
        # It should NOT end with Z unless the local time IS UTC
        # Instead, it should have a + or - for the offset if not UTC
        import re

        self.assertTrue(
            re.search(r"[+-]\d{2}:\d{2}$", data[0]["timestamp"])
            or data[0]["timestamp"].endswith("Z")
        )
        self.assertIn("T", data[0]["timestamp"])

        # Test Case 4: Mixed fields
        data = [
            {"start_time": "2023-10-27 10:00:00", "end_time": None, "other": "value"}
        ]
        engine._standardize_dates(data)
        self.assertEqual(data[0]["start_time"], "2023-10-27 10:00:00Z")
        self.assertIsNone(data[0]["end_time"])


if __name__ == "__main__":
    unittest.main()
