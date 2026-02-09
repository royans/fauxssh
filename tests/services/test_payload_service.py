import unittest
import json
import sqlite3
from unittest.mock import MagicMock, patch, ANY
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.services.payload_service import PayloadService


class TestPayloadService(unittest.TestCase):
    def setUp(self):
        # Mock DB Backend
        self.mock_db = MagicMock()
        self.mock_conn = MagicMock()
        self.mock_cursor = MagicMock()

        self.mock_db._get_conn.return_value = self.mock_conn
        self.mock_conn.cursor.return_value = self.mock_cursor

        # Set placeholder to '?' for reliable string assertions
        self.mock_db.placeholder = "?"

        self.service = PayloadService(db=self.mock_db)

    def test_init_with_vt_disabled(self):
        with patch(
            "ssh_honeypot.services.payload_service.config.get", return_value=False
        ):
            service = PayloadService(db=self.mock_db)
            self.assertIsNone(service.vt_analyzer)

    def test_init_with_vt_enabled(self):
        with patch(
            "ssh_honeypot.services.payload_service.config.get", return_value=True
        ):
            with patch(
                "ssh_honeypot.services.payload_service.VirusTotalAnalyzer"
            ) as MockVT:
                service = PayloadService(db=self.mock_db)
                self.assertIsNotNone(service.vt_analyzer)
                MockVT.assert_called_once()

    def test_get_payload_by_md5_found(self):
        md5 = "abc123md5"

        # Mock DB responses
        # sqlite3.Row behavior emulation is tricky, but now code uses description

        # Tuple responses
        row_analysis = (md5, 10, '{"tags": ["malware"]}')
        cols_analysis = [("payload_md5",), ("risk_score",), ("virustotal_result",)]

        row_base = (md5, "http://evil.com", "2023-01-01")
        cols_base = [("payload_md5",), ("url",), ("timestamp",)]

        # We need the Side Effect to return different things for sequential calls
        # 1. payload_analysis query
        # 2. malicious_payloads query
        self.mock_cursor.fetchone.side_effect = [row_analysis, row_base]

        # We also need to mock description.
        # Since it's a property accessed after execute/fetchone, we need side_effect on property?
        # Property mocks are hard on instances.
        # But `cursor` is a Mock. `cursor.description` is an attribute.
        # We can use a PropertyMock or just update it dynamically with side_effect on execute?
        # Or easier: creating a specialized mock class or using `type(mock).description = PropertyMock(...)`.
        # Simplest approach: Use side_effect on execute to update description.

        def update_desc(*args, **kwargs):
            query = args[0]
            if "payload_analysis" in query:
                self.mock_cursor.description = cols_analysis
            elif "malicious_payloads" in query:
                self.mock_cursor.description = cols_base
            return None

        self.mock_cursor.execute.side_effect = update_desc

        result = self.service.get_payload_by_md5(md5)

        self.assertIsNotNone(result)
        self.assertEqual(result["url"], "http://evil.com")
        self.assertEqual(result["risk_score"], 10)
        self.assertEqual(
            result["virustotal_result"]["tags"], ["malware"]
        )  # Check JSON parsing

    def test_get_payload_by_md5_not_found(self):
        self.mock_cursor.fetchone.return_value = None
        result = self.service.get_payload_by_md5("missing")
        self.assertIsNone(result)

    def test_update_payload_risk_score(self):
        md5 = "abc"
        # Mock ensure_analysis_entry SELECT (found)
        self.mock_cursor.fetchone.side_effect = [{"1": 1}]
        # Mock UPDATE result
        self.mock_cursor.rowcount = 1

        success = self.service.update_payload_risk_score(md5, 90)

        self.assertTrue(success)
        self.mock_cursor.execute.assert_any_call(
            "UPDATE payload_analysis SET risk_score = ? WHERE payload_md5 = ?",
            (90, md5),
        )

    def test_update_payload_tags(self):
        md5 = "abc"
        existing_vt = '{"stats": {}}'

        # Mock get_payload responses (tuples)
        row_analysis = (md5, existing_vt)
        cols_analysis = [("payload_md5",), ("virustotal_result",)]

        row_base = (md5, "http://site.com")
        cols_base = [("payload_md5",), ("url",)]

        # Mock ensure_analysis_entry SELECT (found) -> tuple
        row_check = (1,)

        # Sequence of fetches
        self.mock_cursor.fetchone.side_effect = [row_analysis, row_base, row_check]
        self.mock_cursor.rowcount = 1

        def update_desc(*args, **kwargs):
            query = args[0]
            if "SELECT" in query:
                if "payload_analysis" in query and "SELECT 1" not in query:
                    self.mock_cursor.description = cols_analysis
                elif "malicious_payloads" in query:
                    self.mock_cursor.description = cols_base

        self.mock_cursor.execute.side_effect = update_desc

        success = self.service.update_payload_tags(md5, ["hacked", "phishing"])

        self.assertTrue(success)

        # Verify JSON update
        expected_json_arg = ANY
        # Ideally capture the argument to verify tags
        # But checking method called is good for now
        self.mock_cursor.execute.assert_called_with(
            "UPDATE payload_analysis SET virustotal_result = ? WHERE payload_md5 = ?",
            (ANY, md5),
        )

    def test_submit_to_virustotal_hash_found(self):
        md5 = "hash123"

        # Mock VT Analyzer
        mock_vt = MagicMock()
        mock_report = MagicMock()
        mock_report.last_analysis_stats = {"malicious": 5}
        mock_report.tags = ["trojan"]
        mock_report.sha256 = "sha256hash"
        mock_report.last_analysis_date = "2023-01-01"
        mock_vt.check_hash.return_value = mock_report

        self.service.vt_analyzer = mock_vt

        # Mock DB updates
        self.mock_cursor.fetchone.return_value = {"1": 1}  # ensure entry exists
        self.mock_cursor.rowcount = 1

        result = self.service.submit_to_virustotal(md5)

        self.assertEqual(result["status"], "found")
        self.assertEqual(result["data"]["stats"]["malicious"], 5)
        mock_vt.check_hash.assert_called_with(md5)

    def test_submit_to_virustotal_upload(self):
        md5 = "hash_upload"
        content = b"malicious_content"

        # Mock VT: Hash not found, fallback to upload
        mock_vt = MagicMock()
        mock_vt.check_hash.return_value = None
        mock_analysis = MagicMock()
        mock_analysis.id = "scan_id_123"
        mock_vt.scan_file.return_value = mock_analysis

        self.service.vt_analyzer = mock_vt

        with patch(
            "ssh_honeypot.services.payload_service.config.get", return_value=True
        ):
            # We patch config.get to return True for upload_files

            result = self.service.submit_to_virustotal(md5, raw_content=content)

            self.assertEqual(result["status"], "queued")
            self.assertEqual(result["scan_id"], "scan_id_123")
            mock_vt.scan_file.assert_called()

    def test_submit_to_virustotal_disabled(self):
        self.service.vt_analyzer = None
        result = self.service.submit_to_virustotal("abc")
        self.assertEqual(result["status"], "error")
        self.assertIn("disabled", result["message"])

    def test_ensure_analysis_entry_creates(self):
        md5 = "new_payload"
        # Mock SELECT returns None (not found)
        self.mock_cursor.fetchone.return_value = None

        self.service._ensure_analysis_entry(md5)

        self.mock_cursor.execute.assert_any_call(
            "INSERT INTO payload_analysis (payload_md5) VALUES (?)", (md5,)
        )


if __name__ == "__main__":
    unittest.main()
