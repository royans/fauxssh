import unittest
import os
import hashlib
from unittest.mock import MagicMock
from ssh_honeypot.core.payload_manager import PayloadManager


class TestUploadIntegration(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.pm = PayloadManager(self.db)

    def test_queue_upload(self):
        filename = "malware.sh"
        content = "#!/bin/bash\necho 'evil'"
        session_id = "test-session"
        ip = "1.2.3.4"

        # Mock add_malicious_payload to return True
        self.db.add_malicious_payload.return_value = True
        # Mock get_payload_by_hash to return a dummy payload with an ID
        self.db.get_payload_by_hash.return_value = {"id": 1}

        result = self.pm.queue_upload(filename, content, session_id, ip)

        self.assertTrue(result)
        # Verify add_malicious_payload was called with status='completed'
        args, kwargs = self.db.add_malicious_payload.call_args
        self.assertEqual(kwargs["status"], "completed")
        self.assertEqual(kwargs["url"], f"upload://{filename}")

        # Verify update_payload_status was called
        self.db.update_payload_status.assert_called_once()
        u_args, u_kwargs = self.db.update_payload_status.call_args
        self.assertEqual(
            u_kwargs["payload_md5"], hashlib.md5(content.encode()).hexdigest()
        )


if __name__ == "__main__":
    unittest.main()
