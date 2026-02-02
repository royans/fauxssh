import unittest
import os
import shutil
import tempfile
import hashlib
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from ssh_honeypot.core.payload_manager import PayloadManager
from ssh_honeypot.core.database import HoneyDB


class TestPayloadDeduplication(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test.sqlite")
        self.db = HoneyDB(self.db_path)
        self.pm = PayloadManager(self.db)

        # Mock VT
        self.pm.vt_analyzer = MagicMock()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_duplicate_queue_skipping(self):
        url = "http://example.com/malware"

        # 1. Queue it (First time) - should return True
        res1 = self.pm.queue_payload(url, "s1", "1.1.1.1")
        self.assertTrue(res1)

        # 2. Queue it again while pending - should return False
        res2 = self.pm.queue_payload(url, "s1", "1.1.1.1")
        self.assertFalse(res2)

    def test_failed_backoff(self):
        url = "http://broken.link/file"
        url_hash = hashlib.md5(url.encode()).hexdigest()

        # 1. Simulate a failure 1 hour ago
        one_hour_ago = datetime.now() - timedelta(hours=1)
        self.db.add_malicious_payload(
            url=url,
            url_hash=url_hash,
            session_id="s1",
            ip="1.1.1.1",
            timestamp=one_hour_ago,
            status="failed",
        )

        # 2. Try to queue again - should be skipped due to 48h backoff
        res = self.pm.queue_payload(url, "s2", "2.2.2.2")
        self.assertFalse(res)

        # 3. Simulate failure 50 hours ago
        long_ago = datetime.now() - timedelta(hours=50)
        self.db.add_malicious_payload(
            url=url,
            url_hash=url_hash,
            session_id="s1",
            ip="1.1.1.1",
            timestamp=long_ago,
            status="failed",
        )

        # 4. Try to queue again - should proceed now
        res2 = self.pm.queue_payload(url, "s3", "3.3.3.3")
        self.assertTrue(res2)

    def test_path_resolution_fix(self):
        # This test verifies that PayloadManager can resolve <DATA_DIR> in file_path
        from ssh_honeypot.core.utils import get_data_dir

        data_dir = get_data_dir()
        # Content must be >= 500 bytes to pass the VT size check
        content = b"fake malware content 12345" * 20
        md5 = hashlib.md5(content).hexdigest()

        # Create a real file in the real data dir (PAYLOAD_DIR)
        payload_dir = os.path.join(data_dir, "payloads")
        os.makedirs(payload_dir, exist_ok=True)
        real_path = os.path.join(payload_dir, f"test_resolve_{md5}.txt")
        with open(real_path, "wb") as f:
            f.write(content)

        # Store it in DB with placeholder
        placeholder_path = f"<DATA_DIR>/payloads/test_resolve_{md5}.txt"
        self.db.add_malicious_payload(
            url="http://example.com/resolve",
            url_hash="somehash",
            session_id="s1",
            ip="1.1.1.1",
            status="completed",
            payload_md5=md5,
            payload_size=len(content),
            file_path=placeholder_path,
        )

        # Fetch the item
        item = self.db.get_malicious_payload_by_hash("somehash")

        # Mock VT Analyzer report check
        # Return None to force it to try "Upload" path which checks file existence
        self.pm.vt_analyzer.check_hash.return_value = None
        self.pm.vt_analyzer.scan_file.return_value = MagicMock(id="scan123")

        # Call analyze_payload - it should NOT fail with "file_not_found"
        # Call analyze_payload - it should NOT fail with "file_not_found"
        # Patching os.path.exists specifically in the context of payload_manager
        with patch("ssh_honeypot.core.payload_manager.os.path.exists") as mock_exists:
            mock_exists.return_value = True
            self.pm.analyze_payload(item)

            # Check if exists was called with real_path
            mock_exists.assert_any_call(real_path)


if __name__ == "__main__":
    unittest.main()
