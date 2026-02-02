import unittest
import os
import shutil
import tempfile
import hashlib
from unittest.mock import MagicMock, patch

from ssh_honeypot.core.payload_manager import PayloadManager
from ssh_honeypot.core.database import HoneyDB


class TestPayloadRecovery(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test.sqlite")
        self.db = HoneyDB(self.db_path)
        self.pm = PayloadManager(self.db)
        self.pm.vt_analyzer = MagicMock()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_self_healing_path(self):
        # 1. Setup a "broken" payload record
        content = b"recover_me_123" * 50  # Make it > 500 bytes
        md5 = hashlib.md5(content).hexdigest()

        # Create file in expected location
        payload_dir = os.path.join(self.test_dir, "data", "payloads")
        # Note: PayloadManager resolves PAYLOAD_DIR from get_data_dir()
        # We need to ensure PM looks in our temp dir.
        # Mocking PAYLOAD_DIR would be cleaner or setting env var.

        real_path = os.path.join(payload_dir, f"dangerous_{md5}.txt")
        os.makedirs(payload_dir, exist_ok=True)
        with open(real_path, "wb") as f:
            f.write(content)

        # Add to DB with WRONG path
        wrong_path = "/tmp/does_not_exist/payload.txt"
        self.db.add_malicious_payload(
            url="http://bad.com/file",
            url_hash="hash1",
            session_id="s1",
            ip="1.1.1.1",
            status="completed",
            payload_md5=md5,
            payload_size=len(content),
            file_path=wrong_path,
        )

        # 2. Patch PAYLOAD_DIR and CONFIG
        with (
            patch("ssh_honeypot.core.payload_manager.PAYLOAD_DIR", payload_dir),
            patch("ssh_honeypot.core.payload_manager.config") as mock_config,
        ):

            # Configure config.get to return True for upload_files
            def config_side_effect(section, key=None):
                if section == "virustotal" and key == "upload_files":
                    return True
                return False

            mock_config.get.side_effect = config_side_effect

            item = self.db.get_malicious_payload_by_hash("hash1")

            # 3. Analyze - Should recover path
            # Force "upload" path by returning None for hash check
            self.pm.vt_analyzer.check_hash.return_value = None
            self.pm.vt_analyzer.scan_file.return_value = MagicMock(id="scan1")

            self.pm.analyze_payload(item)

            # 4. Verify DB was updated
            updated_item = self.db.get_malicious_payload_by_hash("hash1")
            self.assertEqual(updated_item["file_path"], real_path)

            # Verify scan called with CORRECT path
            self.pm.vt_analyzer.scan_file.assert_called_with(real_path)


if __name__ == "__main__":
    unittest.main()
