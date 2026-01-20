import os
import sys
import unittest
import asyncio
from unittest.mock import MagicMock, patch
from datetime import datetime

# Ensure we can import from PROJECT_ROOT
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ssh_honeypot.core.config import config
from ssh_honeypot.handlers.unix.cmd_system import SystemHandler
from ssh_honeypot.handlers.unix.cmd_network import handle_ping
from ssh_honeypot.handlers.unix.cmd_apt import AptCommand
from ssh_honeypot.handlers.unix.cmd_who import WhoCommand
from ssh_honeypot.handlers.unix.cmd_last import LastCommand
from ssh_honeypot.services.mysql.server import HoneyMySQLHandler, client_ip_ctx


class TestRealismV2(unittest.TestCase):
    def setUp(self):
        # Setup a mock persona in config
        self.mock_persona = {
            "system": {
                "hostname": "test-host-persona",
                "distro_id": "centos",
                "users": ["alice", "bob"],
                "manufacturer": "PersonaCorp",
                "product_name": "Persona-v1",
                "serial_number": "SN-PERSONA-123",
            },
            "hardware": {
                "cpu_info": "AMD EPYC 9654 96-Core Processor",
                "memory": "128GB",
                "disk_info": '[{"filesystem": "/dev/sda1", "size": "500GB", "used": "50GB", "avail": "450GB", "use": "10%", "mounted": "/"}]',
            },
            "services": {"running_processes": ["nginx", "postgresql"]},
        }

    def mock_get(self, *args, **kwargs):
        sys.stderr.write(f"DEBUG CALL: {args}\n")
        if args[0] == "persona":
            if len(args) == 2:
                res = self.mock_persona.get(args[1])
                # sys.stderr.write(f"DEBUG RET: {res}\n")
                return res
            if len(args) >= 3:
                res = self.mock_persona.get(args[1], {}).get(args[2])
                # sys.stderr.write(f"DEBUG RET: {res}\n")
                return res
        if len(args) >= 2 and args[0] == "system" and args[1] == "distro_id":
            return "centos"
        return None

    def test_system_handler_hardware(self):
        with patch.object(config, "get", side_effect=self.mock_get):
            handler = SystemHandler(MagicMock(), None)
            handler.db.get_fs_node.return_value = None

            # test lscpu
            out, _ = handler.handle_lscpu("lscpu", {})
            self.assertIn("AMD EPYC 9654", out)
            self.assertIn("CPU(s):                          192", out)

            # test free
            out, _ = handler.handle_free("free", {})
            self.assertIn("134217728", out)

            # test nproc
            out, _ = handler.handle_nproc("nproc", {})
            self.assertEqual(out, "192\n")

            # test dmidecode
            out, _ = handler.handle_dmidecode("dmidecode", {"user": "root"})
            self.assertIn("PersonaCorp", out)
            self.assertIn("Persona-v1", out)
            self.assertIn("SN-PERSONA-123", out)

    def test_hostname_uname_priority(self):
        with patch.object(config, "get", side_effect=self.mock_get):
            handler = SystemHandler(MagicMock(), None)
            handler.db.get_fs_node.return_value = None

            out, _ = handler.handle_hostname("hostname", {})
            sys.stderr.write(f"DEBUG OUT HOSTNAME: {repr(out)}\n")
            self.assertEqual(out, "test-host-persona\n")

            out, _ = handler.handle_uname("uname -a", {})
            self.assertIn("test-host-persona", out)

    def test_apt_distro_error(self):
        with patch.object(config, "get", side_effect=self.mock_get):
            handler = AptCommand(MagicMock(), None)
            out, _, _ = handler.handle("apt update", {})
            self.assertIn("command not found", out)

    def test_who_last_session_injection(self):
        with patch.object(config, "get", side_effect=self.mock_get):
            mock_db = MagicMock()
            mock_db.get_active_sessions.return_value = []
            mock_db.get_recent_sessions.return_value = []

            who = WhoCommand(mock_db, None)
            out, _, _ = who.handle("who", {})
            self.assertIn("alice", out)

            last = LastCommand(mock_db, None)
            out, _, _ = last.handle("last", {})
            self.assertIn("alice", out)

    def test_ping_delay(self):
        start = datetime.now().timestamp()
        out = handle_ping(["-c", "4", "8.8.8.8"])
        end = datetime.now().timestamp()
        duration = end - start
        self.assertGreaterEqual(duration, 3.0)
        self.assertIn("4 packets transmitted", out)

    def test_mysql_ip_context(self):
        mock_db = MagicMock()
        mock_llm = MagicMock()
        mock_config = {}
        handler = HoneyMySQLHandler(mock_db, mock_llm, mock_config)
        mock_reader = MagicMock()
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("9.9.9.9", 12345)

        from mysql_mimic import MysqlServer

        with patch.object(
            MysqlServer, "_client_connected_cb", new_callable=MagicMock
        ) as mock_parent:

            def parent_side_effect(reader, writer):
                self.assertEqual(client_ip_ctx.get(), "9.9.9.9")

            mock_parent.side_effect = parent_side_effect
            handler._client_connected_cb(mock_reader, mock_writer)
            self.assertTrue(mock_parent.called)


if __name__ == "__main__":
    unittest.main()
