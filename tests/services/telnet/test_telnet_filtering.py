import pytest
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.telnet.server import handle_telnet_session


class TestTelnetFiltering:
    def test_reject_ssh_banner(self):
        # Mock dependencies
        mock_sock = MagicMock()
        mock_db = MagicMock()
        mock_llm = MagicMock()
        addr = ("1.2.3.4", 5678)

        # Patch config and log to avoid side effects
        with (
            patch("ssh_honeypot.services.telnet.server.config") as mock_config,
            patch("ssh_honeypot.services.telnet.server.log") as mock_log,
        ):

            mock_config.get.return_value = "test-host"

            # Patch TelnetHelper to return the values we want (SSH banner)
            with patch(
                "ssh_honeypot.services.telnet.server.TelnetHelper"
            ) as MockTelnetHelper:
                mock_tn = MockTelnetHelper.return_value
                mock_tn.read_line.return_value = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
                handle_telnet_session(mock_sock, addr, mock_db, mock_llm)

            # Assertions
            # 1. log.warning should have been called with "Protocol Mismatch"
            mock_log.warning.assert_called()
            args, _ = mock_log.warning.call_args
            assert "Protocol Mismatch" in args[0]
            assert "SSH Client detected" in args[0]

            # 2. Socket should be closed
            mock_sock.close.assert_called()

            # 3. DB should NOT have logged auth event (rejected before auth)
            mock_db.log_auth_event.assert_not_called()
            mock_db.start_session.assert_not_called()

    def test_allow_normal_telnet(self):
        # Verify normal flow isn't broken (roughly)
        mock_sock = MagicMock()
        mock_db = MagicMock()
        mock_llm = MagicMock()
        addr = ("1.2.3.4", 5678)

        mock_sock.recv.side_effect = [
            b"root\r\n",  # username
            b"password\r\n",  # password
            b"exit\r\n",  # cmd
        ]

        mock_db.validate_anti_harvesting.return_value = (True, "ok")

        with (
            patch("ssh_honeypot.services.telnet.server.config") as mock_config,
            patch("ssh_honeypot.services.telnet.server.log") as mock_log,
        ):

            mock_config.get.return_value = "test-host"

            # This might run indefinitely if not careful, but recv returns side_effects until exhausted/Exception?
            # server.py loop breaks on recv empty or exception.
            # side_effect raises StopIteration if exhausted? No, mock repeats last? No.
            # Let's add b"" at end
            # Patch TelnetHelper to handle login flow
            with patch(
                "ssh_honeypot.services.telnet.server.TelnetHelper"
            ) as MockTelnetHelper:
                mock_tn = MockTelnetHelper.return_value
                mock_tn.read_line.side_effect = [
                    "root",  # username
                    "password",  # password
                ]

                # Set recv side effect for shell commands + EOF
                mock_sock.recv.side_effect = [b"exit\n", b""]  # command  # EOF

                handle_telnet_session(mock_sock, addr, mock_db, mock_llm)

            # Assert auth WAS logged
            mock_db.log_auth_event.assert_called()
