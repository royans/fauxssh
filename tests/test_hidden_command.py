import pytest
from unittest.mock import MagicMock, patch
import sys
import os

# Add project root
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from ssh_honeypot.command_handler import CommandHandler

class TestHiddenCommand:
    @pytest.fixture
    def mock_db(self):
        db = MagicMock()
        db.get_global_stats.return_value = {
            "sessions": 42,
            "unique_ips": 10,
            "total_commands": 100
        }
        return db

    @pytest.fixture
    def handler(self, mock_db):
        llm = MagicMock()
        return CommandHandler(llm, mock_db)

    @patch('ssh_honeypot.command_handler.get_ignored_ips')
    def test_sys_status_untrusted(self, mock_get_ips, handler):
        """Verify untrusted IP gets NO output (pass-through)."""
        mock_get_ips.return_value = ['10.0.0.1']
        
        context = {'client_ip': '1.2.3.4', 'user': 'root'}
        cmd = "sys_status"
        
        # Call handler method directly
        resp = handler.handle_sys_status(cmd, context)
        assert resp is None
        
        # Integration via process_command
        # If None, process_command continues. We can't easily check 'continue' without mocking further down.
        # But handle_sys_status returning None is the contract.

    @patch('ssh_honeypot.command_handler.get_ignored_ips')
    def test_sys_status_trusted(self, mock_get_ips, handler):
        """Verify trusted IP gets Stats."""
        mock_get_ips.return_value = ['10.0.0.1', '1.2.3.4']
        
        context = {'client_ip': '1.2.3.4', 'user': 'root'}
        cmd = "sys_status"
        
        resp = handler.handle_sys_status(cmd, context)
        
        assert resp is not None
        assert "SSHPot Status" in resp
        assert "Sessions:       42" in resp
        assert "Unique IPs:     10" in resp
        
        # Verify via process_command
        # Should return strict tuple
        out, updates, meta = handler.process_command(cmd, context)
        assert "SSHPot Status" in out
        assert meta['source'] == 'local'
