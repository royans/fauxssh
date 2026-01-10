
import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.command_handler import CommandHandler

class TestCiscoEnableRobustness(unittest.TestCase):
    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_db = MagicMock()
        self.handler = CommandHandler(self.mock_llm, self.mock_db)
        
        # Setup context for Cisco Persona
        self.context = {
            'persona_config': {
                'system': {'handler_type': 'cisco_ios'}
            },
            'env': {'privilege_level': 1}
        }

    def test_clean_input(self):
        """Test standard 'enable' command."""
        cmd = "enable"
        # We need to ensure cisco_handlers is mocked inside CommandHandler module
        # Since it's imported at module level, we patch it there.
        with patch('ssh_honeypot.core.command_handler.cisco_handlers') as mock_cisco:
            # Setup the enable handler to return specific updates
            mock_cisco.handle_cisco_enable.return_value = ("", {'env': {'privilege_level': 15}}, {'source': 'cisco_local', 'cached': False})
            
            resp, updates, meta = self.handler.process_command(cmd, self.context)
            
            mock_cisco.handle_cisco_enable.assert_called()
            self.assertEqual(meta['source'], 'cisco_local')
            self.assertEqual(updates['env']['privilege_level'], 15)

    def test_whitespace_input(self):
        """Test 'enable   ' with trailing whitespace."""
        cmd = "enable   "
        with patch('ssh_honeypot.core.command_handler.cisco_handlers') as mock_cisco:
            # Ensure handle_cisco_enable is set, otherwise dispatch logic fails check for definition?
            # Actually dispatch logic checks: `if base == 'enable': handler_func = ...`
            # It accesses cisco_handlers.handle_cisco_enable.
            mock_cisco.handle_cisco_enable.return_value = ("", {}, {'source': 'test'})
            
            resp, updates, meta = self.handler.process_command(cmd, self.context)
            
            mock_cisco.handle_cisco_enable.assert_called()

    def test_telnet_iac_residue(self):
        """Test input corrupted with Telnet IAC bytes (Generic Negotiation)."""
        # Example: IAC WONT ECHO (FF FC 01) prepended
        cmd = "\xff\xfc\x01enable"
        
        with patch('ssh_honeypot.core.command_handler.cisco_handlers') as mock_cisco:
            mock_cisco.handle_cisco_enable.return_value = ("", {}, {'source': 'test'})
            
            resp, updates, meta = self.handler.process_command(cmd, self.context)
            
            # This assertion SHOULD FAIL if sanitization is missing
            self.assertEqual(meta.get('source'), 'test', "Failed to match enabled with IAC residue")

    def test_null_byte_residue(self):
        """Test input corrupted with Null bytes."""
        cmd = "enable\x00"
        
        with patch('ssh_honeypot.core.command_handler.cisco_handlers') as mock_cisco:
            mock_cisco.handle_cisco_enable.return_value = ("", {}, {'source': 'test'})
            
            resp, updates, meta = self.handler.process_command(cmd, self.context)
            
            # This assertion SHOULD FAIL if sanitization is missing
            self.assertEqual(meta.get('source'), 'test', "Failed to match enable with Null byte")

if __name__ == '__main__':
    unittest.main()
