import unittest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_honeypot.alert_manager import AlertManager
from ssh_honeypot.config_manager import config

class TestKeywordAlerts(unittest.TestCase):
    def setUp(self):
        AlertManager._instance = None
        AlertManager._initialized = False
        
        # Enable keywords
        self.config_patcher = patch.dict(config._config, {
            'alerting': {
                'webhook_url': 'http://integ.test',
                'notify_threshold': 100, # High, so only keyword triggers
                'session_threshold': 100,
                'ip_threshold': 100,
                'keywords': ['magic_word', 'secret_sauce']
            }
        })
        self.config_patcher.start()
        
        self.am = AlertManager()
        # Mock notifier
        self.am.notifier = MagicMock()
        self.am.notifier.webhook_url = "http://integ.test"

    def tearDown(self):
        self.config_patcher.stop()

    def test_keyword_match(self):
        """Test exact substring match triggers alert"""
        session_id = "sess_key_01"
        ip = "10.0.0.5"
        
        # Should Trigger
        self.am.handle_interaction(session_id, ip, "echo magic_word", "magic_word")
        
        # Verify Alert
        self.am.notifier.send_alert.assert_called_with(session_id, ip, "Keyword Trigger: magic_word", 10)
        
        # Verify Auto-Monitoring
        self.assertIn(session_id, self.am.monitored_sessions)

    def test_keyword_case_insensitive(self):
        """Test case insensitivity"""
        session_id = "sess_key_02"
        ip = "10.0.0.5"
        
        # Should Trigger
        self.am.handle_interaction(session_id, ip, "cat SECRET_SAUCE.txt", "")
        
        # Verify Alert
        self.am.notifier.send_alert.assert_called_with(session_id, ip, "Keyword Trigger: secret_sauce", 10)

    def test_no_match(self):
        """Test normal command does not trigger"""
        session_id = "sess_key_03"
        ip = "10.0.0.5"
        
        self.am.handle_interaction(session_id, ip, "ls -la", "")
        
        # Verify NO Alert
        self.am.notifier.send_alert.assert_not_called()
        self.assertNotIn(session_id, self.am.monitored_sessions)

if __name__ == '__main__':
    unittest.main()
