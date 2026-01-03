import unittest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_honeypot.alert_manager import AlertManager
from ssh_honeypot.config_manager import config

class TestAlertManager(unittest.TestCase):
    def setUp(self):
        # Reset Singleton
        AlertManager._instance = None
        AlertManager._initialized = False
        
        # Mock Config for Tiered Tests
        self.config_patcher = patch.dict(config._config, {
            'alerting': {
                'webhook_url': 'http://mock.local',
                'notify_threshold': 6,
                'session_threshold': 7,
                'ip_threshold': 9
            }
        })
        self.config_patcher.start()
        
        self.am = AlertManager()
        self.am.notifier = MagicMock() # Mock the notifier

    def tearDown(self):
        self.config_patcher.stop()

    def test_tier1_notify_only(self):
        # Risk 6: Should Notify but NOT monitor session or IP
        self.am.check_risk_score("s1", "1.1.1.1", 6, "L1 Risk")
        
        self.am.notifier.send_alert.assert_called_with("s1", "1.1.1.1", "L1 Risk", 6)
        self.assertNotIn("s1", self.am.monitored_sessions)
        self.assertNotIn("1.1.1.1", self.am.monitored_ips)

    def test_tier2_monitor_session(self):
        # Risk 7: Should Notify AND Monitor Session, but NOT IP
        self.am.check_risk_score("s2", "2.2.2.2", 7, "L2 Risk")
        
        self.am.notifier.send_alert.assert_called()
        self.assertIn("s2", self.am.monitored_sessions)
        self.assertNotIn("2.2.2.2", self.am.monitored_ips)
        
        # Verify streaming
        self.am.handle_interaction("s2", "2.2.2.2", "whoami", "root")
        self.am.notifier.send_interaction.assert_called()

    def test_tier3_monitor_ip(self):
        # Risk 9: Should Notify, Monitor Session, AND Monitor IP
        self.am.check_risk_score("s3", "3.3.3.3", 9, "L3 Risk")
        
        self.am.notifier.send_alert.assert_called()
        self.assertIn("s3", self.am.monitored_sessions)
        self.assertIn("3.3.3.3", self.am.monitored_ips)
        
        # New session from same IP should stream automatically
        self.am.handle_interaction("s3_new", "3.3.3.3", "ls", "...")
        self.am.notifier.send_interaction.assert_called_with("s3_new", "3.3.3.3", "ls", "...")

if __name__ == '__main__':
    unittest.main()
