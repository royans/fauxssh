import unittest
from unittest.mock import patch, MagicMock
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_honeypot.alert_manager import AlertManager, WebhookNotifier
from ssh_honeypot.config_manager import config

class TestWebhookIntegration(unittest.TestCase):
    def setUp(self):
        AlertManager._instance = None
        AlertManager._initialized = False
        
        # Enable all features
        self.config_patcher = patch.dict(config._config, {
            'alerting': {
                'webhook_url': 'http://integ.test',
                'notify_threshold': 4, # Lower for testing
                'session_threshold': 5,
                'ip_threshold': 8
            }
        })
        self.config_patcher.start()
        
        self.am = AlertManager()
        # Mock the underlying urllib call to prevent real network requests
        self.mock_urlopen_patcher = patch('urllib.request.urlopen')
        self.mock_urlopen = self.mock_urlopen_patcher.start()
        self.mock_urlopen.return_value.__enter__.return_value.status = 200

    def tearDown(self):
        self.config_patcher.stop()
        self.mock_urlopen_patcher.stop()

    def test_full_alert_flow(self):
        """Simulate sequence: High Risk Command -> Trigger -> Streaming"""
        session_id = "sess_integ_01"
        ip = "10.0.0.5"
        
        # 1. Trigger Alert (Simulate analysis loop)
        # Risk (9) > Threshold (5)
        self.am.check_risk_score(session_id, ip, 9, "Integration Test Trigger")
        
        # 2. Verify Session is monitored
        self.assertIn(session_id, self.am.monitored_sessions)
        self.assertIn(ip, self.am.monitored_ips)
        
        # 3. Stream Next Command (Simulate command loop)
        self.am.handle_interaction(session_id, ip, "ls -la", "total 0")
        
        # 4. Stream New Session from same IP (Simulate new login)
        new_session = "sess_integ_02"
        self.am.handle_interaction(new_session, ip, "whoami", "root")
        
        # Verify calls went to "network"
        # We expect at least 3 calls: 1 Alert, 1 Interaction (sess1), 1 Interaction (sess2)
        # However, WebhookNotifier spawns threads, so mock call assertions are tricky without joining.
        # But we mocked urlopen. 
        # Wait a tiny bit for threads to finish?
        import time
        time.sleep(0.1)
        
        self.assertGreaterEqual(self.mock_urlopen.call_count, 3)

if __name__ == '__main__':
    unittest.main()
