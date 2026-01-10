
import unittest
import time
from unittest.mock import patch
from ssh_honeypot.core.dos_protection import DoSProtector

class TestDoSProtection(unittest.TestCase):
    def setUp(self):
        # Patch Persistence to avoid filesystem access and state leakage
        self.patcher_load = patch.object(DoSProtector, '_load_bans')
        self.patcher_save = patch.object(DoSProtector, '_save_ban')
        self.mock_load = self.patcher_load.start()
        self.mock_save = self.patcher_save.start()
        
        self.dos = DoSProtector(limit_rpm=10, ban_time_sec=60)
        
    def tearDown(self):
        self.patcher_load.stop()
        self.patcher_save.stop()
        
    def test_allow_under_limit(self):
        for _ in range(10):
            self.assertTrue(self.dos.is_allowed("1.2.3.4"))
            
    def test_block_over_limit(self):
        for _ in range(10):
            self.dos.is_allowed("1.2.3.4")
        
        # 11th request should be blocked
        self.assertFalse(self.dos.is_allowed("1.2.3.4"))
        
    def test_ban_expiry(self):
        # Trigger ban
        for _ in range(11):
            self.dos.is_allowed("1.2.3.4")
            
        self.assertFalse(self.dos.is_allowed("1.2.3.4"))
        
        # Simulate time travel (61 seconds later)
        with patch('time.time', return_value=time.time() + 61):
             # Tracking uses time.time() inside. Wait, `record['banned_until']` was set with old time.
             # We need to mock time.time globally or updating `tracking` manually?
             # Since logic calls time.time(), patching it works if we patch it for the CLASS under test usage.
             pass

    @patch('ssh_honeypot.core.dos_protection.time.time')
    def test_window_reset(self, mock_time):
        mock_time.return_value = 1000
        
        # 10 requests allowed (Time 1000)
        for _ in range(10):
            self.assertTrue(self.dos.is_allowed("1.2.3.4"))
            
        # Move forward 61s (new window) -> Should be Allowed (Count resets to 1)
        # If reset failed, count would be 11 -> Blocked/Banned
        mock_time.return_value = 1062
        self.assertTrue(self.dos.is_allowed("1.2.3.4")) 
        
    @patch('ssh_honeypot.core.dos_protection.time.time')
    def test_ban_duration(self, mock_time):
        mock_time.return_value = 1000
        # Trigger Ban
        for _ in range(11):
            self.dos.is_allowed("1.2.3.4")
            
        self.assertFalse(self.dos.is_allowed("1.2.3.4"))
        
        # Move 30s -> Still Banned
        mock_time.return_value = 1030
        self.assertFalse(self.dos.is_allowed("1.2.3.4"))
        
        # Move 61s -> Unbanned
        mock_time.return_value = 1062
        self.assertTrue(self.dos.is_allowed("1.2.3.4"))
