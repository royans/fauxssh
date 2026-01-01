
import paramiko
import sys
import unittest
import threading
import time
import socket
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.server import main as server_main
import ssh_honeypot.server

TEST_PORT = 2225

def is_server_running(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

class TestAuthRestrictions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ssh_honeypot.server.PORT = TEST_PORT
        ssh_honeypot.server.ip_connection_counts.clear()
        ssh_honeypot.server.MAX_SESSIONS_PER_IP = 100  # Prevent rate limiting during tests
        # Disable LLM
        ssh_honeypot.server.llm.api_key = ""
        
        # Mock Anti-Harvesting to avoid blocking during tests
        from unittest.mock import MagicMock
        cls.original_get_creds = ssh_honeypot.server.db.get_unique_creds_last_24h
        ssh_honeypot.server.db.get_unique_creds_last_24h = MagicMock(return_value=set())
        
        if not is_server_running(TEST_PORT):
            cls.server_thread = threading.Thread(target=server_main)
            cls.server_thread.daemon = True
            cls.server_thread.start()
            time.sleep(2)
            
    @classmethod
    def tearDownClass(cls):
        # Restore original method
        ssh_honeypot.server.db.get_unique_creds_last_24h = cls.original_get_creds

    def test_root_login_fail(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # Expect AuthenticationException
            with self.assertRaises(paramiko.AuthenticationException):
                client.connect('127.0.0.1', port=TEST_PORT, username='root', password='anypassword')
        finally:
            client.close()

    def test_normal_login_success(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
             client.connect('127.0.0.1', port=TEST_PORT, username='anyuser', password='anypassword')
             self.assertTrue(client.get_transport().is_active())
        finally:
             client.close()

    def test_sudo_blocked(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
             client.connect('127.0.0.1', port=TEST_PORT, username='testuser', password='anypassword')
             stdin, stdout, stderr = client.exec_command("sudo ls")
             out = stdout.read().decode().strip()
             print(f"SUDO OUT: {out}")
             self.assertIn("not in the sudoers file", out)
             self.assertIn("reported", out)
        finally:
             client.close()

    def test_auth_event_logging(self):
        # 1. Successful Login
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        username = "logtestuser"
        password = "secretpassword"
        try:
             client.connect('127.0.0.1', port=TEST_PORT, username=username, password=password)
             # Must trigger a channel request to start session logging
             client.exec_command("ls")
        finally:
             client.close()
             
        # 2. Failed Login (root)
        try:
             client.connect('127.0.0.1', port=TEST_PORT, username='root', password='rootpassword')
        except: pass
        
        # Verify DB
        # Access the global DB instance from server module
        conn = ssh_honeypot.server.db._get_conn()
        c = conn.cursor()
        
        # Check Success
        c.execute("SELECT auth_data, success, client_version FROM auth_events WHERE username=? AND auth_method='password' ORDER BY id DESC", (username,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], password)
        self.assertEqual(row[1], 1) # Success implies 1 (sqlite stores bool as 0/1)
        self.assertIn("SSH", row[2]) # Client version should be logged
        
        # Check Failure
        c.execute("SELECT auth_data, success FROM auth_events WHERE username='root' ORDER BY id DESC")
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'rootpassword')
        self.assertEqual(row[1], 0)
        
        # Check Session Fingerprint (New Feature)
        c.execute("SELECT fingerprint FROM sessions WHERE username=? ORDER BY id DESC", (username,))
        row = c.fetchone()
        self.assertIsNotNone(row)
        fp_json = row[0]
        self.assertIn("cipher", fp_json)
        self.assertIn("mac", fp_json)
        
        conn.close()

if __name__ == "__main__":
    unittest.main()
