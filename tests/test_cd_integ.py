import paramiko
import sys
import unittest
import threading
import time
import socket
import os

# Ensure we can import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.server import main as server_main
import ssh_honeypot.server
import ssh_honeypot.fs_seeder

TEST_PORT = 2226 # Use a dedicated port for this specific test

def is_server_running(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

class TestCDIntegreation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Patch PORT
        ssh_honeypot.server.PORT = TEST_PORT
        ssh_honeypot.server.ip_connection_counts.clear()
        
        # 1. Deterministic State: Clear Cache and Disable LLM to force Fallback
        # But ensure Seed is Present
        from ssh_honeypot.honey_db import HoneyDB
        db = HoneyDB()
        conn = db._get_conn()
        # Clean existing test data if needed.
        # But we want to Seeding to Work.
        conn.close()
        
        # Seed FS for tests that rely on static files (like test_cd_logic)
        ssh_honeypot.fs_seeder.seed_filesystem(db)
        
        # Disable LLM to ensure we hit the static fallback/logic code path
        ssh_honeypot.server.llm.api_key = ""
        
        if not is_server_running(TEST_PORT):
            print(f"[*] Starting Test Server on {TEST_PORT}")
            cls.server_thread = threading.Thread(target=server_main, args=([],))
            cls.server_thread.daemon = True
            cls.server_thread.start()
            
            # Wait for startup
            start = time.time()
            while time.time() - start < 10:
                if is_server_running(TEST_PORT): break
                time.sleep(0.2)
            else:
                raise RuntimeError("Server failed to start")
        else:
             pass
        
    def setUp(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect('127.0.0.1', port=TEST_PORT, username='testuser', password='password', look_for_keys=False, allow_agent=False)

    def tearDown(self):
        self.client.close()

    def test_cd_logic(self):
        """
        Test: cd /etc
        Goal: Verify cd updates the cwd state.
        We MUST test cd and ls in the SAME channel/session (invoke_shell).
        """
        chan = self.client.invoke_shell()
        
        # Wait for initial prompt
        buff = b""
        start = time.time()
        while time.time() - start < 5:
             if chan.recv_ready():
                 buff += chan.recv(4096)
                 if b'$ ' in buff or b'# ' in buff:
                     break
             time.sleep(0.1)

        print(f"DEBUG Initial Prompt: {repr(buff)}")

        # Verify DB has data (Sanity check)
        from ssh_honeypot.honey_db import HoneyDB
        db = HoneyDB()
        passwd_node = db.get_fs_node('/etc/passwd')
        print(f"DEBUG DB Check /etc/passwd: {passwd_node}")
        if not passwd_node:
             self.fail("DB check failed: /etc/passwd missing from global_filesystem table")
        
        # 1. CD to /etc
        print("DEBUG Sending 'cd /etc'")
        chan.send("cd /etc\n")
        
        # Wait for prompt to return
        # Since our optimization returns empty buffer on success, we just expect a new prompt
        buff = b""
        start = time.time()
        while time.time() - start < 3:
             if chan.recv_ready():
                 chunk = chan.recv(4096)
                 buff += chunk
                 if b'$ ' in chunk or b'# ' in chunk:
                     break
             time.sleep(0.1)
        
        print(f"DEBUG Post-CD Output: {repr(buff)}")
             
        # 2. LS to verify we are in /etc
        print("DEBUG Sending 'ls'")
        chan.send("ls\n")
        
        buff = b""
        start = time.time()
        while time.time() - start < 5:
             if chan.recv_ready():
                 chunk = chan.recv(8192) # Read big chunk
                 buff += chunk
                 if b'$ ' in chunk or b'# ' in chunk: 
                     break 
             time.sleep(0.1)
             
        out = buff.decode('utf-8', errors='ignore')
        print(f"DEBUG LS Output: {repr(out)}")
        
        # /etc contains 'passwd', 'shadow', etc.
        if "passwd" not in out:
             self.fail(f"'passwd' not found in ls output (cwd was likely not updated). Output was: {repr(out)}")
        self.assertIn("shadow", out)

if __name__ == "__main__":
    unittest.main()
