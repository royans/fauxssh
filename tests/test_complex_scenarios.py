import paramiko
import sys
import unittest
import threading
import time
import socket
import os
import random

# Ensure we can import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.server import main as server_main, BIND_IP
import ssh_honeypot.server
import ssh_honeypot.fs_seeder

TEST_PORT = 2224 # Use a different port to avoid conflicts

def is_server_running(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

class TestComplexScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Patch PORT
        ssh_honeypot.server.PORT = TEST_PORT
        ssh_honeypot.server.ip_connection_counts.clear()
        
        # 1. Deterministic State: Clear Cache and Disable LLM to force Fallback
        from ssh_honeypot.honey_db import HoneyDB
        db = HoneyDB()
        conn = db._get_conn()
        conn.execute("DELETE FROM command_cache WHERE command = '_global_process_list'")
        conn.commit()
        conn.commit()
        conn.close()
        
        
        # Seed FS for tests that rely on static files (like test_cd_logic)
        ssh_honeypot.fs_seeder.seed_filesystem(db)
        
        # Disable LLM to ensure we hit the static fallback code path (which has 'nginx')
        # instead of relying on stochastic LLM generation.
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
        # Reuse existing server - assume it picks up the monkeypatch?
        # Yes, global 'llm' obj is mutated.
        else:
             # Even if running, we mutate the global llm object.
             pass
        
    def setUp(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect('127.0.0.1', port=TEST_PORT, username='testuser', password='password')

    def tearDown(self):
        self.client.close()

    def test_ps_grep_pipe(self):
        """
        Test: ps -aef | grep nginx
        Goal: Verify that 'ps' returns process list (fallback or LLM) and 'grep' filters it.
        The fallback data contains 'nginx', so we expect a match.
        """
        stdin, stdout, stderr = self.client.exec_command('ps -aef | grep nginx')
        out = stdout.read().decode().strip()
        
        # Verify output
        print(f"DEBUG OUTPUT: {out}")
        self.assertIn("nginx", out)
        self.assertIn("www-data", out)
        # Verify filtering: 'sshd' (present in fallback) should NOT be in output because we grep for nginx
        self.assertNotIn("sshd", out)

    def test_ps_grep_pipe_case_insensitive(self):
        """
        Test: ps -aef | grep -i NGINX
        """
        stdin, stdout, stderr = self.client.exec_command('ps -aef | grep -i NGINX')
        out = stdout.read().decode().strip()
        self.assertIn("nginx", out)

    def test_ps_grep_pipe_inverse(self):
        """
        Test: ps -aef | grep -v root
        Goal: exclude root processes
        """
        stdin, stdout, stderr = self.client.exec_command('ps -aef | grep -v root')
        out = stdout.read().decode().strip()
        # Fallback has nginx as www-data, so some lines remain
        self.assertIn("nginx", out)
        # Should not have root (unless grep matches 'root' in PID or something, but usually user column is checked)
        # The fallback list has 'root' user.
        self.assertNotIn("root", out)

    def test_uptime(self):
        """
        Test: uptime
        Goal: Verify our static handler returns expected format.
        """
        stdin, stdout, stderr = self.client.exec_command('uptime')
        out = stdout.read().decode().strip()
        print(f"UPTIME OUT: {out}")
        self.assertIn("load average:", out)
        self.assertIn("up 14 days", out)

    def test_local_handlers(self):
        """
        Test: free, df, mount
        Goal: Verify they return structured output (not empty).
        """
        first = True
        for cmd in ['mount', 'free', 'df']:
            if not first:
                 self.client.close()
                 self.client.connect('127.0.0.1', port=TEST_PORT, username='testuser', password='password')
            first = False

            stdin, stdout, stderr = self.client.exec_command(cmd)
            out = stdout.read().decode().strip()
            self.assertTrue(len(out) > 10, f"{cmd} output too short")

    def test_wc_secret(self):
        """
        Test: wc notes.txt
        Goal: Verify wc works on a hardcoded secret file (bypassing LLM).
        Secret: "Hint: RudolphsRedNose2025!"
        """
        stdin, stdout, stderr = self.client.exec_command('wc notes.txt')
        out = stdout.read().decode().strip()
        print(f"DEBUG wc: {out}")
        # Expected content is 1 line, 2 words ("Hint:", "Rudolph..."), ~26 chars
        self.assertIn("1", out)
        self.assertIn("notes.txt", out)

    def test_date_dynamic(self):
        """
        Test: date
        Goal: Verify date returns non-empty string.
        """
        stdin, stdout, stderr = self.client.exec_command('date')
        out = stdout.read().decode().strip()
        self.assertTrue(len(out) > 10)
        import datetime
        current_year = str(datetime.datetime.now().year)
        self.assertIn(current_year, out)

    def test_id(self):
        """
        Test: id
        Goal: Verify id returns uid/gid info.
        """
        stdin, stdout, stderr = self.client.exec_command('id')
        out = stdout.read().decode().strip()
        self.assertIn("uid=", out)
        self.assertIn("uid=", out)
        self.assertIn("gid=", out)



if __name__ == "__main__":
    unittest.main()
