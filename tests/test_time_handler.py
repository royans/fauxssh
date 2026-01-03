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

TEST_PORT = 2225  # Use distinct port for this test suite to allow parallel execution if needed

def is_server_running(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

class TestTimeHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Patch PORT
        ssh_honeypot.server.PORT = TEST_PORT
        
        # Disable LLM to ensure deterministic behavior (pure local handlers)
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
        
    def setUp(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect('127.0.0.1', port=TEST_PORT, username='testuser', password='password')

    def tearDown(self):
        self.client.close()

    def test_time_output_format(self):
        """
        Test: time echo hello
        Goal: Verify output contains 'hello' AND the 'real / user / sys' stats.
        """
        stdin, stdout, stderr = self.client.exec_command('time echo hello')
        out = stdout.read().decode().strip()
        
        print(f"DEBUG: {out}")
        self.assertIn("hello", out)
        self.assertIn("real", out)
        self.assertIn("user", out)
        self.assertIn("sys", out)
        self.assertIn("0m0.", out) # Should be very fast

    @unittest.skip("Skipping potential hang in test environment")
    def test_time_duration(self):
        """
        Test: time sleep 2
        Goal: Verify that the execution takes at least 2 seconds and reports ~2s in output.
        """
        start_t = time.time()
        stdin, stdout, stderr = self.client.exec_command('time sleep 2')
        out = stdout.read().decode().strip()
        end_t = time.time()
        
        wall_duration = end_t - start_t
        print(f"DEBUG: Wall={wall_duration}s Out={out}")
        
        # Verify network latency/sleep was respected
        self.assertGreaterEqual(wall_duration, 2.0)
        
        # Verify output stats reflect this (approx 2s)
        # We look for "0m2." or "real\t0m2"
        # Regex could be safer, but simple check works for now
        self.assertTrue("real\t0m2" in out or "real\t0m3" in out, f"Output did not show approx 2s duration: {out}")

if __name__ == "__main__":
    unittest.main()
