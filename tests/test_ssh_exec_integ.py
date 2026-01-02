import paramiko
import sys
import unittest
import threading
import time
import socket
import os

# Ensure we can import server
# Ensure we can import server
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.server import main as server_main, BIND_IP
import ssh_honeypot.server # Allow access to globals
from unittest.mock import MagicMock

TEST_PORT = 2223

def is_server_running():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(('127.0.0.1', TEST_PORT))
        s.close()
        return True
    except:
        return False

class TestSSHExec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Patch PORT
        ssh_honeypot.server.PORT = TEST_PORT
        
        # Reset counters to allow reuse even if previous tests leaked sessions
        ssh_honeypot.server.ip_connection_counts.clear()
        
        if not is_server_running():
            # Start Server in Thread
            print(f"[*] Starting Test Server on {TEST_PORT}")
            cls.server_thread = threading.Thread(target=server_main, args=([],))
            cls.server_thread.daemon = True # Daemonize so it dies with main
            cls.server_thread.start()
            
            # Wait for port to respond (simple health check)
            start = time.time()
            while time.time() - start < 5:
                if is_server_running(): break
                time.sleep(0.5)
            else:
                raise RuntimeError("Server failed to start in test setup")
        else:
            print(f"[*] Server already running on {TEST_PORT}, reusing...")

    def test_hostname(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect('127.0.0.1', port=TEST_PORT, username='test', password='any')
            stdin, stdout, stderr = client.exec_command('hostname')
            out = stdout.read().decode().strip()
            # self.assertEqual(out, "npc-main-server-01") # Depends on config, usually default
            self.assertTrue(len(out) > 0)
        finally:
            client.close()

    def test_command_chaining(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect('127.0.0.1', port=TEST_PORT, username='test', password='any')
            
            # Test 1: Simple Chaining
            stdin, stdout, stderr = client.exec_command("pwd ; pwd")
            out = stdout.read().decode().strip()
            self.assertIn("/home/test", out)
            self.assertEqual(out.count("/home/test"), 2)

            # Test 2: State Persistence with Chaining
            # Note: We create a new client connection for each exec_command usually in standard SSH (unless reusing transport).
            # Paramiko exec_command reuses the transport but opens a new channel. 
            # Our honeypot maintains session by Session ID. 
            # WAIT: If exec_command opens a new channel, does our server assign a NEW session ID?
            
            # Server logic:
            # transport.accept() -> server.event.wait() -> "New Session {id}"
            # So ONE transport = ONE session ID ideally?
            # Looking at server.py:
            # handle_connection -> transport = paramiko.Transport(client) -> list loop waiting for accept().
            # chan = transport.accept(20)
            # ...
            # db.start_session(...)
            # while True: char = chan.recv() ...
            
            # WARNING: Our server currently implements a SINGLE-CHANNEL loop per connection in `handle_connection`.
            # server.py line 163: `chan = transport.accept(20)`
            # It accepts ONE channel. Then enters the loop.
            # If client tries to open a SECOND channel (for 2nd exec_command), our server loop is busy or not listening for accept() again?
            # `handle_connection` logic blocks on `chan.recv` or `handle_exec`.
            # Once `chan.close()` (after exec), the server loop returns/breaks?
            
            # server.py line 255: `chan.close()`, then `return`.
            # `handle_connection` finishes. socket closes. 
            # So we CANNOT reuse the connection for multiple exec_commands currently.
            # Client MUST reconnect.
            
            # BUT: Chaining `cd /etc ; pwd` sends EVERYTHING in ONE exec_command channel.
            # So this works fine.
            
            # Reconnect for clean state
            client.close()
            client.connect('127.0.0.1', port=TEST_PORT, username='test', password='any')
            
            stdin, stdout, stderr = client.exec_command("cd /etc ; pwd")
            out = stdout.read().decode().strip()
            self.assertIn("/etc", out)
            self.assertNotIn("/home", out)
            
        finally:
            client.close()

if __name__ == "__main__":
    unittest.main()
