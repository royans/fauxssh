
import unittest
import threading
import time
import socket
import os
import sys

sys.path.append(os.getcwd())
try:
    from ssh_honeypot.server import main as server_main
    import ssh_honeypot.server
except ImportError:
    pass

TEST_PORT = 2233

def is_server_running(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

class TestSCP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ssh_honeypot.server.PORT = TEST_PORT
        ssh_honeypot.server.ip_connection_counts.clear()
        
        if not is_server_running(TEST_PORT):
            cls.server_thread = threading.Thread(target=server_main, args=([],))
            cls.server_thread.daemon = True
            cls.server_thread.start()
            time.sleep(2)

    def setUp(self):
        # Reset quotas for 127.0.0.1 (DELETE FROM user_filesystem WHERE ip='127.0.0.1')
        try:
            from ssh_honeypot.honey_db import HoneyDB, DB_PATH
            
            # Increase Quota for Test (config object is shared if imported)
            # Necessary because ensure_user_home seeds ~1MB of files on login, consuming default quota.
            from ssh_honeypot.config_manager import config
            config._config['upload']['max_quota_per_ip'] = 10 * 1024 * 1024 # 10MB
            
            db = HoneyDB()
            conn = db._get_conn()
            conn.execute("DELETE FROM user_filesystem WHERE ip = ?", ('127.0.0.1',))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Warning: Failed to reset quotas in setUp: {e}")

    def test_scp_upload(self):
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect('127.0.0.1', port=TEST_PORT, username='testuser', password='any')
        
        # SCP uses exec channel
        chan = client.get_transport().open_session()
        chan.exec_command("scp -t /home/testuser/uploaded_manual.txt")
        
        # 1. Read Ready Byte
        resp = chan.recv(1)
        self.assertEqual(resp, b'\x00', "Server did not send Ready byte")
        
        # 2. Send Header (C mode size name)
        # 0644, 4 bytes, name=test.txt
        chan.send(b"C0644 4 test.txt\n")
        
        # 3. Read ACK
        resp = chan.recv(1)
        self.assertEqual(resp, b'\x00', "Server did not ACK Header")
        
        # 4. Send Content (4 bytes)
        chan.send(b"test")
        
        # 5. Send End Data (0)
        chan.send(b'\x00')
        
        # 6. Read ACK
        resp = chan.recv(1)
        self.assertEqual(resp, b'\x00', "Server did not ACK Data")
        
        client.close()
        print("SCP Protocol Test Passed")

if __name__ == "__main__":
    unittest.main()
