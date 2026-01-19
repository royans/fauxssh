import unittest
from unittest.mock import MagicMock
import threading
import time
import socket
import os
import sys

sys.path.append(os.getcwd())
try:
    from ssh_honeypot.main import main as server_main
    import ssh_honeypot.services.ssh.server
    from ssh_honeypot.core.database import HoneyDB
except ImportError:
    pass

TEST_PORT = 2230


def is_server_running(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except:
        return False


class TestExecSim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ssh_honeypot.services.ssh.server.PORT = TEST_PORT
        ssh_honeypot.services.ssh.server.ip_connection_counts.clear()

        # Seed DB with a "malware" file manually
        db = HoneyDB()
        db.update_fs_node(
            "/home/testuser/malware.sh",
            "/home/testuser",
            "file",
            {"permissions": "-rwxr-xr-x"},
            "#!/bin/bash\necho 'SIMULATED EXECUTION'",
        )

        # Patch LLMInterface in main.py to return our mock
        # We need to start the server with the mocked class
        cls.llm_patcher = unittest.mock.patch("ssh_honeypot.main.LLMInterface")
        cls.mock_llm_class = cls.llm_patcher.start()

        # Setup the instance returned by the class
        cls.mock_llm_instance = cls.mock_llm_class.return_value
        cls.mock_llm_instance.generate_response.side_effect = (
            lambda *args, **kwargs: '{"output": "SIMULATED EXECUTION"}'
        )

        if not is_server_running(TEST_PORT):
            os.environ["FAUXSSH_TEST_MODE"] = "1"
            os.environ["FAUXSSH_PORT"] = str(TEST_PORT)
            cls.server_thread = threading.Thread(target=server_main, args=([],))
            cls.server_thread.daemon = True
            cls.server_thread.start()
            # Wait for startup (increased timeout for background startup tasks)
            start = time.time()
            while time.time() - start < 30:
                if is_server_running(TEST_PORT):
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("Server failed to start")

    @classmethod
    def tearDownClass(cls):
        cls.llm_patcher.stop()

    def test_exec(self):
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect("127.0.0.1", port=TEST_PORT, username="testuser", password="any")

        # Execute absolute path
        stdin, stdout, stderr = client.exec_command("/home/testuser/malware.sh")
        out = stdout.read().decode().strip()
        print(f"Exec Out: {out}")
        self.assertIn("SIMULATED EXECUTION", out)
        client.close()


if __name__ == "__main__":
    unittest.main()
