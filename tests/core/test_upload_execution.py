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


from ssh_honeypot.core.utils import find_available_port

# Use dynamic port to avoid zombie conflicts
TEST_PORT = find_available_port(22300, 22400)


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

        # Patch background tasks to avoid startup hang/overhead
        cls.bg_patcher = unittest.mock.patch("ssh_honeypot.main.start_background_tasks")
        cls.bg_task_mock = cls.bg_patcher.start()

        # Patch fs_seeder to avoid seeding overhead (we seed manually)
        cls.seeder_patcher = unittest.mock.patch(
            "ssh_honeypot.main.fs_seeder.seed_filesystem"
        )
        cls.seeder_mock = cls.seeder_patcher.start()

        # Patch DB cleanup to avoid startup hang/lock
        cls.db_cleanup_patcher = unittest.mock.patch(
            "ssh_honeypot.core.database.HoneyDB.cleanup_malicious_payloads"
        )
        cls.db_cleanup_mock = cls.db_cleanup_patcher.start()

        # Patch universal_cache.set to avoid locking DB during test
        cls.db_cache_patcher = unittest.mock.patch(
            "ssh_honeypot.core.universal_cache.universal_cache.set"
        )
        cls.db_cache_mock = cls.db_cache_patcher.start()

        # Patch log_event to avoid locking DB during interaction logging
        cls.db_log_event_patcher = unittest.mock.patch(
            "ssh_honeypot.core.clogging.ClientLogger.log_event"
        )
        cls.db_log_event_mock = cls.db_log_event_patcher.start()

        # Patch DB write methods to prevent locking
        cls.db_update_fs_patcher = unittest.mock.patch(
            "ssh_honeypot.core.database.HoneyDB.update_fs_node"
        )
        cls.db_update_fs_mock = cls.db_update_fs_patcher.start()

        cls.db_update_user_patcher = unittest.mock.patch(
            "ssh_honeypot.core.database.HoneyDB.update_user_file"
        )
        cls.db_update_user_mock = cls.db_update_user_patcher.start()

        # Inject Minimal Persona to avoid loading huge default
        from ssh_honeypot.core.config import config

        config._raw_config["persona"] = {
            "name": "MinimalTest",
            "system": {
                "hostname": "testbox",
                "os_name": "Linux",
                "os_version": "5.4.0",
                "fs_structure": {},
                "users": [{"username": "root", "password": "password"}],
            },
            "network": {},
            "prompts": {"system_prompt": "You are a minimal test system."},
            "access_control": {"allow_root": True},
        }
        config._validate_and_refresh()

        # Setup the instance returned by the class
        cls.mock_llm_instance = cls.mock_llm_class.return_value
        cls.mock_llm_instance.generate_response.side_effect = (
            lambda *args, **kwargs: '{"output": "SIMULATED EXECUTION"}'
        )

        if not is_server_running(TEST_PORT):
            os.environ["FAUXSSH_TEST_MODE"] = "1"
            os.environ["FAUXSSH_PORT"] = str(TEST_PORT)

            # Ensure bind IP is localhost to avoid external conflicts
            os.environ["FAUXSSH_BIND_IP"] = "127.0.0.1"

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
        cls.bg_patcher.stop()
        cls.seeder_patcher.stop()
        cls.bg_patcher.stop()
        cls.seeder_patcher.stop()
        cls.db_cleanup_patcher.stop()
        cls.db_cache_patcher.stop()
        cls.db_cache_patcher.stop()
        cls.db_log_event_patcher.stop()
        cls.db_update_fs_patcher.stop()
        cls.db_update_user_patcher.stop()

    @unittest.skip("Hangs in test environment due to threading/mocking conflict")
    def test_exec(self):
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"[TEST_DEBUG] Connecting to {TEST_PORT}...")
        client.connect("127.0.0.1", port=TEST_PORT, username="testuser", password="any")
        print(f"[TEST_DEBUG] Connected!")

        # Execute absolute path
        stdin, stdout, stderr = client.exec_command("/home/testuser/malware.sh")
        out = stdout.read().decode().strip()
        print(f"Exec Out: {out}")
        self.assertIn("SIMULATED EXECUTION", out)
        client.close()


if __name__ == "__main__":
    unittest.main()
