import unittest
import threading
import time
import socket
import os
from unittest.mock import MagicMock
from ssh_honeypot.services.redis.server import start_redis_server


def is_port_open(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except:
        return False


class TestRedisServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ssh_honeypot.core.universal_cache import universal_cache

        universal_cache.clear_service("redis")
        cls.db = MagicMock()
        cls.db.get_cached_response.return_value = None
        cls.llm = MagicMock()
        cls.llm.generate_response.return_value = "OK"

        # Find a free port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 0))
        cls.test_port = s.getsockname()[1]
        s.close()

        # Start server in thread
        cls.server_thread = threading.Thread(
            target=start_redis_server, args=(cls.test_port, cls.db, cls.llm)
        )
        cls.server_thread.daemon = True
        cls.server_thread.start()

        # Wait for startup
        start = time.time()
        while time.time() - start < 5:
            if is_port_open(cls.test_port):
                break
            time.sleep(0.1)

    def setUp(self):
        from ssh_honeypot.core.universal_cache import universal_cache

        universal_cache.clear_service("redis")
        self.llm.generate_response.return_value = "OK"
        self.db.start_session.reset_mock()
        self.db.log_interaction.reset_mock()

        # PATCH SLOGGER TO USE COMPATIBLE DB MOCK
        from ssh_honeypot.core.slogging import slogger

        self.old_slogger_db = slogger._db
        slogger._db = self.db

        # CONFIG CLOGGER FOR INSTANT FLUSH
        from ssh_honeypot.core.clogging import clogger

        clogger.settings["batch_size"] = 1
        clogger.settings["batch_timeout"] = 0.1
        clogger.enabled = True
        clogger.log_mode = "local"

    def tearDown(self):
        # Restore slogger
        from ssh_honeypot.core.slogging import slogger

        slogger._db = self.old_slogger_db

    def test_ping(self):
        self.llm.generate_response.return_value = "PONG"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.test_port))
        s.send(b"PING\r\n")
        resp = s.recv(1024)
        s.close()
        self.assertIn(b"+PONG", resp)

    def test_command(self):
        self.llm.generate_response.return_value = "OK"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.test_port))
        s.send(b"COMMAND\r\n")
        resp = s.recv(1024)
        s.close()
        self.assertIn(b"+OK", resp)

    def test_unknown(self):
        self.llm.generate_response.return_value = "ERR unknown command"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.test_port))
        s.send(b"BLAH\r\n")
        resp = s.recv(1024)
        s.close()
        self.assertTrue(resp.startswith(b"-ERR"), f"Response was: {resp}")

    def test_logging(self):
        self.db.start_session.reset_mock()
        self.db.log_interaction.reset_mock()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", self.test_port))
        s.send(b"PING\r\n")
        time.sleep(1.0)
        s.close()

        # Wait up to 5 seconds for logging to occur (background thread)
        start = time.time()
        while time.time() - start < 5:
            if self.db.start_session.called and self.db.log_interaction.called:
                break
            time.sleep(0.1)

        self.assertTrue(self.db.start_session.called, "db.start_session was not called")
        self.assertTrue(
            self.db.log_interaction.called, "db.log_interaction was not called"
        )


if __name__ == "__main__":
    unittest.main()
