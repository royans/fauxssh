import unittest
import threading
import time
import socket
import os
from unittest.mock import MagicMock
from ssh_honeypot.services.redis.server import start_redis_server

TEST_PORT = 6380


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
        cls.db = MagicMock()
        cls.db.get_cached_response.return_value = None  # Cache miss by default

        cls.llm = MagicMock()
        cls.llm.generate_response.return_value = "OK"  # Return string, not Mock

        # Start server in thread
        cls.server_thread = threading.Thread(
            target=start_redis_server, args=(TEST_PORT, cls.db, cls.llm)
        )
        cls.server_thread.daemon = True
        cls.server_thread.start()

        # Wait for startup
        start = time.time()
        while time.time() - start < 5:
            if is_port_open(TEST_PORT):
                break
            time.sleep(0.1)

    def setUp(self):
        # Reset mock return values and calls for each test
        self.llm.generate_response.return_value = "OK"
        self.db.start_session.reset_mock()
        self.db.log_interaction.reset_mock()

    def test_ping(self):
        self.llm.generate_response.return_value = "PONG"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", TEST_PORT))
        s.send(b"PING\r\n")
        resp = s.recv(1024)
        s.close()
        self.assertIn(b"+PONG", resp)

    def test_command(self):
        self.llm.generate_response.return_value = "OK"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", TEST_PORT))
        s.send(b"COMMAND\r\n")
        resp = s.recv(1024)
        s.close()
        self.assertIn(b"+OK", resp)

    def test_unknown(self):
        # Determine strict expectation or adjust mock
        # We ensure the mock returns exactly what handler Expects for an error
        self.llm.generate_response.return_value = "ERR unknown command"

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", TEST_PORT))
        s.send(b"BLAH\r\n")
        resp = s.recv(1024)
        s.close()
        # The handler might return -ERR or +ERR depending on implementation, but handler.py says -ERR
        self.assertTrue(resp.startswith(b"-ERR"), f"Response was: {resp}")

    def test_logging(self):
        # Reset mock
        self.db.start_session.reset_mock()
        self.db.log_interaction.reset_mock()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", TEST_PORT))
        s.send(b"PING\r\n")
        time.sleep(0.5)  # Increased from 0.1
        s.close()
        time.sleep(0.5)  # Increased from 0.1

        # Verify calls
        self.db.start_session.assert_called()
        self.db.log_interaction.assert_called()

        # Verify Protocol Arg
        args, kwargs = self.db.start_session.call_args
        self.assertEqual(kwargs.get("protocol"), "redis")


if __name__ == "__main__":
    unittest.main()
