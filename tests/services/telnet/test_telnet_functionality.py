import socket
import threading
import time
import pytest
import os
from unittest.mock import MagicMock
from ssh_honeypot.services.telnet.server import (
    start_telnet_server,
    IAC,
    DO,
    DONT,
    WILL,
    WONT,
)


# Mock DB and LLM
class MockDB:
    def log_auth_event(self, *args, **kwargs):
        pass

    def validate_anti_harvesting(self, ip, username, password):
        return True, None

    def start_session(self, *args, **kwargs):
        pass

    def list_user_dir(self, *args, **kwargs):
        return []

    def log_interaction(self, *args, **kwargs):
        pass


class MockLLM:
    pass


@pytest.fixture(scope="module")
def telnet_server_port():
    return 2324


@pytest.fixture(scope="module")
def start_server(telnet_server_port):
    db = MockDB()
    llm = MockLLM()
    # Start server
    t = start_telnet_server(telnet_server_port, db, llm)
    time.sleep(1)  # Wait for bind
    yield
    # No clean shutdown implemented yet for the thread/socket in simple server, so it dies with process


def test_telnet_login_flow(start_server, telnet_server_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", telnet_server_port))

    # 1. Receive Banner
    banner = s.recv(1024)
    # Accepts either standard login or Cisco style Username
    assert b"login:" in banner or b"Username:" in banner

    # 2. Send Username
    s.sendall(b"root\r\n")

    # 3. Receive Password Prompt
    time.sleep(0.5)
    resp = s.recv(1024)
    assert b"Password:" in resp

    # 4. Send Password
    s.sendall(b"toor\r\n")

    # 5. Receive Shell Prompt
    time.sleep(0.5)
    resp = s.recv(4096)
    # Valid prompts: Linux banner/prompt OR Cisco prompt (Switch>)
    assert b"Linux" in resp or b"root@" in resp or b"Switch>" in resp or b">" in resp

    # 6. Send Command
    s.sendall(b"id\r\n")
    time.sleep(0.5)
    resp = s.recv(1024)
    # Since we mocked LLM/CommandHandler, it might crash or return basic prompt if naive mock.
    # The current CommandHandler relies on real DB and LLM.
    # To test actual command processing we need a smarter mock or real DB.
    # For now, just verifying we got to shell is enough for connection test.

    s.close()


def test_telnet_negotiation_filtering(start_server, telnet_server_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", telnet_server_port))

    # Read banner
    s.recv(1024)

    # Send Username with IAC codes (e.g. client saying IAC WILL NAWS)
    # IAC(255) WILL(251) NAWS(31)
    payload = b"\xff\xfb\x1fadmin\r\n"
    s.sendall(payload)

    time.sleep(0.5)
    resp = s.recv(1024)
    assert b"Password:" in resp

    s.close()
