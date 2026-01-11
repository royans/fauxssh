import socket
import time
import threading
import pytest
from unittest.mock import MagicMock
from ssh_honeypot.services.telnet.server import (
    start_telnet_server,
    IAC,
    DO,
    DONT,
    WILL,
    WONT,
    ECHO,
    SGA,
)

PORT = 2328


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

    def get_persona_by_name(self, name):
        return {}


class MockLLM:
    def generate_response(self, *args, **kwargs):
        return "Mock Response"


@pytest.fixture(scope="module")
def start_enter_server():
    db = MockDB()
    llm = MockLLM()
    t = start_telnet_server(PORT, db, llm)
    time.sleep(1)
    yield


def test_telnet_enter_cr_only(start_enter_server):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("127.0.0.1", PORT))

    # Login
    s.recv(4096)
    s.sendall(b"root\n")
    s.recv(4096)
    s.sendall(b"pass\n")

    # Wait for Shell Prompt
    buffer = b""
    while b">" not in buffer and b"$" not in buffer:
        buffer += s.recv(4096)

    # Test 1: Send command terminated by CR only (mimicking some raw clients)
    # We use 'foo' which will error but produce output
    s.sendall(b"foo\r")

    time.sleep(0.5)
    resp = s.recv(4096)

    # Expect: "\r\n" (echo of Enter) + Execution Error or Output
    # If the server ignored CR, we would get NO response (timeout)
    assert b"foo" in resp  # Echo
    assert (
        b"Error processing command" in resp or b"Mock Response" in resp or b"% " in resp
    )
    # NOTE: Our mock LLM command handler will probably trigger "Error processing" or similar.

    s.close()


def test_telnet_enter_crlf(start_enter_server):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("127.0.0.1", PORT))

    # Login
    s.recv(4096)
    s.sendall(b"root\n")
    s.recv(4096)  # Password prompt
    s.sendall(b"pass\n")

    # Shell
    while b">" not in s.recv(4096):
        pass

    # Test 2: Standard CRLF
    s.sendall(b"bar\r\n")

    time.sleep(0.5)
    resp = s.recv(4096)

    assert b"bar" in resp
    assert b"Error" in resp or b"Mock" in resp

    s.close()
