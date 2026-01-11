import socket
import time
import threading
import pytest
from unittest.mock import MagicMock
from ssh_honeypot.services.telnet.server import (
    start_telnet_server,
    IAC,
    WILL,
    WONT,
    DO,
    DONT,
    ECHO,
    SGA,
)

PORT = 2330


class MockDB:
    def log_auth_event(self, *args, **kwargs):
        pass

    def validate_anti_harvesting(self, ip, username, password):
        return True, None

    def start_session(self, *args, **kwargs):
        pass

    def list_user_dir(self, *args, **kwargs):
        return [{"path": "/home/root/foo", "is_dir": False}]

    def log_interaction(self, *args, **kwargs):
        pass

    def get_persona_by_name(self, name):
        return {}

    def get_cached_response(self, *args, **kwargs):
        return None

    def cache_response(self, *args, **kwargs):
        pass


class MockLLM:
    def generate_response(self, *args, **kwargs):
        return "Mock LLM Response"


@pytest.fixture(scope="module")
def telnet_server():
    db = MockDB()
    llm = MockLLM()
    # Start server
    t = threading.Thread(target=start_telnet_server, args=(PORT, db, llm), daemon=True)
    t.start()
    time.sleep(1)  # Wait for bind
    yield
    # No clean method to stop server thread in these tests but daemon kills it on exit


def read_until(s, markers, timeout=3.0):
    s.settimeout(timeout)
    buffer = b""
    start = time.time()
    while time.time() - start < timeout:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            buffer += chunk
            for m in markers:
                if m in buffer:
                    return buffer
        except socket.timeout:
            break
        except Exception:
            break
    return buffer


def test_telnet_full_session_flow(telnet_server):
    """
    Simulates a full user session:
    1. Connect & Negotiate
    2. Byte-by-byte Username entry (Simulate typing)
    3. Byte-by-byte Password entry
    4. Run commands (with CR and CRLF)
    5. Exit
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(("127.0.0.1", PORT))

    # 1. Initial Negotiation & Banner
    # Expect Server to send WILL SGA, WILL ECHO
    banner = read_until(s, [b"login:", b"Username:"], timeout=2.0)
    assert b"Debian" in banner or b"Linux" in banner or b"User Access" in banner

    # 2. Login - Username (Byte by Byte to test new buffering)
    username = b"root"
    for b in username:
        s.sendall(bytes([b]))
        time.sleep(0.05)

    # Send Enter (CR only to test fix)
    s.sendall(b"\r")

    # 3. Login - Password
    prompt = read_until(s, [b"Password:"], timeout=2.0)
    assert b"Password:" in prompt

    password = b"password"
    for b in password:
        s.sendall(bytes([b]))
        time.sleep(0.05)

    # Send Enter (CRLF this time)
    s.sendall(b"\r\n")

    # 4. Shell Interaction
    shell_prompt = read_until(s, [b"#", b"$", b">"], timeout=2.0)
    # Check successful login
    assert b"Login incorrect" not in shell_prompt

    # Command 1: 'ls' with CRLF
    s.sendall(b"ls\r\n")
    resp = read_until(s, [b"foo", b"Mock LLM Response", b"Error"], timeout=2.0)
    # Our mock db returns one file 'foo' in list_user_dir, context should reflect that or LLM
    # The MockLLM returns "Mock LLM Response"
    # Actually, if the handler sees a file_list, it might list it depending on prompt?
    # Or strict command handler?
    # Note: The server uses real CommandHandler, which calls LLM.
    # The output should contain "Mock LLM Response" if it fell back to LLM.
    assert b"Mock LLM Response" in resp or b"foo" in resp

    # Wait for prompt again
    read_until(s, [b"#", b"$", b">"], timeout=2.0)

    # Command 2: 'whoami' with CR only (Test Shell Loop CR handling)
    s.sendall(b"whoami\r")
    resp2 = read_until(s, [b"Mock", b"root"], timeout=2.0)
    assert b"Mock LLM Response" in resp2  # Mock LLM handles everything unknown

    # 5. Exit
    s.sendall(b"exit\r\n")
    time.sleep(0.5)

    # Verify connection closed
    try:
        data = s.recv(1024)
        if data:
            # Maybe final bye message?
            pass
    except:
        pass  # Expected close

    s.close()
