import socket
import time
import threading
import pytest
from unittest.mock import MagicMock
from ssh_honeypot.services.telnet.server import start_telnet_server, IAC, DO, DONT, WILL, WONT, ECHO, SGA

# Mock DB and LLM
class MockDB:
    def log_auth_event(self, *args, **kwargs):
        pass
    
    def validate_anti_harvesting(self, ip, username, password):
        return True, None

    def start_session(self, *args, **kwargs):
        pass
    def list_user_dir(self, *args, **kwargs): return []
    def log_interaction(self, *args, **kwargs): pass
    
    def get_persona_by_name(self, name): return {}

class MockLLM:
    def generate_response(self, *args, **kwargs): return "Mock Response"

@pytest.fixture(scope="module")
def telnet_echo_port():
    return 2326

@pytest.fixture(scope="module")
def start_echo_server(telnet_echo_port):
    db = MockDB()
    llm = MockLLM()
    # Start server
    t = start_telnet_server(telnet_echo_port, db, llm)
    time.sleep(1) # Wait for bind
    yield
    # Cleanup implies process death usually for simple threads

def test_telnet_echo_negotiation_and_backspace(start_echo_server, telnet_echo_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(('127.0.0.1', telnet_echo_port))
    
    # 1. Login Phase
    # Receive Banner. Should NOW include WILL SGA + WILL ECHO early negotiation
    # 1. Login Phase
    # Receive Banner. Should NOW include WILL SGA + WILL ECHO early negotiation
    banner = b""
    # Buffering loop to handle packet fragmentation/latency
    start_time = time.time()
    while (IAC + WILL + SGA not in banner or IAC + WILL + ECHO not in banner) and time.time() - start_time < 2:
        try:
            chunk = s.recv(1024)
            if not chunk: break
            banner += chunk
        except socket.timeout:
            break

    assert IAC + WILL + SGA in banner
    assert IAC + WILL + ECHO in banner
    
    # Send User
    s.sendall(b"root\r\n")
    
    # Receive Password Prompt. 
    # Should include WILL ECHO (for password masking)
    chunk = s.recv(1024)
    # It might be in banner or separate packet. 
    # Usually separate after user sends line.
    # Note: socket recv is tricky, we might catch partials.
    # But usually we wait for "Password:" string.
    
    buffer = chunk
    while b"Password:" not in buffer:
        buffer += s.recv(1024)
    
    assert b"Password:" in buffer
    # We expect WILL ECHO to mask password (Server handles, client silent)
    assert IAC + WILL + ECHO in buffer or (IAC + WILL + ECHO in banner) # It was sent line 86
    
    # Send Password
    s.sendall(b"password\r\n")
    
    # 2. Shell Entry Phase
    # Receive Prompt. 
    # Must include re-affirmation of WILL ECHO + WILL SGA (Line 113 fix)
    # And definitely NOT include WONT ECHO.
    
    buffer = b""
    while b">" not in buffer and b"#" not in buffer and b"$" not in buffer:
        buffer += s.recv(4096)
        
    # Check for Echo Negotiation
    # Fix ensures we send WILL ECHO (Server Echoes)
    assert IAC + WILL + ECHO in buffer
    assert IAC + WILL + SGA in buffer
    
    # Explicitly ensure we did NOT send WONT ECHO
    assert IAC + WONT + ECHO not in buffer
    
    # 3. Test Double Echo Prevention
    # Send 'a'
    s.sendall(b"a")
    time.sleep(0.2)
    resp = s.recv(1024)
    
    # Since Server Echoes, we expect 'a' in response
    assert b"a" in resp
    # Since Client is told to NOT Echo (WILL ECHO from server), 
    # Client prints this single 'a'. User sees 'a'. Correct.
    
    # 4. Test Backspace
    # Send Backspace \x7f
    s.sendall(b"\x7f")
    time.sleep(0.2)
    resp = s.recv(1024)
    
    # Expect Erase Sequence \x08 \x08
    assert b"\x08 \x08" in resp
    
    s.close()
