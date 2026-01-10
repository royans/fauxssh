import socket
import time
import threading
import pytest
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.telnet.server import start_telnet_server

PORT = 2331 # Different port to avoid conflict

class MockDB:
    def log_auth_event(self, *args, **kwargs): pass
    def validate_anti_harvesting(self, ip, username, password): return True, None
    def start_session(self, *args, **kwargs): pass
    def list_user_dir(self, *args, **kwargs): return []
    def log_interaction(self, *args, **kwargs): pass
    def get_persona_by_name(self, name): return {}
    def get_cached_response(self, *args, **kwargs): return None
    def cache_response(self, *args, **kwargs): pass

class MockLLM:
    def generate_response(self, *args, **kwargs): return "Mock LLM Response"

@pytest.fixture
def cisco_config_patch():
    # Mock config to return Cisco IOS persona data
    persona_data = {
        'system': {'hostname': 'Switch', 'handler_type': 'cisco_ios'},
        'network': {'ssh_banner': 'User Access Verification'}
    }
    
    with patch('ssh_honeypot.services.telnet.server.config') as mock_conf:
        # Mock get_persona_by_name to return our dict
        mock_conf.get_persona_by_name.return_value = persona_data
        # Also mock get('server', 'hostname') just in case
        mock_conf.get.side_effect = lambda section, key: "Switch" if key == "hostname" else None
        yield mock_conf

def test_cisco_banner_behavior(cisco_config_patch):
    db = MockDB()
    llm = MockLLM()
    
    # Start server
    t = threading.Thread(target=start_telnet_server, args=(PORT, db, llm), daemon=True)
    t.start()
    time.sleep(1) 
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(('127.0.0.1', PORT))
        
        # 1. Read Pre-Login Banner (Should be "User Access Verification")
        # Logic: banner starts immediately
        chunk1 = s.recv(4096)
        
        # Handle simple negotiation loop if server sends IACs
        # Server sends banner, THEN IACs.
        assert b"User Access Verification" in chunk1
        assert b"Debian" not in chunk1
        
        # 2. Perform Login
        # Send Username
        if b"Username:" not in chunk1:
             # Wait for it
             chunk1 += s.recv(4096)
        
        s.sendall(b"admin\r\n")
        time.sleep(0.2)
        
        # Send Password
        s.recv(4096) # Consume "Password: "
        s.sendall(b"cisco\r\n")
        time.sleep(0.5)
        
        # 3. Read Post-Login Output (The Bug Spot)
        # Should contain prompt "Switch>"
        # Should NOT contain "Debian GNU/Linux"
        
        # We might need to read a few times
        output = b""
        start = time.time()
        while time.time() - start < 2.0:
            try:
                data = s.recv(4096)
                if not data: break
                output += data
                if b">" in output: break
            except: break
            
        
        assert b"Switch>" in output
        assert b"Debian GNU/Linux" not in output
        assert b"The programs included with" not in output
        
        # 4. Test ENABLE command (Crash Reproduction)
        s.sendall(b"enable\r\n")
        
        # Expect prompt to change to Switch#
        # If it crashes, we'll get "% Error..."
        output = b""
        start = time.time()
        while time.time() - start < 2.0:
            try:
                data = s.recv(4096)
                if not data: break
                output += data
                if b"#" in output or b"Error" in output: break
            except: break
            
        if b"Error" in output:
             pytest.fail(f"Enable command failed with error: {output}")
             
        assert b"Switch#" in output
        
    finally:
        s.close()
