import pytest
import sys
import os

# Add parent path to find modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from ssh_honeypot.handlers import network_handlers

def test_ifconfig_flags():
    # Test -a (should return full)
    full = network_handlers.handle_ifconfig(['-a'])
    assert "eth0" in full
    assert "lo" in full
    assert "RX packets" in full
    
    # Test eth0 specific
    eth0 = network_handlers.handle_ifconfig(['eth0'])
    assert "eth0" in eth0
    assert "lo" not in eth0
    assert "RX packets" in eth0
    
    # Test invalid interface
    err = network_handlers.handle_ifconfig(['wlan0'])
    assert "error fetching interface information" in err

def test_netstat_flags():
    # Test Route (-r)
    r = network_handlers.handle_netstat(['-r'])
    assert "Kernel IP routing table" in r
    assert "Gateway" in r
    
    # Test Listening (-l)
    l = network_handlers.handle_netstat(['-l'])
    assert "LISTEN" in l
    assert "ESTABLISHED" not in l
    
    # Test Established (implied or -a or explicit logic check)
    # Our impl: default shows ESTABLISHED if -l not present.
    # -a shows both.
    
    # Default (no flags) -> Established?
    # Actually logic says: show_established = 'l' not in flags or 'a' in flags
    # So default (no 'l') shows established.
    d = network_handlers.handle_netstat([])
    assert "ESTABLISHED" in d
    assert "LISTEN" not in d # show_listening = 'l' in flags or 'a' in flags
    
    # All (-a) -> Both
    a = network_handlers.handle_netstat(['-a'])
    assert "ESTABLISHED" in a
    assert "LISTEN" in a
