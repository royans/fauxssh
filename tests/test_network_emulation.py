import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.network import NetworkPersona, network_persona
from ssh_honeypot.handlers import network_handlers

class TestNetworkEmulation(unittest.TestCase):
    def test_singleton(self):
        """Verify we have a global singleton"""
        self.assertIsInstance(network_persona, NetworkPersona)

    def test_ip_addr_output(self):
        """Verify ip addr format"""
        output = network_persona.get_ip_addr_output()
        self.assertIn("eth0", output)
        self.assertIn("172.16.20.5/24", output)
        self.assertIn("UP,LOWER_UP", output)
        self.assertIn("link/ether", output)

    def test_ip_route_output(self):
        """Verify ip route format"""
        output = network_persona.get_ip_route_output()
        self.assertIn("default via 172.16.20.1", output)
        self.assertIn("172.16.20.5", output)

    def test_ifconfig_output(self):
        """Verify ifconfig format"""
        output = network_persona.get_ifconfig_output()
        self.assertIn("eth0: flags", output)
        self.assertIn("inet 172.16.20.5", output)
        self.assertIn("netmask 255.255.255.0", output)
        self.assertIn("MiB", output)
        
    @patch('time.sleep', return_value=None) # Don't actually sleep
    def test_ping_handler_localhost(self, mock_sleep):
        """Verify ping output format for localhost"""
        args = ['localhost', '-c', '2']
        output = network_handlers.handle_ping(args)
        
        self.assertIn("PING localhost (127.0.0.1)", output)
        self.assertIn("icmp_seq=1", output)
        self.assertIn("icmp_seq=2", output)
        self.assertIn("2 packets transmitted, 2 received", output)
        self.assertIn("0% packet loss", output)
        
    @patch('time.sleep', return_value=None)
    def test_ping_handler_external(self, mock_sleep):
        """Verify ping output format for external domain"""
        args = ['google.com', '-c', '1']
        output = network_handlers.handle_ping(args)
        
        self.assertIn("PING google.com", output)
        # Should resolve to fake IP
        self.assertIn("PING google.com", output)
        # Should resolve to fake IP
        self.assertIn("bytes from 142.250.", output) 
        self.assertIn("icmp_seq=1", output)

    def test_handle_netstat(self):
        """Verify netstat shows client IP"""
        client_ip = "203.0.113.55"
        output = network_handlers.handle_netstat([], client_ip)
        
        self.assertIn("Active Internet connections", output)
        self.assertIn("0.0.0.0:22", output) # Listen
        self.assertIn(f"{client_ip}:", output) # Established connection
        self.assertIn("ESTABLISHED", output)

    def test_handle_ss(self):
        """Verify ss shows client IP"""
        client_ip = "198.51.100.2"
        output = network_handlers.handle_ss([], client_ip)
        
        self.assertIn("State", output)
        self.assertIn("Recv-Q", output)
        self.assertIn(f"{client_ip}:", output)

if __name__ == '__main__':
    unittest.main()
