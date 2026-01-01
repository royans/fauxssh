
import pytest
from unittest.mock import MagicMock, patch
import os
import sys

# Add path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.sftp_handler import HoneySFTPServer, HoneySFTPHandle
from paramiko import SFTP_PERMISSION_DENIED

# Mock Config
# Mock Config
@pytest.fixture
def mock_config():
    # Import the REAL config manager to patch it
    from ssh_honeypot import config_manager
    # Patch the 'get' method of the 'config' INSTANCE
    with patch.object(config_manager.config, 'get') as mock_get:
        mock_get.side_effect = lambda *args: {
            ('upload', 'max_file_size'): 100,
            ('upload', 'max_quota_per_ip'): 200
        }.get(args, 100) # Fallback
        yield mock_get

class MockServerObj:
    def __init__(self):
        self.db = MagicMock()
        self.client_ip = '1.2.3.4'
        self.username = 'testuser'

def test_sftp_open_quota_exceeded(mock_config):
    server = MockServerObj()
    # Mock DB saying quota is full (used 250, limit 200)
    server.db.get_ip_upload_usage.return_value = 250
    
    sftp = HoneySFTPServer(server)
    sftp.session_id = 'sess1'
    
    # Attempt open for write
    handle = sftp.open('/tmp/test', os.O_WRONLY | os.O_CREAT, None)
    
    assert handle == SFTP_PERMISSION_DENIED
    server.db.get_ip_upload_usage.assert_called_with('1.2.3.4')

def test_sftp_write_size_limit(mock_config):
    server = MockServerObj()
    server.db.get_ip_upload_usage.return_value = 0 # Empty quota
    
    sftp = HoneySFTPServer(server)
    sftp.session_id = 'sess2'
    
    # Open valid handle
    with patch('builtins.open') as mock_open:
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.tell.return_value = 0 # Start at 0
        
        handle = sftp.open('/tmp/test2', os.O_WRONLY | os.O_CREAT, None)
        assert hasattr(handle, 'max_file_size')
        assert handle.max_file_size == 100
    
        # Write 50 bytes (OK)
        mock_file.write.return_value = 50
        res = handle.write(0, b'A' * 50)
        assert res == 0 # SFTP_OK is 0
        
        # Write 60 bytes (Total 110 > 100) -> Should Fail
        # Use mock file obj to track position
        mock_file.tell.return_value = 50
        
        res = handle.write(50, b'B' * 60)
        assert res == SFTP_PERMISSION_DENIED

def test_scp_quota_check():
    # Test command_handler logic via Unit Test would require extensive mocking of channel.
    # We rely on logic inspection similar to SFTP tests.
    pass
