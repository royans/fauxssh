
import os
import sys
import pytest
import paramiko
from unittest.mock import MagicMock, mock_open, patch

# Ensure the root directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.sftp_handler import HoneySFTPServer, HoneySFTPHandle
from paramiko import SFTP_OK, SFTP_PERMISSION_DENIED

class MockServer:
    def __init__(self):
        self.vfs = {
            '/root': ['file1.txt', 'dir1'],
            '/root/dir1': ['file2.txt']
        }
        self.cwd = '/root'
        self.username = 'root'
        self.session_id = 'test_session_reg'
        self.db = MagicMock()
        self.client_ip = '127.0.0.1'

def test_write_signature_and_seek():
    """
    Regression Test: HoneySFTPHandle.write MUST accept (offset, data).
    Previous bug: write(data) caused TypeError internally or swallowed data.
    """
    handle = HoneySFTPHandle()
    handle.max_file_size = 1024
    
    # Mock the internal file pointer
    mock_fp = MagicMock()
    mock_fp.tell.return_value = 0
    handle.upload_fp = mock_fp
    
    # Data to write
    test_data = b"hello"
    offset = 10
    
    # Call write with offset (This would fail if signature was wrong)
    try:
        result = handle.write(offset, test_data)
    except TypeError as e:
        pytest.fail(f"Handle.write signature incorrect: {e}")
        
    assert result == SFTP_OK
    
    # Verify seek and write calls
    mock_fp.seek.assert_called_with(offset)
    mock_fp.write.assert_called_with(test_data)

def test_realistic_sizes():
    """
    Regression Test: Files should have realistic, deterministic sizes, not 1234.
    """
    server = MockServer()
    sftp = HoneySFTPServer(server)
    
    # helper wrapper to expose _get_file_size logic via stat effectively
    # mocking resolve to return virtual path
    
    # 1. Check Determinism
    path1 = "/root/file1.txt"
    size1 = sftp._get_file_size(path1)
    
    assert size1 > 0
    assert size1 != 1234 # Should not be the old static default
    
    # Repeated call should be identical
    assert sftp._get_file_size(path1) == size1
    
    # Different file should be different (likely)
    path2 = "/root/dir1/file2.txt"
    size2 = sftp._get_file_size(path2)
    assert size2 > 0
    # While CRC collision is possible, highly unlikely for these two paths
    assert size1 != size2 
    
def test_upload_0_byte_prevention():
    """
    Ensures that verification logic works.
    Simulate a write flow and ensure no exceptions interfere.
    """
    handle = HoneySFTPHandle()
    handle.max_file_size = 100
    handle.upload_fp = MagicMock()
    handle.upload_fp.tell.return_value = 0
    
    # Write within limits
    assert handle.write(0, b"short") == SFTP_OK
    
    # Write exceeding limits (simulated via tell + len logic if implemented, or just check blocking)
    # Note: Current implementation uses tell() + len(data) > limit.
    # We need to mock tell()
    handle.upload_fp.tell.return_value = 90
    
    # 90 + 20 > 100 -> Should Fail
    assert handle.write(0, b"A"*20) == paramiko.SFTP_PERMISSION_DENIED

def test_chattr_supported():
    """
    Regression Test: Ensure chattr is supported (returns OK) to prevent
    'scp: remote fsetstat: Operation unsupported' errors.
    """
    server = MockServer()
    sftp = HoneySFTPServer(server)
    handle = HoneySFTPHandle()
    
    attr = paramiko.SFTPAttributes()
    attr.st_mode = 0o600
    
    # Test Server chattr
    assert sftp.chattr("/root/file1.txt", attr) == SFTP_OK
    
    # Test Handle chattr (fsetstat)
    assert handle.chattr(attr) == SFTP_OK
