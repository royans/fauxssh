import os
import sys
import pytest
from unittest.mock import MagicMock

# Ensure the root directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.sftp_handler import HoneySFTPServer
from paramiko import SFTPAttributes, SFTP_OK, SFTP_NO_SUCH_FILE

class MockServer:
    def __init__(self):
        self.vfs = {
            '/root': ['file1.txt', 'dir1'],
            '/root/dir1': ['file2.txt']
        }
        self.cwd = '/root'
        self.username = 'root'
        self.session_id = 'test_session'
        self.db = MagicMock()

def test_sftp_list_folder():
    server = MockServer()
    sftp = HoneySFTPServer(server)
    
    # Test Listing Root
    items = sftp.list_folder('.')
    assert len(items) == 2
    filenames = [i.filename for i in items]
    assert 'file1.txt' in filenames
    assert 'dir1' in filenames
    
    # Test attributes
    for i in items:
        if i.filename == 'dir1':
            assert i.st_mode & 0o40000 # Directory
        else:
            assert i.st_mode & 0o100000 # File (regular)

def test_sftp_resolve():
    server = MockServer()
    sftp = HoneySFTPServer(server)
    
    assert sftp._resolve('.') == '/root'
    assert sftp._resolve('dir1') == '/root/dir1'
    assert sftp._resolve('/tmp') == '/tmp'

def test_sftp_mkdir_rmdir():
    server = MockServer()
    sftp = HoneySFTPServer(server)
    
    # Mkdir
    assert sftp.mkdir('newdir', None) == SFTP_OK
    assert '/root/newdir' in server.vfs
    
    # Rmdir
    assert sftp.rmdir('newdir') == SFTP_OK
    assert '/root/newdir' not in server.vfs

def test_sftp_list_missing():
    server = MockServer()
    sftp = HoneySFTPServer(server)
    
    assert sftp.list_folder('/missing') == SFTP_NO_SUCH_FILE
