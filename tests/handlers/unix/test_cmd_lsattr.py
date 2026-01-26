import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_lsattr import LsattrCommand


@pytest.fixture
def handler():
    db = MagicMock()
    llm = MagicMock()
    return LsattrCommand(db, llm)


def test_lsattr_basic_file(handler):
    context = {"cwd": "/", "client_ip": "1.2.3.4", "user": "root"}
    handler.db.get_user_node.return_value = {"path": "/etc/passwd", "type": "file"}

    output, _, _ = handler.handle("lsattr /etc/passwd", context)
    assert "--------------e------- /etc/passwd" in output


def test_lsattr_missing_file(handler):
    context = {"cwd": "/", "client_ip": "1.2.3.4", "user": "root"}
    handler.db.get_user_node.return_value = None
    handler.db.get_fs_node.return_value = None

    output, _, _ = handler.handle("lsattr fakefile", context)
    assert "lsattr: No such file or directory while trying to stat fakefile" in output


def test_lsattr_directory_listing(handler):
    context = {"cwd": "/tmp", "client_ip": "1.2.3.4", "user": "root"}
    handler.db.get_user_node.return_value = {"path": "/tmp", "type": "directory"}
    handler.db.list_user_dir.return_value = [
        {"path": "/tmp/f1", "type": "file"},
        {"path": "/tmp/f2", "type": "file"},
    ]

    output, _, _ = handler.handle("lsattr", context)
    assert "--------------e------- /tmp/f1" in output
    assert "--------------e------- /tmp/f2" in output


def test_lsattr_directory_itself(handler):
    context = {"cwd": "/", "client_ip": "1.2.3.4", "user": "root"}
    handler.db.get_user_node.return_value = {"path": "/tmp", "type": "directory"}

    output, _, _ = handler.handle("lsattr -d /tmp", context)
    assert "--------------e------- /tmp" in output
    # Should NOT list children
    assert "f1" not in output
