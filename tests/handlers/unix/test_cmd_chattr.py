import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_chattr import ChattrCommand


@pytest.fixture
def handler():
    db = MagicMock()
    llm = MagicMock()
    return ChattrCommand(db, llm)


def test_chattr_no_args(handler):
    context = {"user": "root", "cwd": "/"}
    output, _, _ = handler.handle("chattr", context)
    assert "Usage:" in output


def test_chattr_help(handler):
    context = {"user": "root", "cwd": "/"}
    output, _, _ = handler.handle("chattr --help", context)
    assert "Usage:" in output


def test_chattr_missing_file(handler):
    context = {"user": "root", "cwd": "/"}
    handler.db.get_user_node.return_value = None
    handler.db.get_fs_node.return_value = None

    output, _, _ = handler.handle("chattr +i ghost.txt", context)
    assert "chattr: No such file or directory while trying to stat ghost.txt" in output


def test_chattr_success_user_node(handler):
    context = {"user": "root", "cwd": "/", "client_ip": "1.2.3.4"}
    handler.db.get_user_node.return_value = {"path": "/real.txt", "type": "file"}

    output, _, _ = handler.handle("chattr +i real.txt", context)
    assert output == ""
    # Verify DB was checked with correct params
    handler.db.get_user_node.assert_called_once()


def test_chattr_success_fs_node(handler):
    context = {"user": "root", "cwd": "/", "client_ip": "1.2.3.4"}
    handler.db.get_user_node.return_value = None
    handler.db.get_fs_node.return_value = {"path": "/etc/passwd", "type": "file"}

    output, _, _ = handler.handle("chattr +i /etc/passwd", context)
    assert output == ""
    handler.db.get_fs_node.assert_called_once()


def test_chattr_multiple_files_part_fail(handler):
    context = {"user": "root", "cwd": "/", "client_ip": "1.2.3.4"}
    # First file exists, second doesn't
    handler.db.get_user_node.side_effect = [
        {"path": "/f1", "type": "file"},
        None,
    ]
    handler.db.get_fs_node.return_value = None

    output, _, _ = handler.handle("chattr +i f1 f2", context)
    assert "chattr: No such file or directory while trying to stat f2" in output
    assert "f1" not in output
