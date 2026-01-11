import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_rmdir import RmdirCommand


@pytest.fixture
def mock_db():
    db = MagicMock()
    return db


@pytest.fixture
def handler(mock_db):
    return RmdirCommand(mock_db, MagicMock())


def test_rmdir_success(mock_db, handler):
    path = "/home/user/empty_dir"
    context = {"cwd": "/home/user", "client_ip": "1.2.3.4", "user": "user"}

    # Setup: Dir exists and is empty
    mock_db.get_user_node.return_value = {"type": "dir", "path": path}
    mock_db.list_user_dir.return_value = []  # Empty

    # RmdirCommand gets db from self.db, so it uses the mock_db passed in init
    resp, updates, _ = handler.handle("rmdir empty_dir", context)

    assert resp == ""
    assert updates["file_modifications"][0]["action"] == "delete"
    assert updates["file_modifications"][0]["path"] == path
    mock_db.delete_user_file.assert_called_with("1.2.3.4", "user", path)


def test_rmdir_not_empty(mock_db, handler):
    path = "/home/user/full_dir"
    context = {"cwd": "/home/user", "client_ip": "1.2.3.4", "user": "user"}

    # Setup: Dir exists and has files
    mock_db.get_user_node.return_value = {"type": "dir", "path": path}
    mock_db.list_user_dir.return_value = [{"path": "file.txt"}]

    resp, _, _ = handler.handle("rmdir full_dir", context)

    assert "Directory not empty" in resp
    mock_db.delete_user_file.assert_not_called()


def test_rmdir_not_dir(mock_db, handler):
    path = "/home/user/file.txt"
    context = {"cwd": "/home/user", "client_ip": "1.2.3.4", "user": "user"}

    # Setup: Is a file
    mock_db.get_user_node.return_value = {"type": "file", "path": path}

    resp, _, _ = handler.handle("rmdir file.txt", context)

    assert "Not a directory" in resp
    mock_db.delete_user_file.assert_not_called()


def test_rmdir_missing(mock_db, handler):
    context = {"cwd": "/home/user", "client_ip": "1.2.3.4", "user": "user"}
    mock_db.get_user_node.return_value = None

    resp, _, _ = handler.handle("rmdir ghost", context)

    assert "No such file" in resp


def test_rmdir_permission(mock_db, handler):
    # Try deleting /etc/something (not enabled by default logic)
    # The default logic in cmd_rmdir allows /tmp, /home, /root only
    context = {"cwd": "/"}

    resp, _, _ = handler.handle("rmdir /var/log", context)

    assert "Permission denied" in resp
