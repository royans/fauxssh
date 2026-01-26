import os
import pytest
from unittest.mock import patch
from ssh_honeypot.core import utils


@pytest.fixture
def mock_paths():
    """Matches the paths we want to mock in utils.py"""
    fake_data_dir = "/app/data"
    fake_project_root = "/app/sshpot"
    fake_home = "/home/testuser"

    with (
        patch("ssh_honeypot.core.utils.get_data_dir", return_value=fake_data_dir),
        patch("ssh_honeypot.core.utils.PROJECT_ROOT", fake_project_root),
        patch("os.path.expanduser", return_value=fake_home),
    ):
        yield fake_data_dir, fake_project_root, fake_home


def test_sanitize_path_no_leak(mock_paths):
    """Test that safe paths are untouched."""
    fake_data_dir, fake_root, fake_home = mock_paths

    safe_path = "/var/log/syslog"
    assert utils.sanitize_path(safe_path) == safe_path

    safe_msg = "Hello World"
    assert utils.sanitize_path(safe_msg) == safe_msg

    # Short path should not trigger home masking if configured loosely
    # But current implementation checks > 5 chars on home dir
    assert utils.sanitize_path("/tmp") == "/tmp"


def test_sanitize_path_data_dir(mock_paths):
    """Test masking of data directory."""
    fake_data_dir, _, _ = mock_paths

    leak_path = f"{fake_data_dir}/uploads/malware.exe"
    sanitized = utils.sanitize_path(leak_path)
    assert "<DATA_DIR>" in sanitized
    assert "/app/data" not in sanitized
    assert sanitized == "<DATA_DIR>/uploads/malware.exe"


def test_sanitize_path_project_root(mock_paths):
    """Test masking of project root."""
    _, fake_root, _ = mock_paths

    leak_path = f"{fake_root}/core/config.py"
    sanitized = utils.sanitize_path(leak_path)
    assert "<ROOT>" in sanitized
    assert "/app/sshpot" not in sanitized
    assert sanitized == "<ROOT>/core/config.py"


def test_sanitize_path_home_dir(mock_paths):
    """Test masking of home directory."""
    _, _, fake_home = mock_paths

    leak_path = f"{fake_home}/.ssh/id_rsa"
    sanitized = utils.sanitize_path(leak_path)
    assert "<HOME>" in sanitized
    assert "/home/testuser" not in sanitized
    assert sanitized == "<HOME>/.ssh/id_rsa"


def test_sanitize_obj_recursion(mock_paths):
    """Test recursive sanitization of objects."""
    fake_data_dir, _, _ = mock_paths

    leak_struct = {
        "params": ["normal", f"{fake_data_dir}/file.txt"],
        "meta": {"path": f"{fake_data_dir}/other.log"},
    }

    sanitized = utils.sanitize_obj(leak_struct)

    assert sanitized["params"][0] == "normal"
    assert sanitized["params"][1] == "<DATA_DIR>/file.txt"
    assert sanitized["meta"]["path"] == "<DATA_DIR>/other.log"


def test_sanitize_none_safe():
    """Ensure None or non-strings are handled safely."""
    assert utils.sanitize_path(None) is None
    assert utils.sanitize_path(123) == 123
