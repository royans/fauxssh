import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_useradd import UseraddCommand

@pytest.fixture
def handler():
    return UseraddCommand(MagicMock(), MagicMock())

def test_useradd_root_required(handler):
    context = {'user': 'user', 'source': 'local'}
    output, _, metadata = handler.handle("useradd test", context)
    assert "Permission denied" in output

def test_useradd_usage(handler):
    context = {'user': 'root', 'source': 'local'}
    output, _, metadata = handler.handle("useradd", context)
    assert "Usage: useradd" in output

def test_useradd_basic_success(handler):
    context = {'user': 'root', 'source': 'local'}
    output, _, metadata = handler.handle("useradd newuser", context)
    assert output == ""  # Silent success

def test_useradd_help(handler):
    context = {'user': 'root', 'source': 'local'}
    output, _, metadata = handler.handle("useradd --help", context)
    # My impl: returns Usage if it thinks args are bad.
    # useradd --help -> parts=['useradd', '--help']. username='--help'. 
    # if username.startswith('-'): return Usage...
    assert "Usage: useradd" in output
