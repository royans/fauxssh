import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_apt import AptCommand


@pytest.fixture
def handler():
    return AptCommand(MagicMock(), MagicMock())


def test_apt_root_required(handler):
    context = {"user": "user", "source": "local"}
    output, _, metadata = handler.handle("apt update", context)
    assert "Permission denied" in output
    assert "are you root?" in output


def test_apt_help(handler):
    context = {"user": "root", "source": "local"}
    output, _, metadata = handler.handle("apt", context)
    assert "Usage: apt [options] command" in output


def test_apt_update(handler):
    context = {"user": "root", "source": "local"}
    output, _, metadata = handler.handle("apt update", context)
    assert "Hit:1" in output
    assert "Reading package lists... Done" in output


def test_apt_upgrade(handler):
    context = {"user": "root", "source": "local"}
    output, _, metadata = handler.handle("apt upgrade", context)
    assert "Calculating upgrade... Done" in output
    assert "0 not upgraded" in output


def test_apt_install(handler):
    context = {"user": "root", "source": "local"}
    output, _, metadata = handler.handle("apt install curl", context)
    assert "The following NEW packages will be installed" in output
    assert "curl" in output


def test_apt_remove(handler):
    context = {"user": "root", "source": "local"}
    output, _, metadata = handler.handle("apt remove nano", context)
    assert "The following packages will be REMOVED" in output
    assert "nano" in output
