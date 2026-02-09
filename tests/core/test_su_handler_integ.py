import sys
import os
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from unittest.mock import MagicMock, patch, ANY
from ssh_honeypot.core.command_handler import CommandHandler


@pytest.fixture
def mock_deps():
    llm = MagicMock()
    db = MagicMock()
    return llm, db


@pytest.fixture
def handler(mock_deps):
    llm, db = mock_deps
    return CommandHandler(llm, db)


def test_su_unix_local_handler(handler):
    """Verify su uses local handler on Unix persona"""
    context = {
        "user": "root",
        "cwd": "/root",
        "client_ip": "1.2.3.4",
        "persona_config": {"system": {"handler_type": "unix"}},
    }

    out, updates, meta = handler.process_command("su", context)

    assert "Authentication failure" in out
    assert meta["source"] == "handler"


def test_su_cisco_fallback_and_cache_cleaning(handler):
    """Verify su falls back to LLM on Cisco and cleans bad cache"""
    context = {
        "user": "root",
        "cwd": "/",
        "client_ip": "1.2.3.4",
        "session_id": "test_sess",
        "persona_config": {"system": {"handler_type": "cisco_ios"}},
    }

    # Mock Universal Cache to return tainted data FIRST
    with patch("ssh_honeypot.core.command_handler.universal_cache") as mock_cache:
        # Scenario: Cache has "System resources exhausted"
        mock_cache.get.return_value = {
            "output_text": "Error: System resources exhausted. Please try again later."
        }

        # Mock LLM to return valid response after cache miss (caused by invalidation)
        handler.llm.generate_response.return_value = "% Password: "

        out, updates, meta = handler.process_command("su", context)

        # Expectation:
        # 1. Cache HIT but detected as tainted -> Cache DELETE called
        # 2. Falls through to LLM -> LLM returns "% Password: "

        mock_cache.delete.assert_called_with("ssh_command", ANY)
        assert "% Password: " in out
        assert meta["source"] == "llm"


def test_su_cisco_fallback_valid_cache(handler):
    """Verify su uses valid cache on Cisco"""
    context = {
        "user": "root",
        "cwd": "/",
        "client_ip": "1.2.3.4",
        "session_id": "test_sess",
        "persona_config": {"system": {"handler_type": "cisco_ios"}},
    }

    with patch("ssh_honeypot.core.command_handler.universal_cache") as mock_cache:
        mock_cache.get.return_value = {"output_text": "% Password: "}

        out, updates, meta = handler.process_command("su", context)

        assert "% Password: " in out
        assert meta["source"] == "llm-cache"
        assert meta["cached"] is True


def test_unix_command_on_cisco_persona(handler):
    """Verify Unix commands work on Cisco persona (Telnet)"""
    context = {
        "user": "root",
        "cwd": "/",
        "client_ip": "1.2.3.4",
        "session_id": "test_sess",
        "persona_config": {"system": {"handler_type": "cisco_ios"}},
    }

    # We need to mock a unix handler, e.g., handle_id or handle_uname
    # But since we are using the real CommandHandler class (with mocked dependencies),
    # the real handle_id or handle_uname should be present if imported.
    # However, CommandHandler imports handlers dynamically or in __init__.
    # Let's check if handle_id is available on the handler instance.

    # Check if handle_id exists, if not mock it for this test to ensure dispatch works
    if not hasattr(handler, "handle_id"):
        handler.handle_id = MagicMock(
            return_value=("uid=0(root)", {}, {"source": "handler", "cached": False})
        )
    else:
        # If it exists (it should), we can let it run or mock it to ensure we hit IT and not LLM
        handler.handle_id = MagicMock(
            return_value=("uid=0(root)", {}, {"source": "handler", "cached": False})
        )

    out, updates, meta = handler.process_command("id", context)

    assert "uid=0(root)" in out
    assert meta["source"] == "handler"
    # Ensure it wasn't the LLM
    handler.llm.generate_response.assert_not_called()
