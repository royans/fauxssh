import pytest
from ssh_honeypot.core.command_handler import CommandHandler
from unittest.mock import MagicMock


def test_exit_command_single():
    """
    Test that 'exit' correctly signals termination in CommandHandler.
    Currently, this will likely fall through to LLM and not return 'terminate': True.
    """
    db = MagicMock()
    llm = MagicMock()
    # Mock LLM response for fallback
    llm.generate_response.return_value = "bash: exit: command not found"

    handler = CommandHandler(llm, db)
    context = {"user": "royans", "cwd": "/home/royans", "protocol": "ssh"}

    resp, updates, meta = handler.process_command("exit", context)

    # Expectation for elegant exit:
    # 1. terminate signal in updates
    # 2. logout/exit message (optional but good)
    assert updates.get("terminate") is True


def test_exit_command_chain():
    """
    Test that 'ls; exit' correctly signals termination.
    """
    db = MagicMock()
    llm = MagicMock()
    llm.generate_response.return_value = "file1  file2"

    handler = CommandHandler(llm, db)
    context = {"user": "royans", "cwd": "/home/royans", "protocol": "ssh"}

    resp, updates, meta = handler.process_command("ls; exit", context)

    assert updates.get("terminate") is True
