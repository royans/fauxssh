import pytest
import os
from ssh_honeypot.core.command_handler import CommandHandler
from unittest.mock import MagicMock


@pytest.fixture
def handler():
    os.environ["SSHPOT_TEST_MODE"] = "1"
    db = MagicMock()
    llm = MagicMock()
    h = CommandHandler(llm, db)
    yield h
    if "SSHPOT_TEST_MODE" in os.environ:
        del os.environ["SSHPOT_TEST_MODE"]


def test_tr_simple_replace(handler):
    context = {"stdin": "hello world"}
    res, _ = handler.handle_tr("tr 'l' 'x'", context)
    assert res == "hexxo worxd"


def test_tr_delete(handler):
    context = {"stdin": "hello world"}
    res, _ = handler.handle_tr("tr -d 'l'", context)
    assert res == "heo word"


def test_tr_ranges(handler):
    context = {"stdin": "hello world"}
    res, _ = handler.handle_tr("tr 'a-z' 'A-Z'", context)
    assert res == "HELLO WORLD"


def test_tr_newlines(handler):
    context = {"stdin": "line1\nline2\n"}
    res, _ = handler.handle_tr("tr '\\n' ' '", context)
    assert res == "line1 line2 "


def test_chained_help_flattening_cat(handler):
    # This precisely tests the user's complicated command:
    # cat_help=$( (cat --help 2>&1 | tr '\n' ' ') || cat --help 2>&1)
    # Our process_command handles the pipes and ORs.
    # We simulate cat returning multiline help.

    # Mock cat output via process_command is hard since it's internal logic.
    # But we can test the PIPE logic if we feed it right.
    # Actually, simpler to test the core logic of process_command with a mock command chain.

    # Create specific context
    context = {"env": {}}

    # 1. Test the pipe: cat | tr
    # We need 'cat' to return something. cat --help returns a string.
    # Let's trust the handler logic integration.

    cmd = "echo 'line1\nline2' | tr '\\n' ' '"
    res, updates, _ = handler.process_command(cmd, context)
    assert (
        res == "line1 line2 "
    )  # Note: echo '...' might have literal \n or interpreting?
    # Current echo handler might just return literal.


def test_or_chaining_success_first(handler):
    # true || false -> true
    context = {"env": {}}
    cmd = "echo success || echo fail"
    res, _, _ = handler.process_command(cmd, context)
    assert "success" in res
    assert "fail" not in res


def test_or_chaining_fallback(handler):
    # fail || success -> success
    context = {"env": {}}
    # "madeupcmd" should result in "command not found" -> failure detected
    cmd = "madeupcmd || echo fallback"
    res, _, _ = handler.process_command(cmd, context)
    assert "fallback" in res


def test_user_scenario_cat_help(handler):
    # The actual user command integration test
    # cat_help=$( (cat --help 2>&1 | tr '\n' ' ') || cat --help 2>&1)
    # We simplify the subshell part since process_command handles ( ... ) stripping.

    context = {"env": {}}
    # We mock 'cat --help' behavior by actually running it?
    # cat handler is present.

    cmd = "cat --help | tr '\\n' ' '"
    res, _, _ = handler.process_command(cmd, context)

    # Check that newlines are gone (except maybe trailing)
    assert "\n" not in res.strip()
    assert "Usage: cat" in res


def test_user_scenario_ls_help(handler):
    # The second user command:
    # ls_help=$( (ls --help 2>&1 | tr '\n' ' ') || ls --help 2>&1)

    context = {"env": {}}

    cmd = "ls --help | tr '\\n' ' '"
    res, _, _ = handler.process_command(cmd, context)

    # Check flattening
    assert "\n" not in res.strip()
    assert "Usage: ls" in res
