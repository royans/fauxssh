import pytest
import os
import asyncio
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.imap.session import ImapSession
from ssh_honeypot.core.database import HoneyDB


@pytest.mark.asyncio
async def test_imap_persona_loading():
    """Verifies that ImapSession correctly loads emails from persona YAML."""
    transport = MagicMock()
    transport.get_extra_info.return_value = ("1.2.3.4", 12345)

    db_mock = MagicMock(spec=HoneyDB)
    # Mock mailbox creation/lookup
    db_mock.get_email_mailbox.return_value = {
        "id": 1,
        "uid_validity": 123,
        "uid_next": 1,
    }
    db_mock.get_email_messages.return_value = []  # Empty initially

    llm_mock = MagicMock()

    session = ImapSession(transport, db_mock, llm_mock)
    session.user = "testuser"
    session.identity_user = "testuser"

    # We need to ensure personas/CentOS7_Legacy_Compute/imap/inbox.yaml exists
    # and is loaded. Since we are in the repo, it should be there.

    with patch("ssh_honeypot.services.imap.session.config") as mock_config:
        mock_config.get.side_effect = lambda *args: (
            "CentOS7_Legacy_Compute"
            if args[0] == "persona" and args[1] == "name"
            else None
        )

        session._generate_initial_emails()

    # Verify add_email_message was called with persona data
    # In our inbox.yaml, we have 3 emails.
    assert db_mock.add_email_message.call_count >= 3

    # Check one of the calls
    args, kwargs = db_mock.add_email_message.call_args_list[0]
    # args: (ip, user, mailbox_id, id, date, flags, size, headers, body, template, attachment)
    assert "System Maintenance" in args[7]  # Headers
    assert "kernel update" in args[8]  # Body


@pytest.mark.asyncio
async def test_imap_fallback_emails():
    """Verifies that ImapSession falls back to defaults if persona data is missing."""
    transport = MagicMock()
    transport.get_extra_info.return_value = ("1.2.3.4", 12345)
    db_mock = MagicMock(spec=HoneyDB)
    db_mock.get_email_mailbox.return_value = {
        "id": 1,
        "uid_validity": 123,
        "uid_next": 1,
    }
    db_mock.get_email_messages.return_value = []
    llm_mock = MagicMock()

    session = ImapSession(transport, db_mock, llm_mock)
    session.user = "testuser"
    session.identity_user = "testuser"

    with patch("ssh_honeypot.services.imap.session.config") as mock_config:
        # Mock non-existent persona
        mock_config.get.return_value = "NonExistentPersona"
        session._generate_initial_emails()

    # Should fall back to default welcome email (1 call)
    assert db_mock.add_email_message.call_count == 1
    args, _ = db_mock.add_email_message.call_args
    assert "Welcome" in args[7]
