import pytest
import json
import time
import os
import sys
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.core.event_logger import EventLogger


@pytest.fixture
def mock_logger():
    # Helper to reset singleton
    EventLogger._instance = None
    with patch("logging.getLogger") as mock_get_logger:
        mock_logger_instance = MagicMock()
        mock_get_logger.return_value = mock_logger_instance
        yield mock_logger_instance
    EventLogger._instance = None


def test_log_interaction_schema(mock_logger):
    el = EventLogger()

    el.log_interaction(
        session_id="sess-123",
        ip="1.2.3.4",
        input_cmd="curl evil.com",
        output_content="<html>malware</html>",
        protocol="ssh",
        analysis={"risk_score": 90, "summary": "Bad"},
        user_agent="Mozilla",
    )

    # Verify call
    mock_logger.info.assert_called_once()
    log_entry = mock_logger.info.call_args[0][0]

    print(f"Log Entry: {log_entry}")

    # Parse JSON
    data = json.loads(log_entry)

    # Check Top Level Envelope
    assert data["event_id"]
    assert data["ver"] == "1.0"
    assert data["timestamp"]
    assert data["session_id"] == "sess-123"
    assert data["protocol"] == "ssh"
    assert data["type"] == "interaction"

    # Check Source
    assert data["source"]["ip"] == "1.2.3.4"
    assert data["source"]["user_agent"] == "Mozilla"

    # Check Data (Polymorphic)
    assert data["data"]["input"] == "curl evil.com"
    assert data["data"]["output_head"] == "<html>malware</html>"
    # MD5 of "<html>malware</html>"
    assert data["data"]["output_md5"]
    assert data["data"]["output_size"] == 20

    # Check Analysis
    assert data["analysis"]["risk_score"] == 90


def test_log_auth_schema(mock_logger):
    el = EventLogger()

    el.log_auth(
        session_id="auth-sess",
        ip="5.6.7.8",
        username="root",
        password="password",
        success=False,
        method="password",
        client_version="SSH-2.0-Test",
        fingerprint="SHA256:abc",
    )

    mock_logger.info.assert_called_once()
    log_entry = mock_logger.info.call_args[0][0]
    data = json.loads(log_entry)

    assert data["type"] == "auth"
    assert data["source"]["client_version"] == "SSH-2.0-Test"
    assert data["source"]["fingerprint"] == "SHA256:abc"

    assert data["data"]["username"] == "root"
    assert data["data"]["success"] is False
    assert data["data"]["method"] == "password"
