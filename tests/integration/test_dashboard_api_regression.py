import pytest
import json
from ssh_honeypot.core.database import get_db_backend
from ssh_honeypot.core.background_tasks import run_stats_generation_job


@pytest.fixture
def db():
    return get_db_backend()


def test_session_details_schema(db):
    """Regression test for Session Replay API schema (id, history, user)."""
    # 1. Create a dummy session
    session_id = "test-session-123"
    db.start_session(
        session_id, "1.2.3.4", "admin", "password", "OpenSSH_8.0", protocol="ssh"
    )
    db.log_interaction(session_id, "/", "ls -la", "output here", source="ssh")

    # 2. Fetch details
    details = db.get_session_details(session_id)

    # 3. Verify exactly matching field names used in frontend
    assert details is not None
    assert "id" in details, "Backend must use 'id' field for session UUID"
    assert details["id"] == session_id
    assert "history" in details, "Backend must use 'history' field for interactions"
    assert isinstance(details["history"], list)
    assert len(details["history"]) > 0
    assert "user" in details, "Backend must use 'user' field"
    assert details["user"] == "admin"
    assert "protocol" in details


def test_infographic_stats_schema(db):
    """Regression test for main infographic data schema (kill_chain, etc)."""
    # Trigger generation to ensure data exists or at least structure is returned
    stats = db.get_infographic_stats(hours=24)

    assert "kill_chain" in stats
    if stats["kill_chain"]:
        item = stats["kill_chain"][0]
        assert "stage" in item
        assert "count" in item

    assert "top_ssh_risk" in stats
    if stats["top_ssh_risk"]:
        item = stats["top_ssh_risk"][0]
        # Verify 'session_id' exists for replay linking
        assert "session_id" in item
        assert "command" in item
        assert "risk" in item
