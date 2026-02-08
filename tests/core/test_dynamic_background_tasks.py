import pytest
import os
import json
from unittest.mock import MagicMock, patch
from datetime import datetime
from ssh_honeypot.core.background_tasks import run_stats_generation_job


@pytest.fixture
def mock_db():
    db = MagicMock()
    # Mock basic stats returns
    db.get_infographic_stats.return_value = {}
    db.get_hourly_session_counts.return_value = []
    db.get_daily_session_counts.return_value = []
    db.get_recent_high_risk_events.return_value = []
    db.get_recent_payloads.return_value = []

    # Mock connection and cursor for raw SQL execution
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value = cursor
    db._get_conn.return_value = conn

    return db, cursor


@patch("ssh_honeypot.core.background_tasks.config")
@patch("ssh_honeypot.core.background_tasks.log")
@patch("ssh_honeypot.core.utils.PROJECT_ROOT", "/tmp")
def test_dynamic_protocol_stats(mock_log, mock_config, mock_db):
    """
    Verifies that run_stats_generation_job dynamically picks up protocols
    from the database and generates risk stats for them.
    """
    db, cursor = mock_db

    # Enable stats job
    mock_config.get.side_effect = lambda section, key: (
        True if key == "showstats" else None
    )

    # Mock distinct protocols return
    # We include 'imap' and a custom 'alien_proto' to prove dynamic nature
    cursor.fetchall.side_effect = [
        [("ssh",), ("telnet",), ("imap",), ("alien_proto",)],  # DISTINCT protocol
        [
            (("ssh", 10), ("telnet", 5), ("imap", 2), ("alien_proto", 1))
        ],  # Interaction Counts
    ]

    # Run the job
    run_stats_generation_job(db)

    # Verify DB calls for risk stats
    # 1. Check that get_recent_top_commands_by_risk was called for EACH protocol found
    db.get_recent_top_commands_by_risk.assert_any_call("ssh", limit=15)
    db.get_recent_top_commands_by_risk.assert_any_call("imap", limit=15)
    db.get_recent_top_commands_by_risk.assert_any_call("alien_proto", limit=15)

    # Verify file output
    output_path = "/tmp/data/status_data.json"
    assert os.path.exists(output_path)

    with open(output_path, "r") as f:
        data = json.load(f)

    # Verify keys exist in JSON
    assert "top_ssh_risk" in data
    assert "top_imap_risk" in data
    assert "top_alien_proto_risk" in data

    # Cleanup
    if os.path.exists(output_path):
        os.remove(output_path)
