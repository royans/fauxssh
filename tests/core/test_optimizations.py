import pytest
import json
import time
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.command_handler import CommandHandler
from ssh_honeypot.core.fs_seeder import get_skeleton_data
from ssh_honeypot.core.llm import LLMInterface


def test_skeleton_ssh_presence():
    """Verify that .ssh and authorized_keys are present in the global skeleton."""
    nodes = get_skeleton_data()
    dot_ssh = [n for n in nodes if n["path"] == "~/.ssh"]
    auth_keys = [n for n in nodes if n["path"] == "~/.ssh/authorized_keys"]

    assert len(dot_ssh) > 0, ".ssh directory missing from skeleton"
    assert len(auth_keys) > 0, "authorized_keys file missing from skeleton"
    assert dot_ssh[0]["type"] == "dir"
    assert auth_keys[0]["type"] == "file"


def test_command_timing_metadata():
    """Verify that duration_ms is correctly captured and returned by CommandHandler."""
    mock_db = MagicMock()
    mock_llm = MagicMock()
    handler = CommandHandler(mock_llm, mock_db)

    # Mock the implementation to take some time
    def slow_impl(*args, **kwargs):
        time.sleep(0.01)  # 10ms
        return "out", {}, {"source": "test"}

    with patch.object(handler, "_process_command_impl", side_effect=slow_impl):
        _, _, metadata = handler.process_command("ls")
        assert "duration_ms" in metadata
        assert metadata["duration_ms"] >= 10


def test_free_analysis_extraction():
    """Verify that 'free' analysis is extracted from bundled JSON and avoids redundant calls."""
    llm = LLMInterface()
    llm.provider = "google"

    bundled_text = json.dumps(
        {
            "output": "hello world",
            "analysis": {
                "risk": 42,
                "type": "Discovery",
                "stage": "Recon",
                "explanation": "Bundled analysis test",
            },
        }
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": bundled_text}]}}]
    }

    with patch.object(llm, "analyze_command") as mock_analyze:
        # This will call _handle_provider_response
        with patch.object(llm, "_call_api", return_value=(bundled_text, "llm")):
            # We want to test the logic inside _handle_provider_response which is called by specific providers
            # Let's simulate the provider call
            final_text = llm._handle_provider_response(
                mock_resp, "google", "somehash", command="ls", is_command=True
            )

            assert "hello world" in final_text
            # analyze_command should NOT have been called because we found 'analysis' in the JSON
            mock_analyze.assert_not_called()


def test_cd_tilde_expansion():
    """Verify that handle_cd correctly expands ~ based on the user context."""
    mock_db = MagicMock()
    mock_llm = MagicMock()
    handler = CommandHandler(mock_llm, mock_db)

    # Mock get_user_node to return a directory for any path we try to CD into
    mock_db.get_user_node.return_value = {"type": "dir", "path": "/home/royans"}
    mock_db.get_fs_node.return_value = None

    context = {"user": "royans", "cwd": "/tmp", "client_ip": "1.2.3.4"}

    # Case 1: cd ~
    _, updates, _ = handler.handle_cd("cd ~", context)
    assert updates.get("new_cwd") == "/home/royans"

    # Case 2: cd ~/downloads
    mock_db.get_user_node.return_value = {
        "type": "dir",
        "path": "/home/royans/downloads",
    }
    _, updates, _ = handler.handle_cd("cd ~/downloads", context)
    assert updates.get("new_cwd") == "/home/royans/downloads"


def test_authorized_keys_parsing_robustness():
    """Verify that server.py parsing logic handles options and comments in authorized_keys."""
    from ssh_honeypot.services.ssh.server import HoneypotServer

    # We need a minimal mock of the Server or just the specific method if it was isolated
    # Since it's in the class, let's mock the DB and self
    mock_db = MagicMock()

    with patch("ssh_honeypot.services.ssh.server.db", mock_db):
        server = MagicMock(spec=HoneypotServer)
        server.client_ip = "1.2.3.4"
        server.transport_ref = None

        # Manually set the method logic or import it
        from ssh_honeypot.services.ssh.server import HoneypotServer

        # Test key
        test_type = "ssh-rsa"
        test_key = "AAAAB3NzaC1yc2E..."

        mock_key = MagicMock()
        mock_key.get_name.return_value = test_type
        mock_key.get_base64.return_value = test_key

        # Mock anti-harvesting check
        mock_db.validate_anti_harvesting.return_value = (True, "OK")

        # Mock authorized_keys content with options and comments
        content = f"""
# Comment line
opt1,opt2 {test_type} {test_key} user@host
{test_type} {test_key}
        """
        mock_db.get_user_node.return_value = {"type": "file", "content": content}

        # We need to run the actual logic. Since we just modified it, we can't easily test it
        # without an instance. Let's use the real method on the mock.
        HoneypotServer.check_auth_publickey(server, "royans", mock_key)

        # Verify db.log_auth_event was called with success=True
        # Find the call to log_auth_event
        auth_call = [c for c in mock_db.method_calls if c[0] == "log_auth_event"]
        assert len(auth_call) > 0
        assert auth_call[0][1][4] == True  # success param


def test_llm_coarse_cache():
    """Verify that coarse caching works for identical commands from different contexts."""
    llm = LLMInterface()
    llm.provider = "google"

    command = "ls -la"
    cwd = "/var/www"
    user = "www-data"

    # 1. First call - should be a miss and save to coarse cache
    # We patch _call_google instead of _call_api so the cache saving logic runs
    with patch.object(
        llm, "_call_google", return_value='{"output": "file1"}'
    ) as mock_call:
        res1 = llm.generate_response(command, cwd=cwd, user=user)
        assert "file1" in res1
        assert mock_call.call_count == 1

    # 2. Second call - same command, different "random" prompt data (History/IP)
    # The coarse key only uses command, cwd, user
    # We expect a CACHE HIT, so _call_google should NOT be called again
    with patch.object(
        llm, "_call_google", side_effect=Exception("Should hit cache!")
    ) as mock_call_check:
        # We need to ensure history_str or client_ip would normally change the prompt hash
        res2 = llm.generate_response(command, cwd=cwd, user=user, client_ip="9.9.9.9")
        assert "file1" in res2
        # It should hit the coarse cache and NOT call _call_google
        assert mock_call_check.call_count == 0
