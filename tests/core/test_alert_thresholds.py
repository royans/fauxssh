import sys
import os
import pytest
from unittest.mock import MagicMock, patch

# Ensure the root directory is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ssh_honeypot.core.alert_manager import AlertManager


class TestAlertThresholds:

    @pytest.fixture(autouse=True)
    def setup(self):
        # Reset AlertManager singleton
        AlertManager._instance = None
        # Mock config
        with patch("ssh_honeypot.core.alert_manager.config") as self.mock_config:
            self.mock_config.get.side_effect = self.config_get
            self.current_threshold = 80
            yield

    def config_get(self, *args):
        if args[1] == "notify_threshold":
            return self.current_threshold
        if args[1] == "webhook_url":
            return "https://discord.com/api/webhooks/mock"
        return None

    def test_ban_alert_suppressed_below_threshold(self):
        """Ban alert (level 50) should be suppressed if threshold is 80"""
        self.current_threshold = 80
        am = AlertManager()

        with patch.object(am.notifier, "_send_async") as mock_send:
            am.send_ban_alert("1.2.3.4", 3600, "Brute force")
            mock_send.assert_not_called()

    def test_ban_alert_sent_above_threshold(self):
        """Ban alert (level 50) should be sent if threshold is 40"""
        self.current_threshold = 40
        am = AlertManager()

        with patch.object(am.notifier, "_send_async") as mock_send:
            am.send_ban_alert("1.2.3.4", 3600, "Brute force")
            mock_send.assert_called_once()
            # Verify it contains the risk level 50
            args, _ = mock_send.call_args
            payload = args[0]
            assert "(Score: 50)" in payload["content"]
