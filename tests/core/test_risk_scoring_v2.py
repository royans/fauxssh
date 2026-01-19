import pytest
import os
import sys
import json
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from ssh_honeypot.core.alert_manager import AlertManager
from ssh_honeypot.core.config import config


@pytest.fixture
def mock_notifier():
    with patch("ssh_honeypot.core.alert_manager.WebhookNotifier") as MockNotifier:
        instance = MockNotifier.return_value
        instance.webhook_url = "http://fake.com"
        yield instance


@pytest.fixture
def reset_alert_manager():
    # Reset Singleton
    AlertManager._instance = None
    # If using import cache issues, this might be tricky but _instance=None usually enough for __new__
    yield
    AlertManager._instance = None


def test_risk_scoring_protocol_thresholds(mock_notifier, reset_alert_manager):
    # Setup Config with Environment Override simulation
    # We manually inject into AlertManager instance

    mgr = AlertManager()
    mgr.notifier = mock_notifier

    # 1. Inject Custom Thresholds
    # ssh: notify=50, session=70, ip=90
    # http: notify=60, session=80, ip=95
    mgr.service_thresholds = {
        "ssh": {"notify_threshold": 50, "session_threshold": 70, "ip_threshold": 90},
        "http": {"notify_threshold": 60, "session_threshold": 80, "ip_threshold": 95},
    }

    # Enable messaging
    mgr.msg_history_1h = []

    # Case 1: SSH Score 55 (Should Notify)
    mgr.check_risk_score("s1", "1.1.1.1", 55, "Test SSH High", protocol="ssh")
    mock_notifier.send_alert.assert_called_with("s1", "1.1.1.1", "Test SSH High", 55)
    mock_notifier.send_alert.reset_mock()
    mgr.msg_history_1h = []

    # Case 2: SSH Score 45 (Should NOT Notify)
    mgr.check_risk_score("s2", "1.1.1.1", 45, "Test SSH Low", protocol="ssh")
    mock_notifier.send_alert.assert_not_called()

    # Case 3: HTTP Score 55 (Should NOT Notify, threshold is 60)
    mgr.check_risk_score("s3", "1.1.1.1", 55, "Test HTTP Low", protocol="http")
    mock_notifier.send_alert.assert_not_called()

    # Case 4: HTTP Score 65 (Should Notify)
    mgr.check_risk_score("s4", "1.1.1.1", 65, "Test HTTP High", protocol="http")
    mock_notifier.send_alert.assert_called_with("s4", "1.1.1.1", "Test HTTP High", 65)


def test_config_parsing_integration():
    # Test that ConfigManager correctly parses the env var string
    # We need to instantiate a fresh ConfigManager with mocked env

    test_env = "ssh:11,22,33;http:44,55,66"
    with patch.dict(
        os.environ, {"FAUXSSH_RISK_THRESHOLDS": test_env, "ALERT_KEYWORDS": ""}
    ):
        from ssh_honeypot.core.config import ConfigManager

        cm = ConfigManager()

        svc_cfg = cm.get("alerting", "service_thresholds")
        assert svc_cfg is not None
        assert "ssh" in svc_cfg
        assert svc_cfg["ssh"]["notify_threshold"] == 11
        assert svc_cfg["ssh"]["session_threshold"] == 22
        assert svc_cfg["ssh"]["ip_threshold"] == 33

        assert "http" in svc_cfg
        assert svc_cfg["http"]["notify_threshold"] == 44
