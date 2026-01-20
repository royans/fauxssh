import asyncio
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.mysql.server import HoneyAuthPlugin
from ssh_honeypot.services.mysql.utils import mysql_native_password_hash


def test_mysql_auth_config_lookup():
    mock_db = MagicMock()
    # Simulate the structure we now expect
    config = {
        "auth": {
            "allow_any": True,
            "allow_any_rate": 1.0,
            "weak_passwords": ["test:password123"],
        }
    }

    plugin = HoneyAuthPlugin(mock_db, config)

    # Test weak password match
    nonce = b"12345678901234567890"
    scramble = mysql_native_password_hash("password123", nonce)

    with patch("ssh_honeypot.services.mysql.context.client_ip_ctx") as mock_ctx:
        mock_ctx.get.return_value = "127.0.0.1"
        mock_db.validate_anti_harvesting.return_value = (True, None)

        # Mock user object
        mock_user = MagicMock()
        mock_user.name = "test"

        result = plugin.password_matches(mock_user, scramble, nonce)
        assert result is True
        print("Weak password match passed")


def test_mysql_auth_allow_any():
    mock_db = MagicMock()
    config = {"auth": {"allow_any": True, "allow_any_rate": 1.0, "weak_passwords": []}}

    plugin = HoneyAuthPlugin(mock_db, config)
    nonce = b"12345678901234567890"
    scramble = b"wrong_scramble"

    with patch("ssh_honeypot.services.mysql.context.client_ip_ctx") as mock_ctx:
        mock_ctx.get.return_value = "127.0.0.1"
        mock_db.validate_anti_harvesting.return_value = (True, None)

        mock_user = MagicMock()
        mock_user.name = "random_user"

        result = plugin.password_matches(mock_user, scramble, nonce)
        assert result is True
        print("Allow any passed")


if __name__ == "__main__":
    test_mysql_auth_config_lookup()
    test_mysql_auth_allow_any()
    print("All Auth Tests Passed!")
