import pytest
from unittest.mock import MagicMock, patch
import asyncio
from ssh_honeypot.services.mysql.server import (
    HoneyAuthPlugin,
    HoneyMySQLIdentityProvider,
    client_ip_ctx,
)
from mysql_mimic.auth import NativePasswordAuthPlugin
from hashlib import sha1

from ssh_honeypot.services.mysql.utils import mysql_native_password_hash


class TestMySQLAuth:
    @pytest.fixture
    def mock_db(self):
        db = MagicMock()
        db.validate_anti_harvesting.return_value = (True, "OK")
        db.check_root_desperation.return_value = "NORMAL"
        return db

    @pytest.fixture
    def plugin(self, mock_db):
        config = {
            "auth": {
                "weak_passwords": ["root:password", "admin:admin"],
                "allow_any": False,
            }
        }
        # Username 'root'
        plugin = HoneyAuthPlugin(mock_db, config, "root")
        plugin.salt = b"12345678901234567890"  # 20 bytes
        return plugin

    def test_auth_success(self, plugin, mock_db):
        # We need to simulate the client response for "password"
        # The salt is plugin.salt

        # Test "root:password"
        scramble = mysql_native_password_hash("password", plugin.salt)

        # Set Context
        token = client_ip_ctx.set("1.2.3.4")
        try:
            # user param can be mock or None, unused in our logic
            result = plugin.password_matches(None, scramble, plugin.salt)
        finally:
            client_ip_ctx.reset(token)

        assert result is True
        mock_db.log_auth_event.assert_called_with(
            ip="1.2.3.4",
            username="root",
            password_field="password",
            password_val="password",  # Expected cleartext capture
            success=True,
            client_version="unknown",
            fingerprint="mysql",
            protocol="mysql",
        )

    def test_auth_failure_wrong_password(self, plugin, mock_db):
        scramble = mysql_native_password_hash("wrong", plugin.salt)

        token = client_ip_ctx.set("1.2.3.4")
        try:
            result = plugin.password_matches(None, scramble, plugin.salt)
        finally:
            client_ip_ctx.reset(token)

        assert result is False
        mock_db.log_auth_event.assert_called_with(
            ip="1.2.3.4",
            username="root",
            password_field="password",
            password_val=f"HASH:{scramble.hex()[:8]}...",
            success=False,
            client_version="unknown",
            fingerprint="mysql",
            protocol="mysql",
        )

    def test_anti_harvesting_block(self, plugin, mock_db):
        mock_db.validate_anti_harvesting.return_value = (False, "Blocked")

        scramble = mysql_native_password_hash("password", plugin.salt)

        token = client_ip_ctx.set("1.2.3.4")
        try:
            result = plugin.password_matches(None, scramble, plugin.salt)
        finally:
            client_ip_ctx.reset(token)

        assert result is False
        # Verify warnings logged (via caplog if we wanted)
        # Verify log_auth_event NOT called
        mock_db.log_auth_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_root_desperation_block(self, mock_db):
        # This test checks IdentityProvider behavior
        mock_db.check_root_desperation.return_value = "BLOCK"

        config = {}
        provider = HoneyMySQLIdentityProvider(mock_db, config)

        token = client_ip_ctx.set("1.2.3.4")
        try:
            user = await provider.get_user("root")
        finally:
            client_ip_ctx.reset(token)

        assert user is None  # Should be blocked

    def test_auth_plugin_none_config(self, mock_db):
        # Regression test for AttributeError: 'NoneType' object has no attribute 'get'
        plugin = HoneyAuthPlugin(mock_db, None, "root")
        # Should initiate without error and have empty weak_passwords
        assert plugin.weak_passwords == []
