import logging
import asyncio
from mysql_mimic import MysqlServer, IdentityProvider, User
from mysql_mimic.auth import NativePasswordAuthPlugin
from ssh_honeypot.services.mysql.session import HoneyMySQLSession
from ssh_honeypot.services.mysql.context import client_ip_ctx
from ssh_honeypot.core.database import HoneyDB

log = logging.getLogger("ssh_honeypot")


from ssh_honeypot.services.mysql.utils import mysql_native_password_hash


class HoneyAuthPlugin(NativePasswordAuthPlugin):
    def __init__(self, honey_db, config, username):
        self.honey_db = honey_db
        self.config = config
        self.username = username
        auth_config = (self.config or {}).get("auth") or {}
        self.weak_passwords = auth_config.get("weak_passwords", [])
        # We can pass password=None to super because we override matching logic
        super().__init__()

    def password_matches(self, user, scramble, nonce):
        # scramble is the client response
        # nonce is the salt used

        ip = client_ip_ctx.get()
        # Create a hex representation of the response for "password" logging
        password_repr = scramble.hex() if scramble else ""

        # 1. Anti-Harvesting / Rate Limit
        is_safe, reason = self.honey_db.validate_anti_harvesting(
            ip, self.username, password_repr
        )

        if not is_safe:
            log.warning(f"[MySQL] [!] {reason}")
            return False

        # 2. Check if valid against weak passwords
        is_valid = False
        caught_cleartext = None

        # Try finding a match in weak passwords list
        for weak_pw in self.weak_passwords:
            # weak_passwords config is "username:password" format?
            # Config says: ["root:password", "admin:admin"]

            if ":" in weak_pw:
                u, p = weak_pw.split(":", 1)
                if u != self.username:
                    continue
                candidate_pwd = p
            else:
                candidate_pwd = weak_pw

            # Calculate expected hash for this candidate
            # SHA1( password ) XOR SHA1( nonce + SHA1( SHA1( password ) ) )
            expected = mysql_native_password_hash(candidate_pwd.encode(), nonce)

            if expected == scramble:
                is_valid = True
                caught_cleartext = candidate_pwd
                break

        # 3. Allow Any Logic (if enabled)
        if not is_valid and self.config.get("auth", {}).get("allow_any", False):
            import random

            if random.random() < self.config.get("auth", {}).get("allow_any_rate", 0.0):
                is_valid = True
                caught_cleartext = " ALLOW_ANY_WILDCARD"

        # Log Result
        self.honey_db.log_auth_event(
            ip=ip,
            username=self.username,
            password_field="password",
            password_val=(
                caught_cleartext if caught_cleartext else f"HASH:{password_repr[:8]}..."
            ),
            success=is_valid,
            client_version="unknown",  # TODO: Get from session?
            fingerprint="mysql",
            protocol="mysql",
        )

        return is_valid


class HoneyMySQLIdentityProvider(IdentityProvider):
    def __init__(self, honey_db, config):
        self.honey_db = honey_db
        self.config = config

    async def get_user(self, username):
        ip = client_ip_ctx.get()

        # Root Desperation Check
        if username == "root":
            # We need to check database rules for root logic
            # check_root_desperation(ip)
            desp = self.honey_db.check_root_desperation(ip)
            if desp == "BLOCK":
                # Return None to simulate user not found or just fail later?
                # If we return None, it might say "Access denied for user".
                # If we return User, it checks password.
                # Let's return User but with a plugin that always Fails?
                # Or just rely on the plugin to check strictness?
                # If BLOCK, we want to deny immediately.
                pass  # We still return user, but auth will fail unless we prevent it here.
                # Actually, better to let AuthPlugin handle the BLOCK logic outcome
                # BUT `validate_anti_harvesting` is generic.
                # `check_root_desperation` is specific.

                # Let's enforce it here:
                log.info(f"[MySQL] Root Blocked (Desperation) for {ip}")
                # We can return None?
                # User 'root' usually exists. So returning None implies 'root' doesn't exist?
                # MySQL protocol doesn't strictly distinguish "User not found" vs "Wrong pass" in error messages (Access denied).
                return None
            elif desp == "ALLOW":
                log.info(f"[MySQL] Root Allowed (Desperation) for {ip}")
                # Proceed to auth

        # Return a User instance with our custom plugin
        return User(
            name=username,
            auth_plugin=HoneyAuthPlugin(self.honey_db, self.config, username),
        )


class HoneyMySQLHandler(MysqlServer):
    def __init__(self, honey_db, llm_interface, config):
        self.honey_db = honey_db

        super().__init__(
            session_factory=lambda: HoneyMySQLSession(honey_db, llm_interface, config),
            identity_provider=HoneyMySQLIdentityProvider(honey_db, config),
        )

    async def serve(self, host="0.0.0.0", port=3306):
        log.info(f"[*] Starting MySQL Honeypot on {host}:{port}")
        await self.start_server(host=host, port=port)
