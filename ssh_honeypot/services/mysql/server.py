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
    def __init__(self, honey_db, config):
        self.honey_db = honey_db
        self.config = config
        mysql_auth = (self.config or {}).get("auth") or {}
        self.weak_passwords = mysql_auth.get("weak_passwords", [])
        super().__init__()

    def password_matches(self, user, scramble, nonce):
        # scramble is the client response
        # nonce is the salt used
        username = user.name
        ip = client_ip_ctx.get("127.0.0.1")
        # Create a hex representation of the response for "password" logging
        password_repr = scramble.hex() if scramble else ""

        log.info(
            f"[MySQL] Checking Password: User='{username}' IP='{ip}' ScrambleLen={len(scramble) if scramble else 0}"
        )

        # 1. Anti-Harvesting / Rate Limit
        is_safe, reason = self.honey_db.validate_anti_harvesting(
            ip, username, password_repr
        )

        if not is_safe:
            log.warning(f"[MySQL] [!] Anti-Harvesting Block: {reason}")
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
                if u != username:
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

        if not is_valid:
            log.debug(
                f"[MySQL] No match in weak_passwords (Count: {len(self.weak_passwords)})"
            )

        # 3. Allow Any Logic (if enabled)
        if not is_valid:
            mysql_auth = (self.config or {}).get("auth") or {}
            if mysql_auth.get("allow_any", False):
                import random

                rate = mysql_auth.get("allow_any_rate", 0.0)
                if random.random() < rate:
                    is_valid = True
                    caught_cleartext = " ALLOW_ANY_WILDCARD"
                    log.info(f"[MySQL] Allow Any Triggered (Rate: {rate})")

        # Log Result
        self.honey_db.log_auth_event(
            client_ip=ip,
            username=username,
            auth_method="password",
            auth_data=(
                caught_cleartext if caught_cleartext else f"HASH:{password_repr[:8]}..."
            ),
            success=is_valid,
            client_version="unknown",
            fingerprint="mysql",
            protocol="mysql",
        )

        log.info(f"[MySQL] Auth Result: {is_valid} (User: {username}, IP: {ip})")

        return is_valid


class HoneyMySQLIdentityProvider(IdentityProvider):
    def __init__(self, honey_db, config):
        self.honey_db = honey_db
        self.config = config
        self._plugins = [HoneyAuthPlugin(honey_db, config)]

    def get_plugins(self):
        return self._plugins

    async def get_user(self, username):
        ip = client_ip_ctx.get()
        log.info(f"[MySQL] Auth Request: User='{username}' IP='{ip}'")

        if ip is None:
            log.warning(
                f"[MySQL] [!] Auth Context Missing IP. This might cause Auth Failure."
            )
            # We continue, but audit logs might be incomplete.

        # Root Desperation Check
        if username == "root":
            # We need to check database rules for root logic
            # check_root_desperation(ip)
            desp = self.honey_db.check_root_desperation(ip)
            if desp == "BLOCK":
                log.info(f"[MySQL] Root Blocked (Desperation) for {ip}")
                return None
            elif desp == "ALLOW":
                log.info(f"[MySQL] Root Allowed (Desperation) for {ip}")
                # Proceed to auth

        # Return a User instance with our custom plugin name
        return User(
            name=username,
            auth_plugin=HoneyAuthPlugin.name,
        )


class HoneyMySQLHandler(MysqlServer):
    def __init__(self, honey_db, llm_interface, config):
        self.honey_db = honey_db
        # Resolve mysql config once
        self.mysql_cfg = config.get("mysql") if hasattr(config, "get") else config

        super().__init__(
            session_factory=lambda: HoneyMySQLSession(
                honey_db, llm_interface, self.mysql_cfg
            ),
            identity_provider=HoneyMySQLIdentityProvider(honey_db, self.mysql_cfg),
        )

    async def _client_connected_cb(self, reader, writer):
        try:
            peername = writer.get_extra_info("peername")
            if peername:
                client_ip_ctx.set(peername[0])
                # log.info(f"[*] MySQL Connection from {peername}")
        except Exception as e:
            log.warning(f"[MySQL] Error extracting IP in _client_connected_cb: {e}")

        # Continue with standard mysql-mimic logic
        await super()._client_connected_cb(reader, writer)

    async def serve(self, host="0.0.0.0", port=3306):
        log.info(f"[*] Starting MySQL Honeypot on {host}:{port}")
        await self.start_server(host=host, port=port)
