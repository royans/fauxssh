import os
from pymemcache.client.base import Client
from ssh_honeypot.core.logging_setup import log


class CacheManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CacheManager, cls).__new__(cls)
            cls._instance.client = None
            cls._instance._connect()
        return cls._instance

    def _connect(self):
        host = os.environ.get("MEMCACHED_HOST", "localhost")
        port = int(os.environ.get("MEMCACHED_PORT", 11211))
        try:
            # ignore_exc=True suppresses exceptions and returns None on get/False on set fail
            self.client = Client(
                (host, port), connect_timeout=0.5, timeout=0.5, ignore_exc=True
            )
            log.debug(f"Initialized Memcache Client at {host}:{port}")
        except Exception as e:
            log.warning(f"Failed to init memcache client: {e}")
            self.client = None

    def set_block(self, ip, service, ttl=3600):
        if not self.client:
            return
        key = f"block:{service}:{ip}"
        try:
            self.client.set(key, "1", expire=ttl)
        except Exception:
            pass

    def is_blocked(self, ip, service):
        if not self.client:
            return False
        key = f"block:{service}:{ip}"
        try:
            return self.client.get(key) is not None
        except Exception:
            return False

    def set_content(self, key, scope, content, ttl=86400):
        if not self.client:
            return
        # Hash unique key combo for safety
        import hashlib

        cache_key = (
            f"content:{hashlib.md5((key + list_sep + scope).encode()).hexdigest()}"
        )
        try:
            # Memcache usually handles bytes or strings if configured, but default client handles bytes best or string.
            # We store strings.
            self.client.set(cache_key, content, expire=ttl)
        except Exception:
            pass

    def get_content(self, key, scope):
        if not self.client:
            return None
        import hashlib

        cache_key = (
            f"content:{hashlib.md5((key + list_sep + scope).encode()).hexdigest()}"
        )
        try:
            val = self.client.get(cache_key)
            if val is not None:
                # Ensure it's string
                if isinstance(val, bytes):
                    return val.decode("utf-8")
                return val
        except Exception:
            pass
        return None


list_sep = ":"

cache = CacheManager()
