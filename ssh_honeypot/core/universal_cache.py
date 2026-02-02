import json
import base64
import hashlib
import logging
from datetime import datetime, timedelta

from ssh_honeypot.core.database import get_db_backend
from ssh_honeypot.core.cache import cache

log = logging.getLogger(__name__)


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class UniversalCache:
    """
    Rock-solid Caching API for all honeypot services.
    Handles Memcached-first lookups with DB fallbacks and transparent encoding.
    """

    @staticmethod
    def cleanup_http_cache(web_root):
        """
        Removes HTTP cache entries that conflict with real files in VFS.
        """
        import os

        db = get_db_backend()
        keys = db.get_cache_keys("http_cache")

        for item in keys:
            cache_key = item["cache_key"]
            input_text = item["input_text"]

            if input_text.startswith("HTTP GET "):
                # Extract path: "HTTP GET /index.html" -> "/index.html"
                try:
                    path = input_text.split(" ", 2)[2].split("?")[0]
                    v_path = os.path.normpath(os.path.join(web_root, path.lstrip("/")))

                    # If it's a directory, check for index files
                    is_conflict = False
                    node = db.get_fs_node(v_path)
                    if node:
                        is_conflict = True
                    elif path == "/":
                        # Root / usually maps to index.html/php
                        for idx in ["index.html", "index.php", "index.htm"]:
                            if db.get_fs_node(os.path.join(web_root, idx)):
                                is_conflict = True
                                break

                    if is_conflict:
                        log.debug(
                            f"[UniversalCache] Invalidating conflicting HTTP cache: {input_text}"
                        )
                        UniversalCache.delete("http_cache", cache_key)
                except Exception as e:
                    log.warning(
                        f"[UniversalCache] Error parsing cache key for cleanup: {e}"
                    )

    @staticmethod
    def get(service, key):
        """
        Retrieves an item from cache.
        Priority: Memcached -> Database.
        """
        cache_key = f"ucache:{service}:{key}"

        # 1. Try Memcached First
        cached_data = cache.get_content(cache_key, "UNIVERSAL")
        if cached_data:
            try:
                item = json.loads(cached_data)
                UniversalCache._post_process_item(item)
                # Async hit increment (here sync for simplicity)
                # UniversalCache._increment_hit(key)
                return item
            except Exception as e:
                log.warning(
                    f"[UniversalCache] Failed to parse memcached data for {key}: {e}"
                )

        # 2. Try Database
        db = get_db_backend()
        item = db.get_cache_item(key)
        if item:
            # 3. Backfill Memcached
            try:
                cache.set_content(
                    cache_key, "UNIVERSAL", json.dumps(item, cls=DateTimeEncoder)
                )
            except Exception as e:
                log.warning(
                    f"[UniversalCache] Failed to backfill memcached for {key}: {e}"
                )

            UniversalCache._post_process_item(item)
            return item

        return None

    @staticmethod
    def delete(service, key):
        """Removes an item from both Memcached and Database."""
        # 1. Delete from Database
        db = get_db_backend()
        db.delete_cache_item(key)

        # 2. Delete from Memcached
        cache_key = f"ucache:{service}:{key}"
        try:
            cache.delete_content(cache_key, "UNIVERSAL")
        except Exception as e:
            log.warning(f"[UniversalCache] Memcached delete failed for {key}: {e}")

        return True

    @staticmethod
    def clear_service(service):
        """Removes all items for a specific service."""
        db = get_db_backend()
        # This is a bit heavy but safe.
        # Future: implement db.delete_service_cache(service)
        try:
            keys = db.get_cache_keys(service)
            for item in keys:
                UniversalCache.delete(service, item["cache_key"])
        except Exception as e:
            log.warning(f"[UniversalCache] Failed to clear service {service}: {e}")

    @staticmethod
    def set(
        service,
        key,
        output_text,
        version=1,
        input_text=None,
        risk_score=None,
        attack_stage=None,
        explanation=None,
        metadata=None,
        extra_data=None,
        is_binary=False,
        ttl_days=30,
    ):
        """
        Saves an item to both Memcached and Database.
        """
        if output_text is None:
            return False

        # 1. Guard: Do not cache internal resource errors
        if output_text and "Error: System resources exhausted" in str(output_text):
            log.warning(
                f"[UniversalCache] Preventing cache of resource exhaustion error for key {key}"
            )
            return False

        # 2. Calculate Hashes and Encoding
        input_hash = (
            hashlib.md5(input_text.encode("utf-8")).hexdigest() if input_text else None
        )

        final_output = output_text
        if is_binary:
            if isinstance(output_text, bytes):
                final_output = base64.b64encode(output_text).decode("utf-8")
            else:
                # Already encoded or not bytes?
                pass

        output_hash = (
            hashlib.md5(final_output.encode("utf-8")).hexdigest()
            if isinstance(final_output, str)
            else None
        )
        output_size = len(output_text) if output_text else 0

        # 2. Save to Database
        db = get_db_backend()
        final_meta = metadata or extra_data
        db.set_cache_item(
            cache_key=key,
            service=service,
            version=version,
            input_text=input_text,
            input_hash=input_hash,
            output_text=final_output,
            output_hash=output_hash,
            output_size=output_size,
            is_binary=is_binary,
            risk_score=risk_score,
            attack_stage=attack_stage,
            explanation=explanation,
            metadata=(
                json.dumps(final_meta, cls=DateTimeEncoder) if final_meta else None
            ),
            ttl_days=ttl_days,
        )

        # 3. Save to Memcached
        cache_key = f"ucache:{service}:{key}"
        item_for_cache = {
            "service": service,
            "version": version,
            "input_text": input_text,
            "input_hash": input_hash,
            "output_text": final_output,
            "output_hash": output_hash,
            "output_size": output_size,
            "is_binary": is_binary,
            "risk_score": risk_score,
            "attack_stage": attack_stage,
            "explanation": explanation,
            "metadata": (
                json.dumps(final_meta, cls=DateTimeEncoder) if final_meta else None
            ),
        }
        try:
            cache.set_content(
                cache_key, "UNIVERSAL", json.dumps(item_for_cache, cls=DateTimeEncoder)
            )
        except Exception as e:
            log.warning(f"[UniversalCache] Memcached set failed for {key}: {e}")

        return True

    @staticmethod
    def _post_process_item(item):
        """Handles Base64 decoding and JSON parsing of metadata."""
        if item.get("is_binary") and item.get("output_text"):
            try:
                item["output_bytes"] = base64.b64decode(item["output_text"])
            except Exception as e:
                log.error(f"[UniversalCache] Base64 decode failed: {e}")

        if item.get("metadata") and isinstance(item["metadata"], str):
            try:
                item["metadata"] = json.loads(item["metadata"])
            except:
                item["metadata"] = {}


# Singleton instance
universal_cache = UniversalCache()
