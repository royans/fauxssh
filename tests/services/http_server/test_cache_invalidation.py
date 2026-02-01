import pytest
import hashlib
from unittest.mock import patch, MagicMock
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.universal_cache import UniversalCache

# We need to test the logic of cleanup_http_cache without a real DB if possible,
# or use a temporary DB. Since the method performs SQL DELETEs, an in-memory DB is best.


@pytest.fixture
def honey_db(tmp_path):
    # Use a temporary file DB so that multiple connections share the same state
    # (sqlite3 ':memory:' resets on close)
    db_file = tmp_path / "test_honey.sqlite"
    db = HoneyDB(str(db_file))
    return db


def test_cleanup_http_cache(honey_db):
    # 1. Setup VFS State
    # Create a normal file
    honey_db.update_fs_node(
        "/var/www/html/style.css",
        "/var/www/html",
        "file",
        {"size": 100},
        content="Local CSS",
    )
    # Create an index file
    honey_db.update_fs_node(
        "/var/www/html/index.html",
        "/var/www/html",
        "file",
        {"size": 200},
        content="Local Index",
    )
    # Create a non-web file (should be ignored)
    honey_db.update_fs_node(
        "/etc/passwd", "/etc", "file", {"size": 500}, content="root:x:0:0..."
    )

    # 2. Setup Cache State using UniversalCache
    # We patch get_db_backend to return our test db
    with patch(
        "ssh_honeypot.core.universal_cache.get_db_backend", return_value=honey_db
    ):

        # Helper to set cache
        def set_cache(input_text, output_text):
            key = hashlib.md5(input_text.encode()).hexdigest()
            UniversalCache.set(
                service="http_cache",
                key=key,
                input_text=input_text,
                output_text=output_text,
                ttl_days=30,
            )

        # Helper to get cache
        def get_cache(input_text):
            key = hashlib.md5(input_text.encode()).hexdigest()
            return UniversalCache.get("http_cache", key)

        # Conflict with direct file
        set_cache("HTTP GET /style.css", "Cached CSS")
        # Conflict with index file (direct access)
        set_cache("HTTP GET /index.html", "Cached Index Direct")
        # Conflict with index file (root access)
        set_cache("HTTP GET /", "Cached Root")
        # Non-conflicting file
        set_cache("HTTP GET /other.html", "Cached Other")
        # POST request conflict (Should ideally be cleared too if logic supports it, but currently logic checks startswith HTTP GET)
        # Based on implementation: if input_text.startswith("HTTP GET ")
        # So POST is NOT cleaned up by current logic. Correct.
        set_cache("HTTP POST /index.html", "Cached POST")

        # Verify initial state
        assert get_cache("HTTP GET /style.css")["output_text"] == "Cached CSS"
        assert get_cache("HTTP GET /")["output_text"] == "Cached Root"

        # 3. Run Cleanup
        UniversalCache.cleanup_http_cache("/var/www/html")

        # 4. Verify Results
        # /style.css should be gone
        assert get_cache("HTTP GET /style.css") is None

        # /index.html should be gone (Direct)
        assert get_cache("HTTP GET /index.html") is None

        # / should be gone (Mapped from index.html)
        assert get_cache("HTTP GET /") is None

        # POST to /index.html should REMAIN (per current logic limitation/feature)
        assert get_cache("HTTP POST /index.html")["output_text"] == "Cached POST"

        # /other.html should REMAIN
        assert get_cache("HTTP GET /other.html")["output_text"] == "Cached Other"
