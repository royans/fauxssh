import pytest
from unittest.mock import MagicMock
from ssh_honeypot.core.database import HoneyDB

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

    # 2. Setup Cache State (populate with "stale" hallucinatios)
    # Conflict with direct file
    honey_db.cache_response("HTTP GET /style.css", "HTTP_ROOT", "Cached CSS")
    # Conflict with index file (direct access)
    honey_db.cache_response("HTTP GET /index.html", "HTTP_ROOT", "Cached Index Direct")
    # Conflict with index file (root access)
    honey_db.cache_response("HTTP GET /", "HTTP_ROOT", "Cached Root")
    # Non-conflicting file
    honey_db.cache_response("HTTP GET /other.html", "HTTP_ROOT", "Cached Other")
    # POST request conflict
    honey_db.cache_response("HTTP POST /index.html", "HTTP_ROOT", "Cached POST")

    # Verify initial state
    assert (
        honey_db.get_cached_response("HTTP GET /style.css", "HTTP_ROOT") == "Cached CSS"
    )
    assert honey_db.get_cached_response("HTTP GET /", "HTTP_ROOT") == "Cached Root"

    # 3. Run Cleanup
    honey_db.cleanup_http_cache("/var/www/html")

    # 4. Verify Results
    # /style.css should be gone
    assert honey_db.get_cached_response("HTTP GET /style.css", "HTTP_ROOT") is None

    # /index.html should be gone (Direct)
    assert honey_db.get_cached_response("HTTP GET /index.html", "HTTP_ROOT") is None

    # / should be gone (Mapped from index.html)
    assert honey_db.get_cached_response("HTTP GET /", "HTTP_ROOT") is None

    # POST to /index.html should be gone
    # Note: get_cached_response does exact match on command key
    assert honey_db.get_cached_response("HTTP POST /index.html", "HTTP_ROOT") is None

    # /other.html should REMAIN
    assert (
        honey_db.get_cached_response("HTTP GET /other.html", "HTTP_ROOT")
        == "Cached Other"
    )
