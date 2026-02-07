import pytest
import sqlite3
import time
from ssh_honeypot.core.database import SQLiteBackend


@pytest.fixture
def db():
    # Subclass to hold a SINGLE connection for :memory: database
    class TestBackend(SQLiteBackend):
        def __init__(self):
            self.db_path = ":memory:"
            self.placeholder = "?"
            self._real_conn = sqlite3.connect(":memory:")
            self._real_conn.row_factory = sqlite3.Row
            # Initialize schema on this specific connection
            self._init_db()
            self.skeleton_cache = []

        def _get_conn(self):
            # Return a proxy that ignores close()
            class NoCloseConnection:
                def __init__(self, conn):
                    self.conn = conn

                def __getattr__(self, name):
                    return getattr(self.conn, name)

                def close(self):
                    # Do nothing
                    pass

                def execute(self, *args, **kwargs):
                    return self.conn.execute(*args, **kwargs)

                def executemany(self, *args, **kwargs):
                    return self.conn.executemany(*args, **kwargs)

                def commit(self):
                    return self.conn.commit()

                def cursor(self):
                    return self.conn.cursor()

                # Context manager support
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_val, exc_tb):
                    pass

            return NoCloseConnection(self._real_conn)

        def _init_db(self):
            from ssh_honeypot.core.db_utils import sync_db_schema

            # Pass strict=False or similar if needed, but for now just run it.
            # We use a temporary backend instance that uses our _get_conn
            # which returns the NoCloseConnection.
            sync_db_schema(self)

    backend = TestBackend()
    return backend


def test_unanalyzed_commands_lifo_ordering(db):
    """
    Verify that get_unanalyzed_commands returns the MOST RECENT commands first (LIFO).
    This prevents starvation of new events when the queue is large.
    """
    session_id = "test_session_lifo"
    db.start_session(session_id, "127.0.0.1", "root", "pass", "SSH-2.0")

    # Insert 3 commands sequentially
    # Command 1 (Oldest)
    db.log_interaction(
        session_id, "/", "ls -la", "total 0", created_at="2024-01-01 10:00:00"
    )

    # Command 2 (Middle)
    db.log_interaction(
        session_id, "/", "whoami", "root", created_at="2024-01-01 10:01:00"
    )

    # Command 3 (Newest)
    db.log_interaction(
        session_id, "/", "curl bad.site", "", created_at="2024-01-01 10:02:00"
    )

    # Fetch 3 unanalyzed commands
    queue = db.get_unanalyzed_commands(limit=3)

    assert len(queue) == 3

    # Verify Order: Newest First
    assert queue[0]["command"] == "curl bad.site"
    assert queue[1]["command"] == "whoami"
    assert queue[2]["command"] == "ls -la"


def test_unanalyzed_sessions_lifo_ordering(db):
    """
    Verify that get_unanalyzed_sessions returns the MOST RECENT sessions first (LIFO).
    """
    import os

    os.environ["FAUXSSH_LOG_EMPTY_SESSIONS"] = "true"

    # Session 1 (Oldest)
    db.start_session(
        "s1", "1.1.1.1", "u1", "p1", "v1", start_time="2024-01-01 10:00:00"
    )
    db.log_interaction("s1", "/", "ls", "")  # Prevent deletion
    db.end_session("s1")  # Must end to be eligible

    # Session 2 (Middle)
    db.start_session(
        "s2", "2.2.2.2", "u2", "p2", "v2", start_time="2024-01-01 11:00:00"
    )
    db.log_interaction("s2", "/", "ls", "")
    db.end_session("s2")

    # Session 3 (Newest)
    db.start_session(
        "s3", "3.3.3.3", "u3", "p3", "v3", start_time="2024-01-01 12:00:00"
    )
    db.log_interaction("s3", "/", "ls", "")
    db.end_session("s3")

    # Fetch unanalyzed
    queue = db.get_unanalyzed_sessions(limit=3)

    assert len(queue) == 3
    assert queue[0] == "s3"
    assert queue[1] == "s2"
    assert queue[2] == "s1"
