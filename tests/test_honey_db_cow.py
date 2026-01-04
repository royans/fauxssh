import pytest
import sqlite3
import os
import json
import sys
import datetime
from unittest.mock import MagicMock, patch

# Ensure imports
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from ssh_honeypot.honey_db import HoneyDB

# Mock Skeleton Data
MOCK_SKELETON = [
    {"path": "/etc/passwd", "type": "file", "content": "root:x:0:0::/root:/bin/bash", "metadata": {}},
    {"path": "~/.bashrc", "type": "file", "content": "alias ls='ls --color'", "metadata": {}},
    {"path": "~/readonly.txt", "type": "file", "content": "default", "metadata": {}}
]

@pytest.fixture
def db(tmp_path):
    """Creates a temporary DB instance with mocked skeleton."""
    db_file = tmp_path / "test_cow.sqlite"
    
    # Mock get_skeleton_data to return controlled data
    with patch("ssh_honeypot.fs_seeder.get_skeleton_data", return_value=MOCK_SKELETON):
        honey_db = HoneyDB(str(db_file))
        return honey_db

def test_cow_read_global(db):
    """Verify reading a global skeleton file work without DB entry."""
    node = db.get_user_node("1.1.1.1", "root", "/etc/passwd")
    assert node is not None
    assert node['content'] == "root:x:0:0::/root:/bin/bash"
    assert node['path'] == "/etc/passwd"

def test_cow_read_dynamic_home(db):
    """Verify reading a home-relative skeleton file resolves for specific user."""
    # User: alice
    node = db.get_user_node("1.1.1.1", "alice", "/home/alice/.bashrc")
    assert node is not None
    assert node['content'] == "alias ls='ls --color'"
    assert node['username'] == "alice"

    # User: bob
    node2 = db.get_user_node("2.2.2.2", "bob", "/home/bob/.bashrc")
    assert node2 is not None
    assert node2['content'] == "alias ls='ls --color'"
    assert node2['username'] == "bob"

def test_cow_write_shadowing(db):
    """Verify writing a file to DB shadows the skeleton default."""
    ip = "1.1.1.1"
    user = "alice"
    path = "/home/alice/readonly.txt"
    
    # 1. Read Default
    node = db.get_user_node(ip, user, path)
    assert node['content'] == "default"
    
    # 2. Update (Shadow)
    db.update_user_file(ip, user, path, "/home/alice", "file", {}, "modified")
    
    # 3. Read Modified
    node = db.get_user_node(ip, user, path)
    assert node['content'] == "modified"

def test_cow_list_merge(db):
    """Verify listing a directory merges skeleton and DB items."""
    ip = "1.1.1.1"
    user = "alice"
    home = "/home/alice"
    
    # Default state: .bashrc and readonly.txt should be visible
    items = db.list_user_dir(ip, user, home)
    filenames = [os.path.basename(i['path']) for i in items]
    assert ".bashrc" in filenames
    assert "readonly.txt" in filenames
    
    # Add a new DB-only file
    db.update_user_file(ip, user, f"{home}/newfile.txt", home, "file", {}, "new")
    
    # List again: merged
    items = db.list_user_dir(ip, user, home)
    filenames = [os.path.basename(i['path']) for i in items]
    assert ".bashrc" in filenames
    assert "readonly.txt" in filenames
    assert "newfile.txt" in filenames

def test_last_accessed_update(db):
    """Verify that reading a user file updates its last_accessed timestamp."""
    ip = "1.1.1.1"
    user = "alice"
    path = "/home/alice/testfile.txt"
    
    # 1. Create File (DB Write)
    db.update_user_file(ip, user, path, "/home/alice", "file", {}, "content")
    
    # Get initial state
    conn = db._get_conn()
    c = conn.cursor()
    c.execute("SELECT last_accessed FROM user_filesystem WHERE ip=? AND path=?", (ip, path))
    initial_access = c.fetchone()[0]
    conn.close()
    
    # Initially likely NULL or created_at depending on impl details, our impl defaults NULL
    assert initial_access is None
    
    # 2. Read File (Trigger Touch)
    import time
    time.sleep(1.1) # Ensure timestamp diff if any
    db.get_user_node(ip, user, path)
    
    # 3. Verify Update
    conn = db._get_conn()
    c = conn.cursor()
    c.execute("SELECT last_accessed FROM user_filesystem WHERE ip=? AND path=?", (ip, path))
    new_access = c.fetchone()[0]
    conn.close()
    
    assert new_access is not None

def test_prune_uploads_aggressive(db):
    """Verify pruning respects last_accessed vs created_at."""
    ip = "1.1.1.1"
    user = "alice"
    
    # Helper to inject old timestamps
    def inject_file(path, created_offset_days, accessed_offset_days=None):
        db.update_user_file(ip, user, path, "/home/alice", "file", {}, f"content_{path}")
        conn = db._get_conn()
        
        created_ts = (datetime.datetime.now() - datetime.timedelta(days=created_offset_days)).isoformat()
        
        if accessed_offset_days is not None:
             accessed_ts = (datetime.datetime.now() - datetime.timedelta(days=accessed_offset_days)).isoformat()
             conn.execute("UPDATE user_filesystem SET created_at=?, last_accessed=? WHERE path=?", (created_ts, accessed_ts, path))
        else:
             conn.execute("UPDATE user_filesystem SET created_at=?, last_accessed=NULL WHERE path=?", (created_ts, path))
             
        conn.commit()
        conn.close()

    import datetime
    
    # Case A: Old Creation, Recent Access -> KEEP
    inject_file("/home/alice/active.txt", 10, 1) # Created 10d ago, Accessed 1d ago
    
    # Case B: Old Creation, Old Access -> DELETE
    inject_file("/home/alice/inactive.txt", 10, 10) # Created 10d ago, Accessed 10d ago
    
    # Case C: Old Creation, Never Accessed (NULL) -> DELETE (Fallback to created)
    inject_file("/home/alice/abandoned.txt", 10, None) # Created 10d ago, Never accessed
    
    # Case D: Recent Creation, Never Accessed -> KEEP
    inject_file("/home/alice/new.txt", 1, None)
    
    # Run Prune (Cutoff 5 days)
    deleted = db.prune_uploads(days=5)
    deleted_paths = [d['path'] for d in deleted]
    
    # assertions
    assert "/home/alice/inactive.txt" in deleted_paths
    assert "/home/alice/abandoned.txt" in deleted_paths # Fallback logic
    assert "/home/alice/active.txt" not in deleted_paths
    assert "/home/alice/new.txt" not in deleted_paths

def test_tombstone_deletion(db):
    """Verify deleting a skeleton file creates a tombstone and hides it."""
    ip = "1.1.1.1"
    user = "alice"
    path = "/home/alice/readonly.txt"
    
    # 1. Verify existence
    node = db.get_user_node(ip, user, path)
    assert node is not None
    assert node['content'] == "default"
    
    # 2. Delete (Create Tombstone)
    db.delete_user_file(ip, user, path)
    
    # 3. Verify gone in listing
    items = db.list_user_dir(ip, user, "/home/alice")
    filenames = [os.path.basename(i['path']) for i in items]
    assert "readonly.txt" not in filenames
    
    # 4. Verify explicit get returns None
    node = db.get_user_node(ip, user, path)
    assert node is None

def test_prune_skips_tombstones(db):
    """Verify pruning does not remove tombstones (ghost file prevention)."""
    ip = "1.1.1.1"
    user = "alice"
    path = "/home/alice/readonly.txt"
    
    # 1. Delete to create tombstone
    db.delete_user_file(ip, user, path)
    
    # 2. Force old access time on tombstone
    conn = db._get_conn()
    old_ts = (datetime.datetime.now() - datetime.timedelta(days=60)).isoformat()
    # Tombstone has is_deleted=1
    conn.execute("UPDATE user_filesystem SET last_accessed=?, created_at=? WHERE path=?", (old_ts, old_ts, path))
    conn.commit()
    conn.close()
    
    # 3. Prune
    deleted = db.prune_uploads(days=30)
    
    # 4. Assert Tombstone NOT deleted
    # The file should still be hidden (ghost prevention)
    items = db.list_user_dir(ip, user, "/home/alice")
    filenames = [os.path.basename(i['path']) for i in items]
    assert "readonly.txt" not in filenames
    
    # Check raw DB to be sure tombstone exists
    conn = db._get_conn()
    c = conn.cursor()
    c.execute("SELECT is_deleted FROM user_filesystem WHERE path=?", (path,))
    row = c.fetchone()
    conn.close()
    assert row is not None
    assert row[0] == 1

def test_quota_ignores_tombstones(db):
    """Verify usage calculation ignores tombstones to prevent crashes."""
    ip = "1.1.1.1"
    user = "alice"
    path = "/home/alice/readonly.txt"
    
    db.delete_user_file(ip, user, path)
    
    # Should not raise
    usage = db.get_ip_upload_usage(ip)
    assert usage == 0

def test_list_user_dir_includes_global_and_hides_tombstones(db):
    """Verify list_user_dir merges Global DB and respects tombstones"""
    ip = "10.0.0.99"
    user = "global_tester"
    parent = "/home/global_tester"
    
    # 1. Seed Global FS
    conn = db._get_conn()
    conn.execute("INSERT OR REPLACE INTO global_filesystem (path, parent_path, type) VALUES (?, ?, ?)",
                (f"{parent}/global_static.sh", parent, "file"))
    conn.commit()
    conn.close()
    
    # 2. List (Should see Global file via Layer 3 merge)
    items = db.list_user_dir(ip, user, parent)
    filenames = [os.path.basename(i['path']) for i in items]
    assert "global_static.sh" in filenames
    
    # 3. Tombstone it
    db.delete_user_file(ip, user, f"{parent}/global_static.sh")
    
    # 4. List (Should be HIDDEN)
    items_after = db.list_user_dir(ip, user, parent)
    filenames_after = [os.path.basename(i['path']) for i in items_after]
    assert "global_static.sh" not in filenames_after

def test_skeleton_ownership_fix(db):
    """Verify skeleton items (starting with ~) get user ownership dynamically."""
    ip = "10.0.0.88"
    user = "skel_tester"
    parent = "/home/skel_tester"
    
    # 1. list_user_dir should show ~/.bashrc etc.
    items = db.list_user_dir(ip, user, parent)
    
    # Check for a standard skeleton file
    profile = next((i for i in items if i['path'].endswith('.bashrc')), None)
    assert profile is not None
    
    # Verify Metadata has Owner injected
    meta = json.loads(profile['metadata'])
    assert meta.get('owner') == user
    assert meta.get('group') == user
