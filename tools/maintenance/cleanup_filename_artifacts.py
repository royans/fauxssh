#!/usr/bin/env python3
import sqlite3
import os
import argparse
import sys

# Add project root to path
sys.path.append(os.path.join(os.path.dirname(__file__), "../../"))

try:
    from ssh_honeypot.honey_db import HoneyDB
except ImportError:
    print("Error: Could not import HoneyDB. Make sure you run this from the project root or install the package.")
    sys.exit(1)

def cleanup(db_path, dry_run=True):
    print(f"Opening DB: {db_path}")
    if not os.path.exists(db_path):
        print("Error: DB file not found.")
        return

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # 1. Detect suspicious filenames (starting with -) in USER filesystem
    c.execute("SELECT ip, username, path FROM user_filesystem")
    rows = c.fetchall()
    
    found_user = []
    for r in rows:
        ip, user, path = r
        basename = os.path.basename(path)
        if basename.startswith('-'):
            found_user.append(r)

    # 2. Detect suspicious in GLOBAL filesystem
    # Global FS table: path, parent_path, type, metadata, ...
    c.execute("SELECT path FROM global_filesystem")
    rows_global = c.fetchall()
    
    found_global = []
    for r in rows_global:
        path = r[0]
        basename = os.path.basename(path)
        if basename.startswith('-'):
            found_global.append(path)

    if not found_user and not found_global:
        print("No suspicious artifact files found.")
        conn.close()
        return

    print(f"Found {len(found_user)} suspicious user files and {len(found_global)} global files.")
    
    for f in found_user:
        print(f" - [USER] {f[2]} (User: {f[1]})")
    for f in found_global:
        print(f" - [GLOBAL] {f}")

    if dry_run:
        print("\n[DRY RUN] No changes made. Run with --force to delete.")
    else:
        print("\nDeleting...")
        count = 0
        for f in found_user:
            c.execute("DELETE FROM user_filesystem WHERE ip=? AND username=? AND path=?", f)
            count += 1
            
        for path in found_global:
            c.execute("DELETE FROM global_filesystem WHERE path=?", (path,))
            count += 1
            
        conn.commit()
        print(f"Deleted {count} records.")

    conn.close()

if __name__ == "__main__":
    # Robust Setup for Environment
    try:
        from ssh_honeypot.config_manager import get_data_dir
        # This will use FAUXSSH_DATA_DIR from .env if loaded by config_manager
        auto_path = os.path.join(get_data_dir(), "honeypot.sqlite")
    except ImportError:
        # Fallback if import fails (unlikely in correct env)
        auto_path = "data/honeypot.sqlite"

    parser = argparse.ArgumentParser(description="Cleanup artifact files (starting with -) from HoneyDB")
    
    # We allow explicit override, but default to the robustly discovered path
    parser.add_argument("--db", default=auto_path, help=f"Path to SQLite DB (Default: {auto_path})")
    parser.add_argument("--force", action="store_true", help="Perform deletion")
    
    args = parser.parse_args()
    
    print(f"[*] Using Database: {os.path.abspath(args.db)}")
    cleanup(args.db, dry_run=not args.force)
