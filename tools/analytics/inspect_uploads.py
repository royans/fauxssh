#!/usr/bin/env python3
import sqlite3
import argparse
import os
import sys
import hashlib
import json

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
sys.path.append(os.path.join(PROJECT_ROOT, "ssh_honeypot"))


try:
    from config_manager import get_data_dir
    DB_PATH = os.path.join(get_data_dir(), "honeypot.sqlite")
except ImportError:
    DB_PATH = os.path.join(PROJECT_ROOT, "data", "honeypot.sqlite")

def get_db_connection():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found at {DB_PATH}")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)

def calculate_sha256(content):
    if isinstance(content, str):
        content = content.encode('utf-8')
    return hashlib.sha256(content).hexdigest()

def list_uploads():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT ip, username, path, content, created_at, metadata FROM user_filesystem")
    rows = c.fetchall()
    conn.close()

    print(f"{'Time':<20} | {'IP':<15} | {'User':<10} | {'Path':<30} | {'SHA256 (Preview)'}")
    print("-" * 110)

    for r in rows:
        ip, user, path, content, created_at, metadata = r
        content_hash = calculate_sha256(content or "")
        print(f"{created_at:<20} | {ip:<15} | {user:<10} | {path:<30} | {content_hash[:16]}...")

def export_upload(ip, user, path, output_file):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT content FROM user_filesystem WHERE ip=? AND username=? AND path=?", (ip, user, path))
    row = c.fetchone()
    conn.close()

    if not row:
        print("[!] File not found.")
        return

    content = row[0]
    if isinstance(content, str):
        content = content.encode('utf-8')

    with open(output_file, 'wb') as f:
        f.write(content)
    
    print(f"[*] Exported {len(content)} bytes to {output_file}")
    print(f"[*] Hash: {hashlib.sha256(content).hexdigest()}")

def main():
    parser = argparse.ArgumentParser(description="FauxSSH Upload Inspector")
    parser.add_argument("--list", action="store_true", help="List all uploaded files")
    parser.add_argument("--export", nargs=3, metavar=('IP', 'USER', 'PATH'), help="Export a specific file content")
    parser.add_argument("--out", type=str, default="exported_malware.bin", help="Output filename for export")

    args = parser.parse_args()

    if args.export:
        export_upload(args.export[0], args.export[1], args.export[2], args.out)
    else:
        list_uploads()

if __name__ == "__main__":
    main()
