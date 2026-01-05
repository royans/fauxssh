
import sqlite3
import os
import re
from collections import Counter
import sys

# Function to get DB path
def get_db_path():
    # Prefer the fetched captured DB
    path = os.path.abspath("data/remote_capture/honeypot.sqlite")
    if os.path.exists(path):
        return path
    return "data/honeypot.sqlite"

def analyze():
    db_path = get_db_path()
    print(f"[*] Analyzing database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
    except Exception as e:
        print(f"[!] Could not connect to DB: {e}")
        return

    # Interesting file access commands
    # We want to see what attackers are trying to read
    interest_cmds = ['cat', 'head', 'tail', 'more', 'less', 'vi', 'vim', 'nano', 'grep', 'ls']
    
    # Simple regex to capture arguments that look like paths
    # Matches /path/to/file or local files
    path_regex = re.compile(r'\s+([/~a-zA-Z0-9_\-\.]+)')

    file_hits = Counter()
    
    # Get all commands
    try:
        c.execute("SELECT command FROM interactions")
        rows = c.fetchall()
    except sqlite3.OperationalError:
         print("[!] Could not query interactions table. Is the DB valid?")
         return

    for row in rows:
        cmd = row['command'].strip()
        parts = cmd.split()
        if not parts: continue
        
        base_cmd = parts[0]
        
        if base_cmd in interest_cmds:
            # Simple heuristic: take the last argument if it looks like a path
            # Or iterate all args
            args = parts[1:]
            for arg in args:
                # Filter out flags
                if arg.startswith('-'): continue
                
                # Normalize path (simple string normalization)
                # We specifically care about absolute paths often used in scanning
                if arg.startswith('/'):
                    file_hits[arg] += 1
                elif arg in ['passwd', 'shadow', 'hosts', 'resolv.conf']: 
                    # Catch attempts like 'cat passwd' if they happened to be in /etc (cwd tracking is complex here, keeping it simple)
                    file_hits[arg] += 1

    print("\n[+] Top 20 Requested Files/Paths:")
    print(f"{'Count':<8} {'Path':<40}")
    print("-" * 50)
    for path, count in file_hits.most_common(20):
        print(f"{count:<8} {path:<40}")

    print("\n[+] Top 20 Raw Commands (for context):")
    print("-" * 50)
    c.execute("SELECT command, count(*) as cnt FROM interactions GROUP BY command ORDER BY cnt DESC LIMIT 20")
    for row in c.fetchall():
        print(f"{row['cnt']:<8} {row['command']}")

if __name__ == "__main__":
    analyze()
