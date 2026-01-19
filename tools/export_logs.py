#!/usr/bin/env python3
import sys
import os
import json
import argparse
import time

# Adjust path to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ssh_honeypot.core.database import get_db_backend
from ssh_honeypot.core.config import config
from ssh_honeypot.core.logging_setup import log


def export_logs(output_file):
    """
    Exports interactions from the active DB to a JSON file.
    """
    print(f"[*] Exporting logs to: {output_file}")
    print(f"[*] Source Backend: {type(get_db_backend()).__name__}")

    db = get_db_backend()
    count = 0

    try:
        with open(output_file, "w") as f:
            for row in db.iter_interactions():
                # Reconstruct Unified Event format
                # Row keys depends on DB schema: session_id, cwd, command, response, timestamp...

                # timestamp in DB is usually float or ISO string depending on version?
                # In SQLiteBackend (HoneyDB), 'timestamp' column in 'interactions' table...
                # Wait, 'interactions' table in 'database.py' usually defaults to CURRENT_TIMESTAMP in schema
                # or is inserted?
                # Looking at _init_db in database.py:
                # CREATE TABLE IF NOT EXISTS interactions (... timestamp DATETIME DEFAULT CURRENT_TIMESTAMP ...)

                # So it's likely a string.

                event = {
                    "ver": "1.0",
                    "event_id": f"export-{count}",  # We don't store event_id in interactions table typically
                    "timestamp": row.get("timestamp"),
                    "type": "interaction",
                    "session_id": row.get("session_id"),
                    "protocol": "ssh",
                    "source": {"imported": True},
                    "data": {
                        "input": row.get("command"),
                        "output_head": row.get("response_head"),
                        "output_size": row.get("response_size"),
                        "output_md5": row.get("response_md5"),
                        "cwd": row.get("cwd"),
                    },
                }

                # Construct full response if available (it is in SQLite)
                # But 'events.json.log' usually has limited response.
                # If user wants FULL export, maybe we shouldn't follow 'events.json.log' format strictly?
                # User asked "export log", implies same format.
                # But let's dump what we have.
                if row.get("response"):
                    # events.json.log doesn't usually carry full response body for size reasons
                    # but let's include it in export as 'full_output'
                    event["data"]["full_output"] = row.get("response")

                f.write(json.dumps(event, default=str) + "\n")

                count += 1
                if count % 1000 == 0:
                    print(f"    Exported {count} entries...")

    except KeyboardInterrupt:
        print("\n[!] Export interrupted.")
    except Exception as e:
        print(f"\n[!] Error exporting: {e}")
        import traceback

        traceback.print_exc()

    print(f"[*] Export Complete. Total: {count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export DB interactions to JSON log")
    parser.add_argument(
        "output", help="Path to output JSON file (e.g. exported_logs.json)"
    )

    args = parser.parse_args()

    export_logs(args.output)
