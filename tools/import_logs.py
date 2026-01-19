#!/usr/bin/env python3
import sys
import os
import json
import argparse
from datetime import datetime

# Adjust path to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ssh_honeypot.core.database import get_db_backend
from ssh_honeypot.core.config import config
from ssh_honeypot.core.logging_setup import log


from ssh_honeypot.core.logging_setup import log


def cleanup_bad_imports(db):
    """
    Deletes sessions that were imported with placeholder data (0.0.0.0 / unknown)
    by previous versions of this tool, to allow clean re-import.
    """
    try:
        conn = db._get_conn()
        cursor = conn.cursor()

        # Check if we are on Postgres or SQLite
        ph = getattr(db, "placeholder", "?")

        # Select bad sessions
        query_select = f"""
            SELECT COUNT(*) FROM sessions 
            WHERE client_version = 'imported-log-v1' 
            AND (remote_ip = '0.0.0.0' OR username = 'unknown')
        """
        cursor.execute(query_select)
        if ph == "%s":
            # Postgres RealDictCursor returns dict or Row? _get_conn raw?
            # _get_conn returns RAW psycopg2 connection. Default cursor is tuple.
            # If using db_postgres.py, _get_conn returns PooledConnectionWrapper around raw conn.
            # Default cursor is tuple.
            count = cursor.fetchone()[0]
        else:
            count = cursor.fetchone()[0]

        if count > 0:
            print(
                f"[*] Cleaning up {count} corrupted/placeholder entries from previous imports..."
            )

            # 1. Delete associated interactions first (FK Constraint)
            query_delete_interactions = f"""
                DELETE FROM interactions
                WHERE session_id IN (
                    SELECT session_id FROM sessions 
                    WHERE client_version = 'imported-log-v1' 
                    AND (remote_ip = '0.0.0.0' OR username = 'unknown')
                )
            """
            cursor.execute(query_delete_interactions)

            # 2. Delete the sessions
            query_delete_sessions = f"""
                DELETE FROM sessions 
                WHERE client_version = 'imported-log-v1' 
                AND (remote_ip = '0.0.0.0' OR username = 'unknown')
            """
            cursor.execute(query_delete_sessions)
            conn.commit()
            print(f"    [+] Deleted {count} session rows (and related interactions).")

        conn.close()
    except Exception as e:
        print(f"[!] Warning: Failed to cleanup bad imports: {e}")


def import_logs(log_file_path, dry_run=False):
    """
    Reads legacy JSON logs and imports them into the active Database Backend.
    """
    if not os.path.exists(log_file_path):
        print(f"[!] Log file not found: {log_file_path}")
        return

    print(f"[*] Importing logs from: {log_file_path}")
    print(f"[*] Target Backend: {type(get_db_backend()).__name__}")

    db = get_db_backend()

    # Cleanup "Bad" Imports from previous runs
    if not dry_run:
        cleanup_bad_imports(db)

    count = 0
    errors = 0
    known_sessions = set()  # Local cache to avoid DB hits

    with open(log_file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)

                # Check format.
                # All formats rely on session_id being present or reconstructible
                session_id = entry.get("session_id")
                if not session_id:
                    # Unified logs might have session_id at root
                    pass

                # Pre-check Session Existence to silence FK errors
                if session_id and session_id not in known_sessions:
                    # Check DB
                    if not db.get_session(session_id):
                        if not dry_run:
                            # Extract Metadata if available
                            ts_str = entry.get("timestamp")
                            start_time = None
                            if ts_str:
                                try:
                                    if isinstance(ts_str, (int, float)):
                                        start_time = datetime.fromtimestamp(ts_str)
                                    else:
                                        # Handle "2026-01-17 01:21:57" format
                                        start_time = datetime.strptime(
                                            str(ts_str), "%Y-%m-%d %H:%M:%S"
                                        )
                                except (ValueError, TypeError):
                                    pass

                            ip = entry.get("ip", "0.0.0.0")
                            if ip == "unknown":
                                ip = "0.0.0.0"

                            user = entry.get("user", "unknown")
                            client = "imported-log-v1"
                            if "client_version" in entry:
                                client = entry["client_version"]

                            # Reconstruct silently
                            try:
                                db.start_session(
                                    session_id=session_id,
                                    ip=ip,
                                    username=user,
                                    password="unknown",
                                    client_version=client,
                                    start_time=start_time,
                                )
                            except Exception:
                                # Ignore if race condition / duplicate
                                pass
                    known_sessions.add(session_id)

                if "type" in entry and "data" in entry:
                    # It's a Unified Event.
                    if entry["type"] == "interaction":
                        data = entry["data"]
                        if not dry_run:
                            try:
                                db.log_interaction(
                                    session_id=entry["session_id"],
                                    cwd=data.get("cwd", "/unknown"),
                                    command=data.get("input", ""),
                                    response=data.get("output_head", "") or "",
                                    source="import_tool",
                                    request_md5=data.get("output_md5"),
                                )
                            except Exception:
                                # Start session check handled above, so specific errors ignored
                                pass
                else:
                    # Legacy Log Entry
                    if not dry_run:
                        try:
                            db.log_interaction(
                                session_id=entry.get("session_id", "unknown_import"),
                                cwd=entry.get("cwd", "/"),
                                command=entry.get("command", ""),
                                response="[CONTENT MISSING - IMPORTED FROM LOG]",
                                source="backfill",
                                was_cached=entry.get("cached", False),
                                duration_ms=entry.get("response_time_ms", 0),
                            )
                        except Exception:
                            pass

                count += 1
                if count % 100 == 0:
                    print(f"    Processed {count} entries...")

            except json.JSONDecodeError:
                errors += 1
            except Exception as e:
                print(f"Error importing line: {e}")
                errors += 1

    print(f"[*] Import Complete.")
    print(f"    Success: {count}")
    print(f"    Errors/Skipped: {errors}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import JSON logs into DB")
    parser.add_argument(
        "logfile", help="Path to JSON log file (e.g. data/honeypot.json.log)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Parse only, do not write to DB"
    )

    args = parser.parse_args()

    import_logs(args.logfile, args.dry_run)
