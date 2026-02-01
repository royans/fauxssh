import argparse
import sys
import logging

# Ensure packages are found if run directly
import os

if __name__ == "__main__":
    sys.path.append(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )

from ssh_honeypot.core.config import config
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.db_postgres import PostgresBackend
from ssh_honeypot.core.db_utils import sync_db_schema
from ssh_honeypot.core.db_schema import TABLE_SCHEMAS


def sync_db():
    print("[Management] Starting Database Schema Sync...")

    # 1. Check Config
    db_type = config.get("database", "type")
    if db_type != "postgres":
        print(f"[Management] Database type is '{db_type}', skipping Postgres sync.")
        return

    pg_config = config.get("database", "postgres")
    print(
        f"[Management] Connecting to Postgres (User: {pg_config.get('user')}, Host: {pg_config.get('host')})..."
    )

    # 2. Check Password Presence (Security check)
    if not pg_config.get("password"):
        print(
            "[Management] WARNING: No password found in configuration! Check .env loading."
        )

    try:
        db = PostgresBackend(config=pg_config)
        print(f"[Management] Connected: {db.get_connection_info()}")

        print("[Management] Running sync_db_schema...")
        sync_db_schema(db)
        print("[Management] Schema Sync Complete.")

    except Exception as e:
        print(f"[Management] ERROR: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="SSH Honeypot Management Utility")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Sync DB Command
    subparsers.add_parser("sync_db", help="Synchronize Database Schema")

    args = parser.parse_args()

    if args.command == "sync_db":
        sync_db()
    else:
        parser.print_help()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
