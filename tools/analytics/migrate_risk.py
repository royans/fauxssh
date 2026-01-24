#!/usr/bin/env python3
import sys
import os

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
sys.path.append(PROJECT_ROOT)

try:
    from ssh_honeypot.core.database import get_db_backend
    from ssh_honeypot.core.config import config
except ImportError:
    print(
        "[!] Error: Could not import ssh_honeypot. Make sure you are in the project root."
    )
    sys.exit(1)


def migrate_risk_scores():
    db = get_db_backend()
    conn = db._get_conn()
    ph = getattr(db, "placeholder", "?")

    print(f"[*] Connected to: {db.get_connection_info()}")

    try:
        cursor = conn.cursor()

        # 1. Check current max risk in command_analysis
        cursor.execute("SELECT MAX(risk_score) FROM command_analysis")
        row = cursor.fetchone()
        max_risk = row[0] if row and row[0] is not None else 0

        if max_risk > 10:
            print(
                f"[!] Warning: Max risk is already {max_risk}. Migration might have already been run."
            )
            confirm = input("[?] Proceed anyway? (y/N): ")
            if confirm.lower() != "y":
                print("[*] Aborted.")
                return

        # 2. Update command_analysis
        print("[*] Updating command_analysis table...")
        cursor.execute(
            "UPDATE command_analysis SET risk_score = risk_score * 10 WHERE risk_score <= 10"
        )
        ca_count = cursor.rowcount

        # 3. Update sessions
        print("[*] Updating sessions table...")
        cursor.execute(
            "UPDATE sessions SET risk_score = risk_score * 10 WHERE risk_score <= 10"
        )
        s_count = cursor.rowcount

        conn.commit()
        print(f"[SUCCESS] Migration complete.")
        print(f" - {ca_count} command analysis entries updated.")
        print(f" - {s_count} sessions updated.")

    except Exception as e:
        print(f"[!] Migration Error: {e}")
        conn.rollback()
    finally:
        conn.close()


if __name__ == "__main__":
    migrate_risk_scores()
