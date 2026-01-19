#!/usr/bin/env python3
import sqlite3
import json
import os
import sys
import time
from datetime import datetime, timedelta

# Find DB path relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)


try:
    from ssh_honeypot.core.utils import get_data_dir, get_ignored_ips

    # New centralized backend
    from ssh_honeypot.core.database import get_db_backend
except ImportError as e:
    # Fallback only for testing/dev environments not set up correctly
    import traceback

    traceback.print_exc()
    error_msg = str(e)

    def get_ignored_ips():
        return []

    def get_db_backend():
        raise ImportError(f"Failed to import core modules: {error_msg}")


def anonymize_ip(ip):
    if not ip:
        return "unknown"
    if ":" in ip:
        return "xxxx:xxxx:xxxx:xxxx::200"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.200"
    return "xxx.xxx.xxx.200"


def get_db():
    try:
        db = get_db_backend()
        conn = db._get_conn()
        ph = getattr(db, "placeholder", "?")

        if ph == "%s":  # Postgres
            import psycopg2.extras

            conn.cursor_factory = psycopg2.extras.RealDictCursor

        return conn, ph
    except Exception as e:
        print(f"Error connecting to DB: {e}", file=sys.stderr)
        sys.exit(1)


def generate_report():
    conn, ph = get_db()
    cursor = conn.cursor()

    report = {"generated_at": datetime.now().isoformat(), "status": {}, "activity": {}}

    try:
        # Prepare IP Filter
        try:
            ignored = get_ignored_ips()
        except:
            ignored = []

        sess_filter = ""
        auth_filter = ""
        params = []

        if ignored:
            placeholders = ",".join([ph] * len(ignored))
            sess_filter = f" AND remote_ip NOT IN ({placeholders})"
            auth_filter = f" AND client_ip NOT IN ({placeholders})"
            params = ignored

        # 1. General Stats
        cursor.execute(
            f"SELECT COUNT(*) as count FROM sessions WHERE username != 'royans'{sess_filter}",
            params,
        )
        row = cursor.fetchone()
        if hasattr(row, "keys"):  # Dict-like (RealDictCursor or Row)
            total_sessions = row["count"] if "count" in row else list(row.values())[0]
        else:
            total_sessions = row[0]

        cursor.execute(
            f"""
            SELECT COUNT(*) as count FROM interactions i
            JOIN sessions s ON i.session_id = s.session_id
            WHERE s.username != 'royans' {sess_filter.replace('remote_ip', 's.remote_ip')}
        """,
            params,
        )
        row = cursor.fetchone()
        if hasattr(row, "keys"):
            total_commands = row["count"] if "count" in row else list(row.values())[0]
        else:
            total_commands = row[0]

        cursor.execute(
            f"SELECT MIN(start_time) as first_seen FROM sessions WHERE username != 'royans'{sess_filter}",
            params,
        )
        row_min = cursor.fetchone()
        if hasattr(row_min, "keys"):
            first_seen = row_min["first_seen"]
        elif row_min:
            first_seen = row_min[0]
        else:
            first_seen = None

        report["status"] = {
            "total_sessions": total_sessions,
            "total_commands": total_commands,
            "tracking_since": str(first_seen) if first_seen else None,
        }

        # 2. Top Requesters (IPs)
        cursor.execute(
            f"""
            SELECT remote_ip, COUNT(*) as count 
            FROM sessions 
            WHERE username != 'royans'{sess_filter}
            GROUP BY remote_ip 
            ORDER BY count DESC 
            LIMIT 10
        """,
            params,
        )
        top_ips = []
        for row in cursor.fetchall():
            top_ips.append(
                {"ip": anonymize_ip(row["remote_ip"]), "count": row["count"]}
            )
        report["activity"]["top_ips"] = top_ips

        # 3. Top Usernames
        cursor.execute(
            f"""
            SELECT username, COUNT(*) as count 
            FROM auth_events 
            WHERE username != 'royans'{auth_filter}
            GROUP BY username 
            ORDER BY count DESC 
            LIMIT 10
        """,
            params,
        )
        top_users = []
        for row in cursor.fetchall():
            top_users.append({"username": row["username"], "count": row["count"]})
        report["activity"]["top_usernames"] = top_users

        # 4. Top Commands
        cursor.execute(
            f"""
            SELECT i.command, COUNT(*) as count 
            FROM interactions i
            JOIN sessions s ON i.session_id = s.session_id
            WHERE s.username != 'royans' {sess_filter.replace('remote_ip', 's.remote_ip')}
            GROUP BY i.command 
            ORDER BY count DESC 
            LIMIT 10
        """,
            params,
        )
        top_cmds = []
        for row in cursor.fetchall():
            top_cmds.append({"command": row["command"], "count": row["count"]})
        report["activity"]["top_commands"] = top_cmds

        # 5. Top Client Versions
        cursor.execute(
            f"""
            SELECT client_version, COUNT(*) as count 
            FROM sessions 
            WHERE username != 'royans'{sess_filter}
            GROUP BY client_version 
            ORDER BY count DESC 
            LIMIT 10
        """,
            params,
        )
        top_clients = []
        for row in cursor.fetchall():
            client = row["client_version"]
            # Handle potential None or missing keys if row isn't standard
            if not client and hasattr(row, "keys") and "client_version" not in row:
                client = list(row.values())[0]  # Fallback
            top_clients.append({"client": client, "count": row["count"]})
        report["activity"]["top_clients"] = top_clients

        # 6. Recent Sessions
        cursor.execute(
            f"""
            SELECT session_id, remote_ip, username, start_time, client_version 
            FROM sessions 
            WHERE username != 'royans'{sess_filter}
            ORDER BY start_time DESC 
            LIMIT 5
        """,
            params,
        )
        recent_sessions = []
        for row in cursor.fetchall():
            start_t = row["start_time"]
            if isinstance(start_t, datetime):
                start_t = start_t.isoformat()

            recent_sessions.append(
                {
                    "time": start_t,
                    "ip": anonymize_ip(row["remote_ip"]),
                    "user": row["username"],
                    "client": row["client_version"],
                }
            )
        report["activity"]["recent_sessions"] = recent_sessions

        # 7. Threat Stats
        report["threat_stats"] = {}

        # 7a. Activity Type Distribution
        cursor.execute(
            """
            SELECT activity_type, COUNT(*) as count
            FROM command_analysis
            GROUP BY activity_type
            ORDER BY count DESC
        """
        )
        activity_dist = []
        for row in cursor.fetchall():
            activity_dist.append({"type": row["activity_type"], "count": row["count"]})
        report["threat_stats"]["activity_distribution"] = activity_dist

        # 7b. Top High Risk Commands
        cursor.execute(
            """
            SELECT command_text, risk_score, activity_type, COUNT(*) as count
            FROM command_analysis
            WHERE risk_score >= 7
            GROUP BY command_text, risk_score, activity_type
            -- Group By updated for Postgres strictness
            ORDER BY risk_score DESC, count DESC
            LIMIT 5
        """
        )
        top_risk = []
        for row in cursor.fetchall():
            top_risk.append(
                {
                    "command": row["command_text"],
                    "risk": row["risk_score"],
                    "type": row["activity_type"],
                }
            )
        report["threat_stats"]["high_risk_commands"] = top_risk

    except Exception as e:
        report["error"] = str(e)
    finally:
        conn.close()

    print(
        json.dumps(report, indent=2, default=str)
    )  # default=str handles datetime serialization


if __name__ == "__main__":
    generate_report()
