#!/usr/bin/env python3
import sqlite3
import json
import os
import sys
import time
from datetime import datetime, timedelta

# Find DB path relative to this script
# Find DB path relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
sys.path.append(os.path.join(PROJECT_ROOT, "ssh_honeypot"))


try:
    from config_manager import get_data_dir
    DB_PATH = os.path.join(get_data_dir(), "honeypot.sqlite")
except ImportError:
    DB_PATH = os.path.join(PROJECT_ROOT, "data", "honeypot.sqlite")

def anonymize_ip(ip):
    if not ip: return "unknown"
    if ":" in ip:
        # IPv6: Truncate to first 4 segments? Or just generic mask.
        # Simple approach: keep first 3 words if possible, or just masked
        return "xxxx:xxxx:xxxx:xxxx::200"
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.200"
    return "xxx.xxx.xxx.200"

def get_db():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found at {DB_PATH}", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_report():
    conn = get_db()
    cursor = conn.cursor()
    
    report = {
        "generated_at": datetime.now().isoformat(),
        "status": {},
        "activity": {}
    }
    
    try:
        # 1. General Stats
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE username != 'royans'")
        total_sessions = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM interactions i
            JOIN sessions s ON i.session_id = s.session_id
            WHERE s.username != 'royans'
        """)
        total_commands = cursor.fetchone()[0]
        
        cursor.execute("SELECT MIN(start_time) FROM sessions WHERE username != 'royans'")
        row_min = cursor.fetchone() # returns (None,) if no sessions
        first_seen = row_min[0] if row_min else None
        
        report["status"] = {
            "total_sessions": total_sessions,
            "total_commands": total_commands,
            "tracking_since": first_seen
        }
        
        # 2. Top Requesters (IPs)
        # We look at sessions for unique IPs
        cursor.execute("""
            SELECT remote_ip, COUNT(*) as count 
            FROM sessions 
            WHERE username != 'royans'
            GROUP BY remote_ip 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_ips = []
        for row in cursor.fetchall():
            top_ips.append({
                "ip": anonymize_ip(row["remote_ip"]),
                "count": row["count"]
            })
        report["activity"]["top_ips"] = top_ips
        
        # 3. Top Usernames
        cursor.execute("""
            SELECT username, COUNT(*) as count 
            FROM auth_events 
            WHERE username != 'royans'
            GROUP BY username 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_users = []
        for row in cursor.fetchall():
            top_users.append({
                "username": row["username"],
                "count": row["count"]
            })
        report["activity"]["top_usernames"] = top_users
        
        # 4. Top Commands
        cursor.execute("""
            SELECT i.command, COUNT(*) as count 
            FROM interactions i
            JOIN sessions s ON i.session_id = s.session_id
            WHERE s.username != 'royans'
            GROUP BY i.command 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_cmds = []
        for row in cursor.fetchall():
            top_cmds.append({
                "command": row["command"],
                "count": row["count"]
            })
        report["activity"]["top_commands"] = top_cmds
        
        # 5. Top Client Versions
        cursor.execute("""
            SELECT client_version, COUNT(*) as count 
            FROM sessions 
            WHERE username != 'royans'
            GROUP BY client_version 
            ORDER BY count DESC 
            LIMIT 10
        """)
        top_clients = []
        for row in cursor.fetchall():
            top_clients.append({
                "client": row["client_version"],
                "count": row["count"]
            })
        report["activity"]["top_clients"] = top_clients

        # 6. Recent Sessions
        cursor.execute("""
            SELECT session_id, remote_ip, username, start_time, client_version 
            FROM sessions 
            WHERE username != 'royans'
            ORDER BY start_time DESC 
            LIMIT 5
        """)
        recent_sessions = []
        for row in cursor.fetchall():
            recent_sessions.append({
                "time": row["start_time"],
                "ip": anonymize_ip(row["remote_ip"]),
                "user": row["username"],
                "client": row["client_version"]
            })
        report["activity"]["recent_sessions"] = recent_sessions
        
        # 7. Threat Stats [NEW]
        report["threat_stats"] = {}
        
        # 7a. Activity Type Distribution
        cursor.execute("""
            SELECT activity_type, COUNT(*) as count
            FROM command_analysis
            GROUP BY activity_type
            ORDER BY count DESC
        """)
        activity_dist = []
        for row in cursor.fetchall():
            activity_dist.append({
                "type": row["activity_type"],
                "count": row["count"]
            })
        report["threat_stats"]["activity_distribution"] = activity_dist
        
        # 7b. Top High Risk Commands
        cursor.execute("""
            SELECT command_text, risk_score, activity_type, COUNT(*) as count
            FROM command_analysis
            WHERE risk_score >= 7
            GROUP BY command_text
            ORDER BY risk_score DESC, count DESC
            LIMIT 5
        """)
        top_risk = []
        for row in cursor.fetchall():
            top_risk.append({
                "command": row["command_text"],
                "risk": row["risk_score"],
                "type": row["activity_type"]
            })
        report["threat_stats"]["high_risk_commands"] = top_risk

    except Exception as e:
        report["error"] = str(e)
    finally:
        conn.close()
        
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    generate_report()
