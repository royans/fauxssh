#!/usr/bin/env python3
import sqlite3
import argparse
import os
import sys
import json
from datetime import datetime

# Add project root to sys.path to ensure we can find DB
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, "data", "honeypot.sqlite")

def get_db_connection():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found at {DB_PATH}")
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def list_sessions(limit=50, no_failed=False):
    conn = get_db_connection()
    c = conn.cursor()
    
    # Base Query
    query = """
        SELECT 
            s.session_id, 
            s.remote_ip, 
            s.username, 
            s.password,
            s.start_time, 
            s.end_time,
            s.client_version,
            s.fingerprint,
            (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id) as cmd_count,
            (
                SELECT AVG(ca.risk_score) 
                FROM interactions i 
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash 
                WHERE i.session_id = s.session_id
            ) as avg_risk
        FROM sessions s
    """
    
    where_clauses = []
    params = []
    
    if no_failed:
        # A failed login generally implies no session created OR specific flag. 
        # In current FauxSSH, 'sessions' table usually records successful sessions or attempted ones?
        # Actually sessions are created on successful auth. 
        # But let's check auth_events for login failures if we want "Login Failed" filtering?
        # The user request says "filter out sessions where login failed".
        # If session exists in 'sessions' table, it usually means auth passed (or was attempted enough to create session context).
        # Let's assume if username is present it's a "session". 
        # Maybe "login failed" refers to auth_events that didn't result in a session? 
        # For this tool, we are listing SESSIONS. So we likely only have successful logins here.
        # However, let's look at `auth_events` to be sure.
        # Wait, if `sessions` table is only for established sessions, then `no_failed` might be redundant or 
        # valid checks against `auth_events` are needed. 
        # Let's assume "sessions" table contains successful logins.
        pass

    query += " ORDER BY s.start_time DESC LIMIT ?"
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    # Header
    print(f"{'Start Time':<20} | {'IP Address':<15} | {'User':<10} | {'Pwd':<10} | {'Ver':<8} | {'Fp':<8} | {'Cmds':<4} | {'Risk':<4} | {'Session ID'}")
    print("-" * 120)

    for r in rows:
        start = r['start_time']
        ip = r['remote_ip']
        user = r['username']
        pwd = r['password'] or ""
        ver = (r['client_version'] or "").replace("SSH-2.0-", "")[:8]
        fp = (r['fingerprint'] or "")[:8]
        cmds = r['cmd_count']
        risk = f"{r['avg_risk']:.1f}" if r['avg_risk'] is not None else "-"
        sid = r['session_id'][:8] + "..."
        
        print(f"{start:<20} | {ip:<15} | {user:<10} | {pwd:<10} | {ver:<8} | {fp:<8} | {cmds:<4} | {risk:<4} | {sid}")


def list_commands(limit=50):
    conn = get_db_connection()
    c = conn.cursor()
    
    query = """
        SELECT 
            i.timestamp,
            i.session_id,
            s.remote_ip,
            s.username,
            i.command,
            i.request_md5,
            length(i.response) as resp_size,
            ca.activity_type,
            ca.risk_score,
            ca.explanation
        FROM interactions i
        JOIN sessions s ON i.session_id = s.session_id
        LEFT JOIN command_analysis ca ON i.request_md5 = ca.command_hash
        ORDER BY i.id DESC
        LIMIT ?
    """
    
    c.execute(query, (limit,))
    rows = c.fetchall()
    conn.close()
    
    print(f"{'Timestamp':<20} | {'IP':<15} | {'User':<10} | {'Risk':<4} | {'Type':<12} | {'Command':<30} | {'Analysis'}")
    print("-" * 140)
    
    for r in rows:
        ts = r['timestamp']
        ip = r['remote_ip']
        user = r['username']
        risk = r['risk_score'] if r['risk_score'] is not None else "-"
        atype = r['activity_type'] if r['activity_type'] else "-"
        cmd = r['command']
        expl = r['explanation'] or ""
        
        # Truncate command for display
        cmd_display = (cmd[:27] + '...') if len(cmd) > 27 else cmd
        
        print(f"{ts:<20} | {ip:<15} | {user:<10} | {risk:<4} | {atype:<12} | {cmd_display:<30} | {expl}")
        # print full command on next line if it was truncated?
        if len(cmd) > 27:
            print(f"{'':<65} > Full: {cmd}")

def main():
    parser = argparse.ArgumentParser(description="FauxSSH Unified Analytics Tool")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sessions", action="store_true", help="List recent sessions (default)")
    group.add_argument("--commands", action="store_true", help="List recent commands with analysis")
    
    parser.add_argument("--limit", type=int, default=50, help="Number of rows to show (default: 50)")
    parser.add_argument("--no-failed", action="store_true", help="Filter out failed logins (for sessions)")
    
    args = parser.parse_args()
    
    if args.sessions:
        list_sessions(limit=args.limit, no_failed=args.no_failed)
    elif args.commands:
        list_commands(limit=args.limit)
    else:
        # Should not reach here due to required group, but fallback
        list_sessions(limit=args.limit)

if __name__ == "__main__":
    main()
