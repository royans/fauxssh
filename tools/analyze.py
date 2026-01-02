#!/usr/bin/env python3
import sqlite3
import argparse
import os
import sys
import json
import shutil
import textwrap
from datetime import datetime
from dateutil import tz

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

def to_local_time(ts_str):
    try:
        if not ts_str: return "-"
        # Assuming TS is UTC or naive stored as UTC
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=tz.tzutc())
        local_dt = dt.astimezone(tz.tzlocal())
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ts_str

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
    
    params = []
    query += " ORDER BY s.start_time DESC LIMIT ?"
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    # Header
    print(f"{'Start Time':<20} | {'IP Address':<15} | {'User':<10} | {'Pwd':<10} | {'Ver':<8} | {'Fp':<8} | {'Cmds':<4} | {'Risk':<4} | {'Session ID'}")
    print("-" * 120)

    for r in rows:
        start = to_local_time(r['start_time'])
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
            s.remote_ip,
            s.username,
            i.command,
            i.source,
            i.request_md5,
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
    
    # Dynamic Width Calculation
    try:
        term_width = shutil.get_terminal_size((120, 20)).columns
    except:
        term_width = 120
    
    # Fixed widths
    w_ts = 20
    w_ip = 15
    w_user = 10
    w_src = 8  # New Source Column
    w_risk = 5
    w_type = 15
    
    # Separators: " | " * 7 = 3 * 7 = 21 chars
    used_width = w_ts + w_ip + w_user + w_src + w_risk + w_type + 21
    remaining = term_width - used_width
    
    if remaining < 40: remaining = 40 # Minimum expectation
    
    # Split remaining roughly 45/55 for Command vs Analysis
    w_cmd = int(remaining * 0.45)
    w_expl = int(remaining * 0.55)
    
    # Ensure minimums
    if w_cmd < 20: w_cmd = 20
    if w_expl < 20: w_expl = 20
    
    print(f"{'Timestamp':<{w_ts}} | {'IP':<{w_ip}} | {'User':<{w_user}} | {'Src':<{w_src}} | {'Risk':<{w_risk}} | {'Type':<{w_type}} | {'Command':<{w_cmd}} | {'Analysis'}")
    print("-" * term_width)
    
    for r in rows:
        ts = to_local_time(r['timestamp'])
        ip = r['remote_ip']
        user = r['username']
        src = (r['source'] or "UNK")[:8] # Limit to 8 chars (e.g. "LLM", "Local", "Chain")
        risk = str(r['risk_score']) if r['risk_score'] is not None else "-"
        atype = r['activity_type'] if r['activity_type'] else "-"
        cmd = r['command'].replace('\r', '')
        expl = (r['explanation'] or "").replace('\n', ' ')
        
        # Wrapping logic
        # We wrap command and indent subsequent lines
        cmd_wrapper = textwrap.TextWrapper(width=w_cmd, subsequent_indent='  ')
        cmd_lines = cmd_wrapper.wrap(cmd) if cmd else [""]
        
        expl_wrapper = textwrap.TextWrapper(width=w_expl)
        expl_lines = expl_wrapper.wrap(expl) if expl else [""]
        
        # Max of lines to determine height of row
        height = max(len(cmd_lines), len(expl_lines))
        
        # Calculate offset for Command column padding
        # Widths: TS(20) | IP(15) | User(10) | Src(8) | Risk(5) | Type(15) |
        # Separators: 6 * 3 chars = 18 chars
        # 20+15+10+8+5+15 = 73 + 18 = 91
        cmd_offset_len = w_ts + w_ip + w_user + w_src + w_risk + w_type + 18
        cmd_padding = " " * cmd_offset_len
        
        for i in range(height):
            c_line = cmd_lines[i] if i < len(cmd_lines) else ""
            e_line = expl_lines[i] if i < len(expl_lines) else ""
            
            if i == 0:
                print(f"{ts:<{w_ts}} | {ip:<{w_ip}} | {user:<{w_user}} | {src:<{w_src}} | {risk:<{w_risk}} | {atype:<{w_type}} | {c_line:<{w_cmd}} | {e_line}")
            else:
                # Clean Indent
                print(f"{cmd_padding} | {c_line:<{w_cmd}} | {e_line}")
        
    print(f"\n[!] Showing last {limit} commands.")

def reset_failed_analysis():
    conn = get_db_connection()
    c = conn.cursor()
    
    print("[*] Checking for failed analysis records ('Batch Miss')...")
    c.execute("SELECT COUNT(*) FROM command_analysis WHERE explanation LIKE '%Batch Miss%'")
    count = c.fetchone()[0]
    
    if count == 0:
        print("[+] No failed analysis records found. Nothing to reset.")
        conn.close()
        return

    print(f"[!] Found {count} failed records.")
    confirm = input(f"Are you sure you want to DELETE them so they can be re-analyzed? (y/N) ")
    
    if confirm.lower() == 'y':
        c.execute("DELETE FROM command_analysis WHERE explanation LIKE '%Batch Miss%'")
        conn.commit()
        print(f"[+] Deleted {c.rowcount} records. The server will pick them up automatically.")
    else:
        print("[-] Operation cancelled.")
    
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="FauxSSH Unified Analytics Tool")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sessions", action="store_true", help="List recent sessions (default)")
    group.add_argument("--commands", action="store_true", help="List recent commands with analysis")
    group.add_argument("--retry-failed", action="store_true", help="Delete 'Batch Miss' records to trigger re-analysis")
    
    parser.add_argument("--limit", type=int, default=50, help="Number of rows to show (default: 50)")
    parser.add_argument("--no-failed", action="store_true", help="Filter out failed logins (for sessions)")
    
    args = parser.parse_args()
    
    if args.sessions:
        list_sessions(limit=args.limit, no_failed=args.no_failed)
    elif args.commands:
        list_commands(limit=args.limit)
    elif args.retry_failed:
        reset_failed_analysis()
    else:
        list_sessions(limit=args.limit)

if __name__ == "__main__":
    main()
