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


from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ... (Previous imports unrelated to output formatting can stay, but we replace the output logic)
# Add project root to sys.path to ensure we can find DB
# Add project root to sys.path to ensure we can find config_manager
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
sys.path.append(os.path.join(PROJECT_ROOT, "ssh_honeypot"))

from dotenv import load_dotenv, find_dotenv
# Load .env explicitly so config_manager sees FAUXSSH_DATA_DIR
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

try:
    from config_manager import get_data_dir
    DB_PATH = os.path.join(get_data_dir(), "honeypot.sqlite")
except ImportError:
    # Fallback if import fails (e.g. structure change)
    DB_PATH = os.path.join(PROJECT_ROOT, "data", "honeypot.sqlite")

def get_db_connection():
    if not os.path.exists(DB_PATH):
        console.print(f"[bold red][!] Database not found at {DB_PATH}[/bold red]")
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def to_local_time(ts_str):
    try:
        if not ts_str: return "-"
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=tz.tzutc())
        local_dt = dt.astimezone(tz.tzlocal())
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ts_str

def clean_ip(ip):
    """Removes ::ffff: prefix from IPv4 mapped addresses."""
    if ip and ip.startswith("::ffff:"):
        return ip.replace("::ffff:", "")
    return ip

def get_risk_style(score):
    if score is None: return "white"
    try:
        s = float(score)
        if s >= 8: return "bold red"
        if s >= 5: return "yellow"
        return "green"
    except:
        return "white"


def list_sessions(limit=50, no_failed=False):
    conn = get_db_connection()
    c = conn.cursor()
    
    # query updated to fetch first/last command times
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
            (SELECT MIN(timestamp) FROM interactions i WHERE i.session_id = s.session_id) as first_cmd,
            (SELECT MAX(timestamp) FROM interactions i WHERE i.session_id = s.session_id) as last_cmd,
            (
                SELECT AVG(ca.risk_score) 
                FROM interactions i 
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash 
                WHERE i.session_id = s.session_id
            ) as avg_risk
        FROM sessions s
    """
    params = []
    # logic for no_failed filtering could go here if implemented in query
    query += " ORDER BY s.start_time DESC LIMIT ?"
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    table = Table(title=f"Recent Sessions (Last {limit})", box=box.SIMPLE)
    table.add_column("Start Time", style="cyan", no_wrap=True)
    table.add_column("IP Address", style="magenta")
    table.add_column("User", style="green")
    table.add_column("Password")
    table.add_column("Client Ver", style="dim")
    table.add_column("FP", style="dim")
    table.add_column("Cmds", justify="right")
    table.add_column("Dur", justify="right", style="yellow")
    table.add_column("Risk", justify="right")
    table.add_column("Session ID", style="dim", no_wrap=True)

    for r in rows:
        start = to_local_time(r['start_time'])
        ip = clean_ip(r['remote_ip'])
        user = r['username']
        pwd = r['password'] or ""
        ver = (r['client_version'] or "").replace("SSH-2.0-", "")[:15]
        
        # Parse Fingerprint nicely
        fp = "-"
        if r['fingerprint']:
            try:
                fp_data = json.loads(r['fingerprint'])
                fp = " captured" 
            except: pass
            
        cmds = str(r['cmd_count'])
        
        # Calculate Duration
        duration_str = "-"
        if r['first_cmd'] and r['last_cmd'] and r['cmd_count'] > 1:
            try:
                # Timestamps are likely strings in DB
                t1 = datetime.strptime(r['first_cmd'], "%Y-%m-%d %H:%M:%S")
                t2 = datetime.strptime(r['last_cmd'], "%Y-%m-%d %H:%M:%S")
                delta = t2 - t1
                # Format to concise string e.g. "1m 30s" or "5s"
                total_seconds = int(delta.total_seconds())
                if total_seconds < 60:
                    duration_str = f"{total_seconds}s"
                else:
                    m, s = divmod(total_seconds, 60)
                    duration_str = f"{m}m {s}s"
            except Exception as e:
                # Fallback if parsing fails
                duration_str = "?"

        risk_val = r['avg_risk']
        risk_str = f"{risk_val:.1f}" if risk_val is not None else "-"
        risk_style = get_risk_style(risk_val)
        
        # Full Session ID requested
        sid = r['session_id']
        
        table.add_row(start, ip, user, pwd, ver, fp, cmds, duration_str, f"[{risk_style}]{risk_str}[/{risk_style}]", sid)

    console.print(table)


def list_commands(limit=50, ip_filter=None, session_filter=None):
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
        WHERE 1=1
    """
    
    params = []
    if ip_filter:
        query += " AND s.remote_ip = ?"
        params.append(ip_filter)
    if session_filter:
        query += " AND i.session_id LIKE ?"
        params.append(f"{session_filter}%")
    
    query += " ORDER BY i.id DESC LIMIT ?"
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    
    table = Table(title=f"Recent Commands (Last {limit})", box=box.ROUNDED)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("IP", style="magenta")
    table.add_column("User", style="green")
    table.add_column("Src", style="yellow")
    table.add_column("Risk", justify="right")
    table.add_column("Command", style="white", overflow="fold") # Enable wrapping
    table.add_column("Analysis", style="italic cyan")

    for r in rows:
        ts = to_local_time(r['timestamp'])
        ip = clean_ip(r['remote_ip']) or "-"
        user = r['username'] or "-"
        src = r['source'] or "-"
        
        risk_val = r['risk_score']
        risk_str = str(risk_val) if risk_val is not None else "-"
        risk_style = get_risk_style(risk_val)
        
        cmd = (r['command'] or "").replace('\r', '').strip()
        expl = (r['explanation'] or "").replace('\n', ' ').strip()
        
        # No more truncation! Rich handles wrapping automatically.

        table.add_row(ts, ip, user, src, f"[{risk_style}]{risk_str}[/{risk_style}]", cmd, expl)
 
    console.print(table)

def reset_failed_analysis():
    conn = get_db_connection()
    c = conn.cursor()
    console.print("[*] Checking for failed analysis records...")
    c.execute("SELECT COUNT(*) FROM command_analysis WHERE explanation LIKE '%Batch Miss%'")
    count = c.fetchone()[0]
    
    if count == 0:
        console.print("[green][+] No failed analysis records found.[/green]")
        conn.close()
        return

    console.print(f"[bold yellow][!] Found {count} failed records.[/bold yellow]")
    confirm = input("Delete? (y/N) ")
    if confirm.lower() == 'y':
        c.execute("DELETE FROM command_analysis WHERE explanation LIKE '%Batch Miss%'")
        conn.commit()
        console.print(f"[green][+] Deleted {c.rowcount} records.[/green]")
    
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="FauxSSH Analytics")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--sessions", action="store_true", help="List recent sessions")
    group.add_argument("--commands", action="store_true", help="List recent commands")
    group.add_argument("--retry-failed", action="store_true", help="Reset failed analysis")
    
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--no-failed", action="store_true")
    parser.add_argument("--ip", help="Filter by IP")
    parser.add_argument("--session-id", help="Filter by Session ID")
    
    args = parser.parse_args()
    
    if args.sessions:
        list_sessions(limit=args.limit, no_failed=args.no_failed)
    elif args.commands:
        list_commands(limit=args.limit, ip_filter=args.ip, session_filter=args.session_id)
    elif args.retry_failed:
        reset_failed_analysis()
    else:
        if args.ip or args.session_id:
            list_commands(limit=args.limit, ip_filter=args.ip, session_filter=args.session_id)
        else:
            list_sessions(limit=args.limit, no_failed=args.no_failed)

if __name__ == "__main__":
    main()

