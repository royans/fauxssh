#!/usr/bin/env python3
import hashlib
import sqlite3
import argparse
import os
import sys
import json
import shutil
import textwrap
from datetime import datetime
from dateutil import tz


from rich.console import Console, Group
from rich.table import Table
from rich import box
from rich.text import Text
from rich.rule import Rule

console = Console()

# ... (Previous imports unrelated to output formatting can stay, but we replace the output logic)
# Add project root to sys.path to ensure we can find DB
# Add project root to sys.path to ensure we can find config_manager
# Add project root to sys.path to ensure we can find ssh_honeypot module
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# tools/analytics -> tools -> project_root
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

# Explicitly load .env to match main app behavior
try:
    from dotenv import load_dotenv
    env_path = os.path.join(PROJECT_ROOT, '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    pass

try:
    from ssh_honeypot.core.utils import get_data_dir, get_ignored_ips
    from ssh_honeypot.core.config import config
    # Use the DB_PATH from core database to match app exactly
    from ssh_honeypot.core.database import DB_PATH
except ImportError as e:
    console.print(f"[bold red][!] Import Error: {e}[/bold red]")
    # Fallback/Debug
    DB_PATH = os.path.join(PROJECT_ROOT, "data", "honeypot.sqlite")


def get_db_connection(db_path_override=None):
    path = db_path_override if db_path_override else DB_PATH
    if not os.path.exists(path):
        console.print(f"[bold red][!] Database not found at {path}[/bold red]")
        sys.exit(1)
    conn = sqlite3.connect(path)
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

def clean_ip(ip, anon=False):
    """Removes ::ffff: prefix from IPv4 mapped addresses and optionally masks last octet."""
    if not ip: return "-"
    if ip.startswith("::ffff:"):
        ip = ip.replace("::ffff:", "")
    
    if anon:
        if "." in ip:
            parts = ip.split(".")
            if len(parts) == 4:
                parts[3] = "XXX"
                return ".".join(parts)
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



def parse_sort_param(sort_str, field_map):
    """
    Parses "Field1:Desc,Field2:Asc" into a SQL ORDER BY clause.
    field_map: dict mapping user field names (lowercase) to SQL columns.
    Returns: SQL substring (e.g., "avg_risk DESC, start_time ASC")
    """
    if not sort_str: return None
    
    clauses = []
    for part in sort_str.split(','):
        if ':' in part:
            field, direction = part.split(':', 1)
        else:
            field, direction = part, "ASC"
            
        field = field.strip().lower()
        direction = direction.strip().upper()
        
        if direction not in ("ASC", "DESC"):
            continue
            
        if field in field_map:
            sql_col = field_map[field]
            # Special logic for Unique - it is inverse of cmd_ip_count
            # Unique High (Rare) = Low Count. Desc (High to Low) -> Count ASC
            # Unique Low (Common) = High Count. Asc (Low to High) -> Count DESC
            if field == "unique":
               direction = "ASC" if direction == "DESC" else "DESC"

            clauses.append(f"{sql_col} {direction}")
            
    return ", ".join(clauses) if clauses else None

def list_sessions(limit=50, no_failed=False, anon=False, db_path=None, sort_param=None, ip_filter=None, protocol_filter=None):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    
    query = """
        SELECT 
            s.session_id, 
            s.remote_ip, 
            s.username, 
            s.password,
            s.start_time, 
            s.end_time,
            s.client_version,
            s.client_version,
            s.fingerprint,
            s.protocol,
            (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id) as cmd_count,
            (SELECT MIN(timestamp) FROM interactions i WHERE i.session_id = s.session_id) as first_cmd,
            (SELECT MAX(timestamp) FROM interactions i WHERE i.session_id = s.session_id) as last_cmd,
            (
                SELECT AVG(ca.risk_score) 
                FROM interactions i 
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash 
                WHERE i.session_id = s.session_id
            ) as avg_risk,
            (SELECT group_concat(command, '|||') FROM interactions i WHERE i.session_id = s.session_id) as all_commands,
            s.summary,
            s.risk_score
        FROM sessions s
        WHERE 1=1
    """
    params = []
    
    if protocol_filter:
        query += " AND s.protocol = ?"
        params.append(protocol_filter)
    
    # Filter Ignored IPs
    try:
        ignored = get_ignored_ips()
    except: ignored = []
    
    if ignored:
        placeholders = ','.join(['?'] * len(ignored))
        query += f" AND s.remote_ip NOT IN ({placeholders})"
        params.extend(ignored)

    if ip_filter:
        query += " AND (s.remote_ip = ? OR s.remote_ip = ?)"
        params.append(ip_filter)
        if not ip_filter.startswith("::ffff:"):
            params.append(f"::ffff:{ip_filter}")
        else:
            params.append(ip_filter)

    # Sorting
    # Maps: User Field -> SQL Column
    sort_map = {
        "risk": "s.risk_score",
        "cmds": "cmd_count",
        "time": "s.start_time",
        "ip": "s.remote_ip",
        "user": "s.username",
        "client": "s.client_version", 
        "sessionid": "s.session_id",
        "proto": "s.protocol"
    }
    
    order_clause = parse_sort_param(sort_param, sort_map)
    if order_clause:
         query += f" ORDER BY {order_clause} LIMIT ?"
    else:
         query += " ORDER BY s.start_time DESC LIMIT ?"
         
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()

    table = Table(title=f"Recent Sessions (Last {limit})", box=box.SIMPLE)
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("IP", style="magenta")
    table.add_column("User", style="green")
    table.add_column("Passwd", style="dim")
    table.add_column("Proto", style="cyan")
    table.add_column("Client", style="dim")
    table.add_column("Cmds", justify="right")
    table.add_column("Dur", justify="right", style="yellow")
    table.add_column("Risk", justify="right")
    table.add_column("Summary", style="italic white", overflow="fold")
    table.add_column("SessionID", style="dim", no_wrap=True)

    for r in rows:
        start = to_local_time(r['start_time'])
        ip = clean_ip(r['remote_ip'], anon=anon)
        user = r['username']
        proto = r['protocol'] or "ssh"
             
        # Truncate Password
        pwd = r['password'] or ""
        if len(pwd) > 15: pwd = pwd[:12] + "..."
        
        # Truncate Client
        ver = (r['client_version'] or "").replace("SSH-2.0-", "")
        if len(ver) > 15: ver = ver[:12] + "..."
        
        cmds = str(r['cmd_count'])
        
        # Calculate Duration
        duration_str = "-"
        if r['first_cmd'] and r['last_cmd'] and r['cmd_count'] > 1:
            try:
                t1 = datetime.strptime(r['first_cmd'], "%Y-%m-%d %H:%M:%S")
                t2 = datetime.strptime(r['last_cmd'], "%Y-%m-%d %H:%M:%S")
                delta = t2 - t1
                total_seconds = int(delta.total_seconds())
                if total_seconds < 60:
                    duration_str = f"{total_seconds}s"
                else:
                    m, s = divmod(total_seconds, 60)
                    duration_str = f"{m}m {s}s"
            except: pass
        
        # Risk Priority: Session Risk > Avg Risk
        risk_val = r['risk_score']
        if risk_val is None:
             risk_val = r['avg_risk']
             
        risk_str = f"{risk_val:.1f}" if risk_val is not None else "-"
        risk_style = get_risk_style(risk_val)
        
        summary = r['summary'] or ""
        if len(summary) > 60: # Reduced width to fit new columns
             summary = summary[:57] + "..."
        
        # Full Session ID requested
        sid = r['session_id']
        
        table.add_row(start, ip, user, pwd, proto, ver, cmds, duration_str, f"[{risk_style}]{risk_str}[/{risk_style}]", summary, sid)

    console.print(table)


def list_commands(limit=50, ip_filter=None, session_filter=None, anon=False, db_path=None, sort_param=None, protocol_filter=None, show_output=False):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    
    # 1. Get Total Unique IPs for Unique% Calculation
    try:
        c.execute("SELECT COUNT(DISTINCT remote_ip) FROM sessions")
        total_ips = c.fetchone()[0] or 1 # Avoid div by zero
    except:
        total_ips = 1

    query = """
        SELECT 
            i.timestamp,
            s.remote_ip,
            s.username,
            i.command,
            i.response,
            i.source,
            i.request_md5,
            i.response_size,
            ca.activity_type,
            ca.risk_score,
            ca.explanation,
            (SELECT COUNT(DISTINCT s2.remote_ip) 
             FROM interactions i2 
             JOIN sessions s2 ON i2.session_id = s2.session_id 
             WHERE i2.request_md5 = i.request_md5) as cmd_ip_count
        FROM interactions i
        JOIN sessions s ON i.session_id = s.session_id
        LEFT JOIN command_analysis ca ON i.request_md5 = ca.command_hash
        WHERE 1=1
    """
    
    params = []
    
    # Filter Ignored IPs
    try:
        ignored = get_ignored_ips()
    except: ignored = []
    
    if ignored:
        placeholders = ','.join(['?'] * len(ignored))
        query += f" AND s.remote_ip NOT IN ({placeholders})"
        params.extend(ignored)

    if ip_filter:
        query += " AND (s.remote_ip = ? OR s.remote_ip = ?)"
        params.append(ip_filter)
        if not ip_filter.startswith("::ffff:"):
            params.append(f"::ffff:{ip_filter}")
        else:
            params.append(ip_filter)

    if session_filter:
        query += " AND i.session_id LIKE ?"
        params.append(f"{session_filter}%")
    
    if protocol_filter:
        query += " AND s.protocol = ?"
        params.append(protocol_filter)
    
    # Sorting
    sort_map = {
        "time": "i.timestamp",
        "ip": "s.remote_ip",
        "user": "s.username",
        "unique": "cmd_ip_count", # Logic handled in parse_sort_param
        "risk": "ca.risk_score",
        "src": "i.source"
    }
    
    order_clause = parse_sort_param(sort_param, sort_map)
    
    if order_clause:
        query += f" ORDER BY {order_clause} LIMIT ?"
    else:
        query += " ORDER BY i.id DESC LIMIT ?"
        
    params.append(limit)
    
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    
    table = Table(title=f"Recent Commands (Last {limit})", box=box.ROUNDED)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("IP", style="magenta")
    table.add_column("User", style="green")
    table.add_column("Command", style="white", overflow="fold") # Enable wrapping
    table.add_column("Size", justify="right", style="dim")
    table.add_column("Src", style="yellow")
    table.add_column("Unique%", justify="right", style="bold blue")
    table.add_column("Risk", justify="right")
    table.add_column("Analysis", style="italic cyan", overflow="fold", max_width=60)

    for r in rows:
        ts = to_local_time(r['timestamp'])
        ip = clean_ip(r['remote_ip'], anon=anon) or "-"
        user = r['username'] or "-"
        src = r['source'] or "-"
        
        # New Size Column
        size_val = r['response_size']
        size_str = f"{size_val}" if size_val is not None else "-"
        
        # Calculate Unique%
        # % of IPs that ran this command = cmd_ip_count / total_ips
        # Unique% = 100% - (Freq%)
        # High Unique% = Rare command
        cmd_ip_count = r['cmd_ip_count'] or 0
        freq = cmd_ip_count / total_ips
        unique_pct = (1.0 - freq) * 100.0
        unique_str = f"{unique_pct:.1f}%"
        
        risk_val = r['risk_score']
        risk_str = f"{risk_val}" if risk_val is not None else "-"
        risk_style = get_risk_style(risk_val)
        
        cmd_cell = Text(r['command'] or "")
        
        # Append Output Snippet if requested
        if show_output:
            resp = r['response'] or ""
            if resp:
                 # Truncate response
                 snippet = textwrap.shorten(resp, width=300, placeholder="...")
                 
                 # Use Group + Rule for perfect width handling
                 cmd_cell = Group(
                     cmd_cell,
                     Rule(style="dim"),
                     Text(snippet, style="italic grey50")
                 )

        explanation = r['explanation'] or ""
        # Relaxed truncation to allow wrapping to show more context
        if len(explanation) > 300:
             explanation = textwrap.shorten(explanation, width=300, placeholder="...")

        table.add_row(ts, ip, user, cmd_cell, size_str, src, unique_str, f"[{risk_style}]{risk_str}[/{risk_style}]", explanation)
        
    console.print(table)


def list_top_ips(limit=50, anon=False, db_path=None):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    
    # 1. Total Unique IPs
    try:
        c.execute("SELECT COUNT(DISTINCT remote_ip) FROM sessions")
        total_unique_ips = c.fetchone()[0]
    except: total_unique_ips = 0

    query = """
        SELECT 
            s.remote_ip,
            COUNT(DISTINCT s.session_id) as total_sessions,
            MIN(s.start_time) as first_seen,
            MAX(s.start_time) as last_seen,
            
            -- Total Commands
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip) as total_cmds,
             
            -- Last 1 Hour Activity (Active Attackers)
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip 
             AND i.timestamp > datetime('now', '-1 hour')) as recent_cmds_1h,

            -- Estimated Current RPM (Last 1 Minute) -> Proxy for Suspension Risk
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip 
             AND i.timestamp > datetime('now', '-1 minute')) as current_rpm

        FROM sessions s
        WHERE 1=1
        GROUP BY s.remote_ip
        ORDER BY current_rpm DESC, total_sessions DESC
        LIMIT ?
    """
    
    c.execute(query, (limit,))
    rows = c.fetchall()
    conn.close()

    table = Table(title=f"Top Attacking IPs (Limit {limit}) - Total IPs: {total_unique_ips}", box=box.ROUNDED)
    table.add_column("Rank", style="dim", justify="right")
    table.add_column("IP", style="magenta")
    table.add_column("Sessions", justify="right", style="green")
    table.add_column("Total Cmds", justify="right")
    table.add_column("1h Cmds", justify="right", style="yellow")
    table.add_column("Current RPM", justify="right", style="bold")
    table.add_column("Last Seen", style="dim")
    table.add_column("Status", justify="center")

    rank = 1
    for r in rows:
        ip = clean_ip(r['remote_ip'], anon=anon)
        sessions = r['total_sessions']
        cmds = r['total_cmds']
        recent_1h = r['recent_cmds_1h']
        rpm = r['current_rpm']
        last_seen = to_local_time(r['last_seen'])
        
        # Determine Status/Risk
        # RPM Limit is 1000
        rpm_style = "white"
        status = "Idle"
        status_style = "dim"
        
        if rpm > 0:
            status = "Active"
            status_style = "green"
            
        if rpm >= 1000:
            status = "SUSPENDED (Sim)" # Likely suspended by DoSProtector
            status_style = "bold red reverse"
            rpm_style = "bold red"
        elif rpm >= 800:
            status = "CRITICAL"
            status_style = "bold red"
            rpm_style = "red"
        elif rpm >= 500:
            status = "WARNING"
            status_style = "yellow"
            rpm_style = "yellow"
        elif rpm > 100:
            status = "High Traffic"
            status_style = "bold blue"
            
        table.add_row(
            str(rank),
            ip,
            str(sessions),
            str(cmds),
            str(recent_1h),
            f"[{rpm_style}]{rpm}[/{rpm_style}]",
            last_seen,
            f"[{status_style}]{status}[/{status_style}]"
        )
        rank += 1
        
    console.print(table)
    console.print("[dim]Note: 'Current RPM' is based on DB logs. Actual DoS suspension happens in-memory at 1000 RPM.[/dim]")


def reset_failed_analysis(db_path=None):
    conn = get_db_connection(db_path)
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
    group.add_argument("--top-ips", action="store_true", help="Show Top IPs and Frequency")
    
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--no-failed", action="store_true")
    parser.add_argument("--ip", help="Filter by IP")
    parser.add_argument("--session-id", help="Filter by Session ID")
    parser.add_argument("--anon", action="store_true", help="Mask the last octet of IP addresses")
    parser.add_argument("--db", help="Path to SQLite database file")
    parser.add_argument("--sort", help="Sort order (e.g. Risk:Desc,Cmds:Desc)")
    parser.add_argument("--protocol", help="Filter by protocol (ssh, telnet, redis, mcp)")
    parser.add_argument("--output", action="store_true", help="Show command output snippets")
    
    args = parser.parse_args()
    
    if args.sessions:
        list_sessions(limit=args.limit, no_failed=args.no_failed, anon=args.anon, db_path=args.db, sort_param=args.sort, ip_filter=args.ip, protocol_filter=args.protocol)
    elif args.commands:
        list_commands(limit=args.limit, ip_filter=args.ip, session_filter=args.session_id, anon=args.anon, db_path=args.db, sort_param=args.sort, protocol_filter=args.protocol, show_output=args.output)
    elif args.retry_failed:
        reset_failed_analysis(db_path=args.db)
    elif args.top_ips:
        list_top_ips(limit=args.limit, anon=args.anon, db_path=args.db)
    else:
        if args.ip or args.session_id:
            list_commands(limit=args.limit, ip_filter=args.ip, session_filter=args.session_id, anon=args.anon, db_path=args.db, sort_param=args.sort, protocol_filter=args.protocol, show_output=args.output)
        else:
            list_sessions(limit=args.limit, no_failed=args.no_failed, anon=args.anon, db_path=args.db, sort_param=args.sort, ip_filter=args.ip, protocol_filter=args.protocol)

if __name__ == "__main__":
    main()

