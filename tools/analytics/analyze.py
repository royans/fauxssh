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
from dateutil import tz, parser


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

    env_path = os.path.join(PROJECT_ROOT, ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    pass

try:
    from ssh_honeypot.core.utils import get_data_dir, get_ignored_ips
    from ssh_honeypot.core.config import config
    from ssh_honeypot.core.database import get_db_backend
except ImportError as e:
    console.print(f"[bold red][!] Import Error: {e}[/bold red]")
    sys.exit(1)


def get_db_connection(db_path_override=None):
    # If path override is provided, assume SQLite for backward compat or manual file checks
    if db_path_override:
        conn = sqlite3.connect(db_path_override)
        conn.row_factory = sqlite3.Row
        return conn, "?"

    # Use central factory
    db = get_db_backend()
    conn = db._get_conn()

    # If using psycopg2 (Postgres), we might need to set row_factory or equivalent if not using RealDictCursor.
    # PostgresBackend._get_conn returns raw connection.
    # psycopg2 needs extras.RealDictCursor for dictionary-like access.
    # Let's inspect connection type or just handle it.

    # Check for placeholder
    ph = getattr(db, "placeholder", "?")

    # If wrapper needed for Row-like access?
    # SSHPot logic usually uses tuples for fetching unless row_factory set.
    # But analyze.py heavily uses r["column"] access.
    # So we MUST ensure the cursor yields dict-like objects.

    # Robustness: Force Row/Cursor Factory based on connection type
    conn_type = str(type(conn))
    if "sqlite3" in conn_type:
        conn.row_factory = sqlite3.Row
        ph = "?"  # Force SQLite placeholder
    elif "psycopg2" in conn_type:
        import psycopg2.extras

        conn.cursor_factory = psycopg2.extras.RealDictCursor
        ph = "%s"

    return conn, ph


def to_local_time(ts_str):
    try:
        if not ts_str:
            return "-"
        if isinstance(ts_str, datetime):
            dt = ts_str
        else:
            # parsing with dateutil is more robust (handles microseconds, T, etc)
            dt = parser.parse(str(ts_str))

        # If naive, assume it's already local (since Postgres/SQLite defaults often stick to server time)
        # We ensure it's timezone-aware for consistency if needed, or just return formatted string.
        # But to be safe if it *was* UTC, we'd need to know source.
        # Given user request, we assume stored time = local time or user wants to see stored time as is.
        if dt.tzinfo is None:
            # Assume local system time (since DB seems to store local naive)
            dt = dt.replace(tzinfo=tz.tzlocal())

        # Convert to local (no-op if already matching local)
        local_dt = dt.astimezone(tz.tzlocal())
        return local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts_str)


def clean_ip(ip, anon=False):
    """Removes ::ffff: prefix from IPv4 mapped addresses and optionally masks last octet."""
    if not ip:
        return "-"
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
    if score is None:
        return "white"
    try:
        s = float(score)
        if s >= 8:
            return "bold red"
        if s >= 5:
            return "yellow"
        return "green"
    except:
        return "white"


def parse_sort_param(sort_str, field_map):
    """
    Parses "Field1:Desc,Field2:Asc" into a SQL ORDER BY clause.
    field_map: dict mapping user field names (lowercase) to SQL columns.
    Returns: SQL substring (e.g., "avg_risk DESC, start_time ASC")
    """
    if not sort_str:
        return None

    clauses = []
    for part in sort_str.split(","):
        if ":" in part:
            field, direction = part.split(":", 1)
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


def list_sessions(
    limit=50,
    no_failed=False,
    anon=False,
    db_path=None,
    sort_param=None,
    ip_filter=None,
    protocol_filter=None,
):
    conn, ph = get_db_connection(db_path)
    c = conn.cursor()

    # Dialect-specific aggregation
    agg_func = "STRING_AGG" if ph == "%s" else "group_concat"

    query = f"""
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
            s.fingerprint,
            s.protocol,
            (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id) as cmd_count,
            (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id AND i.source = 'llm') as llm_count,
            (SELECT MIN(timestamp) FROM interactions i WHERE i.session_id = s.session_id) as first_cmd,
            (SELECT MAX(timestamp) FROM interactions i WHERE i.session_id = s.session_id) as last_cmd,
            (
                SELECT AVG(ca.risk_score) 
                FROM interactions i 
                JOIN command_analysis ca ON i.request_md5 = ca.command_hash 
                WHERE i.session_id = s.session_id
            ) as avg_risk,
            (SELECT {agg_func}(command, '|||') FROM interactions i WHERE i.session_id = s.session_id) as all_commands,
            s.summary,
            s.risk_score,
            ii.country,
            ii.org,
            ii.network_type,
            ii.abuse_tags
        FROM sessions s
        LEFT JOIN ip_intelligence ii ON s.remote_ip = ii.ip
        WHERE 1=1
    """
    params = []

    if protocol_filter:
        query += f" AND s.protocol = {ph}"
        params.append(protocol_filter)

    # Filter Ignored IPs
    try:
        ignored = get_ignored_ips()
    except:
        ignored = []

    if ignored:
        placeholders = ",".join([ph] * len(ignored))
        query += f" AND s.remote_ip NOT IN ({placeholders})"
        params.extend(ignored)

    if ip_filter:
        query += f" AND (s.remote_ip = {ph} OR s.remote_ip = {ph})"
        params.append(ip_filter)
        if not ip_filter.startswith("::ffff:"):
            params.append(f"::ffff:{ip_filter}")
        else:
            params.append(ip_filter)

    # Filter 0-Command Sessions (Connection Checks) by default
    # User can override with FAUXSSH_ANALYTICS_SHOW_EMPTY=true
    show_empty = (
        str(os.getenv("FAUXSSH_ANALYTICS_SHOW_EMPTY", "false")).lower() == "true"
    )
    if not show_empty:
        # Filter based on interactions count using a subquery in WHERE
        # HAVING requires GROUP BY in SQLite, so we must repeat the subquery condition
        query += " AND (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id) > 0"

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
        "proto": "s.protocol",
    }

    order_clause = parse_sort_param(sort_param, sort_map)
    if order_clause:
        query += f" ORDER BY {order_clause} LIMIT {ph}"
    else:
        query += f" ORDER BY s.start_time DESC LIMIT {ph}"

    params.append(limit)

    if ph == "%s":
        import psycopg2.extras

        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        c = conn.cursor()

    c.execute(query, tuple(params))
    rows = c.fetchall()
    conn.close()

    table = Table(title=f"Recent Sessions (Last {limit})", box=box.SIMPLE)
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("IP", style="magenta")
    table.add_column("User / HTTP Request", style="green")
    # table.add_column("Passwd", style="dim")  # Hidden by request
    table.add_column("Proto", style="cyan")
    table.add_column("Client", style="dim")
    table.add_column("Cmds", justify="right")
    table.add_column("LLMs", justify="right", style="cyan")
    table.add_column("Dur", justify="right", style="yellow")
    table.add_column("Geo", style="blue")
    table.add_column("ISP/Type", style="dim")
    table.add_column("Risk", justify="right")
    table.add_column("Summary", style="italic white", overflow="fold")
    table.add_column("SessionID", style="dim", no_wrap=True)

    for r in rows:
        start = to_local_time(r["start_time"])
        ip = clean_ip(r["remote_ip"], anon=anon)
        user = r["username"]
        proto = r["protocol"] or "ssh"

        # Special handling for HTTP to show Method+URL
        if proto == "http":
            all_cmds = r["all_commands"]
            if all_cmds:
                # Take the first command
                first_req = all_cmds.split("|||")[0]
                # If it's pure GET, strip it to save space? User asked for "Method if not Get".
                # But "Show URL in User including Method if its not Get".
                if " GET " in first_req:
                    # Strip "HTTP GET " prefix if present or similar
                    # Format is "HTTP GET /path" usually from server.py logic
                    user = first_req.replace("HTTP GET ", "").strip()
                else:
                    user = first_req.replace("HTTP ", "").strip()  # Keep Method

                # Truncate
                if len(user) > 50:
                    user = user[:47] + "..."

        # Truncate Password (unused now but kept variable if needed)
        pwd = r["password"] or ""
        # if len(pwd) > 15:
        #     pwd = pwd[:12] + "..."

        # Truncate Client
        ver = (r["client_version"] or "").replace("SSH-2.0-", "")
        if len(ver) > 15:
            ver = ver[:12] + "..."

        cmds = str(r["cmd_count"])
        llms = str(r["llm_count"])

        # Calculate Duration
        duration_str = "-"
        if r["first_cmd"] and r["last_cmd"] and r["cmd_count"] > 1:
            try:
                t1 = r["first_cmd"]
                t2 = r["last_cmd"]

                if not isinstance(t1, datetime):
                    t1 = datetime.strptime(t1, "%Y-%m-%d %H:%M:%S")
                if not isinstance(t2, datetime):
                    t2 = datetime.strptime(t2, "%Y-%m-%d %H:%M:%S")

                delta = t2 - t1
                total_seconds = int(delta.total_seconds())
                if total_seconds < 60:
                    duration_str = f"{total_seconds}s"
                else:
                    m, s = divmod(total_seconds, 60)
                    duration_str = f"{m}m {s}s"
            except:
                pass

        # Risk Priority: Session Risk > Avg Risk
        risk_val = r["risk_score"]
        if risk_val is None:
            risk_val = r["avg_risk"]

        risk_str = f"{risk_val:.1f}" if risk_val is not None else "-"
        risk_style = get_risk_style(risk_val)

        summary = r["summary"] or ""
        if len(summary) > 60:  # Reduced width to fit new columns
            summary = summary[:57] + "..."

        # Full Session ID requested
        sid = r["session_id"]

        # Geo Info
        geo = r["country"] or "-"
        isp = r["org"] or r["network_type"] or "-"
        if len(isp) > 20:
            isp = isp[:17] + "..."

        tags = r["abuse_tags"]
        if tags and tags != "[]":
            risk_str += " !"  # Flag abuse tags

        table.add_row(
            start,
            ip,
            user,
            # pwd, # Passwd hidden
            proto,
            ver,
            cmds,
            llms,
            duration_str,
            geo,
            isp,
            f"[{risk_style}]{risk_str}[/{risk_style}]",
            summary,
            sid,
        )

    console.print(table)


def list_commands(
    limit=50,
    ip_filter=None,
    session_filter=None,
    anon=False,
    db_path=None,
    sort_param=None,
    protocol_filter=None,
    show_output=False,
):
    conn, ph = get_db_connection(db_path)
    # Ensure cursor factory
    if ph == "%s":
        import psycopg2.extras

        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        c = conn.cursor()

    # 1. Get Total Unique IPs for Unique% Calculation
    try:
        c.execute("SELECT COUNT(DISTINCT remote_ip) FROM sessions")
        total_ips = c.fetchone()["count"] if ph == "%s" else c.fetchone()[0]
        # Postgres returns dict with RealDictCursor, SQLite returns Row (indexable) or tuple?
        # Row is indexable by name too.
        # But wait, fetchone()[0] works for Row if it behaves like tuple.
        # RealDictCursor returns dict, so [0] fails.
        # Safe way: list(row.values())[0] or use alias?
        # Let's fix the query to have an alias.
    except:
        total_ips = 1

    # Fix query to have alias
    try:
        c.execute("SELECT COUNT(DISTINCT remote_ip) as cnt FROM sessions")
        row = c.fetchone()
        if row:
            if isinstance(row, dict):
                total_ips = row["cnt"]
            else:
                total_ips = row[0]  # SQLite Row supports index or name
        else:
            total_ips = 1
    except:
        total_ips = 1

    if not total_ips:
        total_ips = 1

    query = f"""
        SELECT 
            i.timestamp,
            s.remote_ip,
            s.protocol,
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

    try:
        ignored = get_ignored_ips()
    except:
        ignored = []

    if ignored:
        placeholders = ",".join([ph] * len(ignored))
        query += f" AND s.remote_ip NOT IN ({placeholders})"
        params.extend(ignored)

    if ip_filter:
        query += f" AND (s.remote_ip = {ph} OR s.remote_ip = {ph})"
        params.append(ip_filter)
        if not ip_filter.startswith("::ffff:"):
            params.append(f"::ffff:{ip_filter}")
        else:
            params.append(ip_filter)

    if session_filter:
        query += f" AND i.session_id LIKE {ph}"
        params.append(f"{session_filter}%")

    if protocol_filter:
        query += f" AND s.protocol = {ph}"
        params.append(protocol_filter)

    sort_map = {
        "time": "i.timestamp",
        "ip": "s.remote_ip",
        "user": "s.username",
        "unique": "cmd_ip_count",
        "risk": "ca.risk_score",
        "src": "i.source",
    }
    order_clause = parse_sort_param(sort_param, sort_map)

    if order_clause:
        query += f" ORDER BY {order_clause} LIMIT {ph}"
    else:
        query += f" ORDER BY i.id DESC LIMIT {ph}"

    params.append(limit)

    c.execute(query, tuple(params))
    rows = c.fetchall()
    conn.close()

    table = Table(title=f"Recent Commands (Last {limit})", box=box.ROUNDED)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("IP", style="magenta")
    table.add_column("Proto", style="cyan")
    table.add_column("User", style="green")
    table.add_column("Command", style="white", overflow="fold")  # Enable wrapping
    table.add_column("Size", justify="right", style="dim")
    table.add_column("Src", style="yellow")
    table.add_column("Unique%", justify="right", style="bold blue")
    table.add_column("Risk", justify="right")
    table.add_column("Analysis", style="italic cyan", overflow="fold", max_width=60)

    for r in rows:
        ts = to_local_time(r["timestamp"])
        ip = clean_ip(r["remote_ip"], anon=anon) or "-"
        proto = r["protocol"] or "-"
        user = r["username"] or "-"
        src = r["source"] or "-"

        # New Size Column
        size_val = r["response_size"]
        size_str = f"{size_val}" if size_val is not None else "-"

        # Calculate Unique%
        # % of IPs that ran this command = cmd_ip_count / total_ips
        # Unique% = 100% - (Freq%)
        # High Unique% = Rare command
        cmd_ip_count = r["cmd_ip_count"] or 0
        freq = cmd_ip_count / total_ips
        unique_pct = (1.0 - freq) * 100.0
        unique_str = f"{unique_pct:.1f}%"

        risk_val = r["risk_score"]
        risk_str = f"{risk_val}" if risk_val is not None else "-"
        risk_style = get_risk_style(risk_val)

        cmd_text = r["command"] or ""
        cmd_styled = Text(cmd_text)

        # Highlight Non-GET HTTP Requests
        if cmd_text.startswith("HTTP ") and " GET " not in cmd_text:
            cmd_styled.stylize("bold magenta")

        cmd_cell = cmd_styled

        # Append Output Snippet if requested
        if show_output:
            resp = r["response"] or ""
            if resp:
                # Truncate response
                snippet = textwrap.shorten(resp, width=300, placeholder="...")

                # Use Group + Rule for perfect width handling
                cmd_cell = Group(
                    cmd_cell, Rule(style="dim"), Text(snippet, style="italic grey50")
                )

        explanation = r["explanation"] or ""
        # Relaxed truncation to allow wrapping to show more context
        if len(explanation) > 300:
            explanation = textwrap.shorten(explanation, width=300, placeholder="...")

        table.add_row(
            ts,
            ip,
            proto,
            user,
            cmd_cell,
            size_str,
            src,
            unique_str,
            f"[{risk_style}]{risk_str}[/{risk_style}]",
            explanation,
        )

    console.print(table)


def list_top_ips(limit=50, anon=False, db_path=None):
    conn, ph = get_db_connection(db_path)
    # Ensure cursor factory
    if ph == "%s":
        import psycopg2.extras

        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        c = conn.cursor()

    # Get total unique IPs for stats
    try:
        c.execute("SELECT COUNT(DISTINCT remote_ip) as cnt FROM sessions")
        row = c.fetchone()
        if hasattr(row, "keys") and "cnt" in row:
            total_unique_ips = row["cnt"]
        elif isinstance(row, dict) and "cnt" in row:
            total_unique_ips = row["cnt"]
        elif row:
            total_unique_ips = row[0]
        else:
            total_unique_ips = 0
    except:
        total_unique_ips = 0

    query = f"""
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
             -- Note: datetime('now') is SQLite specific. 
             -- Postgres uses NOW() or CURRENT_TIMESTAMP.
             -- Fixed below via regex or replacement if needed? 
             -- Actually, PostgresBackend might need to install 'datetime' function/compatibility?
             -- Or we blindly replace datetime usage.
             
            -- Estimated Current RPM
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip 
             AND i.timestamp > datetime('now', '-1 minute')) as current_rpm,

            -- LLM Usage 1h
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip 
             AND i.source = 'llm'
             AND i.timestamp > datetime('now', '-1 hour')) as llm_1h,

            -- LLM Usage 24h
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip 
             AND i.source = 'llm'
             AND i.timestamp > datetime('now', '-24 hours')) as llm_24h,

             ii.country,
             ii.org

        FROM sessions s
        LEFT JOIN ip_intelligence ii ON s.remote_ip = ii.ip
        WHERE 1=1
        GROUP BY s.remote_ip, ii.country, ii.org
        -- Group By must include all non-agg columns in standard SQL (Postgres strictness)
        ORDER BY current_rpm DESC, total_sessions DESC
        LIMIT {ph}
    """

    # Postgres Compatibility Fixes
    if ph == "%s":
        # Replace SQLite datetime calls with Postgres equivalent
        # SQLite: datetime('now', '-1 hour')
        # Postgres: NOW() - INTERVAL '1 hour'
        query = query.replace(
            "datetime('now', '-1 hour')", "(NOW() - INTERVAL '1 hour')"
        )
        query = query.replace(
            "datetime('now', '-24 hours')", "(NOW() - INTERVAL '24 hours')"
        )
        query = query.replace(
            "datetime('now', '-1 minute')", "(NOW() - INTERVAL '1 minute')"
        )
        # Ensure 'current_rpm' and others are usable in ORDER BY (standard SQL supports alias in ORDER BY, but GROUP BY requirements are strict)

    c.execute(query, (limit,))
    rows = c.fetchall()
    conn.close()

    table = Table(
        title=f"Top Attacking IPs (Limit {limit}) - Total IPs: {total_unique_ips}",
        box=box.ROUNDED,
    )
    table.add_column("Rank", style="dim", justify="right")
    table.add_column("IP", style="magenta")
    table.add_column("Sessions", justify="right", style="green")
    table.add_column("Total Cmds", justify="right")
    table.add_column("LLM (1h/24h)", justify="right", style="cyan")
    table.add_column(
        "Latest Cmds", justify="right", style="yellow"
    )  # Renamed for space
    table.add_column("RPM", justify="right", style="bold")
    table.add_column("Location", style="blue")
    table.add_column("Last Seen", style="dim")
    table.add_column("Status", justify="center")

    rank = 1
    for r in rows:
        ip = clean_ip(r["remote_ip"], anon=anon)
        sessions = r["total_sessions"]
        cmds = r["total_cmds"]
        recent_1h = r["recent_cmds_1h"]
        llm_1h = r["llm_1h"]
        llm_24h = r["llm_24h"]
        rpm = r["current_rpm"]
        last_seen = to_local_time(r["last_seen"])

        # Determine Status/Risk
        # RPM Limit is 1000
        rpm_style = "white"
        status = "Idle"
        status_style = "dim"

        if rpm > 0:
            status = "Active"
            status_style = "green"

        if rpm >= 1000:
            status = "SUSPENDED (Sim)"  # Likely suspended by DoSProtector
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

        loc = f"{r['country'] or '?'} / {r['org'] or '?'}"
        if len(loc) > 30:
            loc = loc[:27] + "..."

        table.add_row(
            str(rank),
            ip,
            str(sessions),
            str(cmds),
            f"{llm_1h}/{llm_24h}",
            str(recent_1h),
            f"[{rpm_style}]{rpm}[/{rpm_style}]",
            loc,
            last_seen,
            f"[{status_style}]{status}[/{status_style}]",
        )
        rank += 1

    console.print(table)
    console.print(
        "[dim]Note: 'Current RPM' is based on DB logs. Actual DoS suspension happens in-memory at 1000 RPM.[/dim]"
    )


def list_payloads(limit=50, anon=False, db_path=None, show_all=False):
    conn, ph = get_db_connection(db_path)
    # conn.row_factory set in get_db_connection if SQLite, else RealDictCursor for PG
    # Ensure cursor factory
    if ph == "%s":
        import psycopg2.extras

        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        c = conn.cursor()

    # Dialect-specific aggregation
    agg_func = "STRING_AGG" if ph == "%s" else "group_concat"

    query = f"""
        SELECT 
            p.id,
            p.timestamp,
            p.url,
            p.status,
            p.payload_md5,
            p.payload_size,
            p.file_path,
            p.ip as first_ip,
            (SELECT {agg_func}(DISTINCT ip, ', ') FROM payload_requests pr WHERE pr.payload_id = p.id) as all_ips,
            p.session_id,
            p.session_id,
            p.error_message,
            p.virustotal_result,
            p.vt_last_scanned
        FROM malicious_payloads p

        ORDER BY p.timestamp DESC
        LIMIT {ph}
    """

    c.execute(query, (limit,))
    rows = c.fetchall()
    conn.close()

    table = Table(title=f"Malicious Payloads (Last {limit})", box=box.ROUNDED)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("URL", style="blue underline", overflow="fold")
    table.add_column("Score", style="bold")
    table.add_column("Details", style="dim", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("IPs", style="magenta")

    for r in rows:
        ts = to_local_time(r["timestamp"])

        # Combine first IP (legacy/backup) with new list if new table empty?
        # Ideally all_ips covers it. But for safety:
        ips_str = r["all_ips"]
        if not ips_str:
            ips_str = r["first_ip"]  # Fallback for old records

        # Clean IPs
        ip_list = (
            [clean_ip(ip.strip(), anon=anon) for ip in ips_str.split(",")]
            if ips_str
            else []
        )
        # Unique valid IPs
        ip_list = sorted(list(set([ip for ip in ip_list if ip and ip != "-"])))

        # Format for display (truncate if too many)
        if len(ip_list) > 3:
            display_ip = f"{', '.join(ip_list[:2])} (+{len(ip_list)-2})"
        else:
            display_ip = ", ".join(ip_list)

        status = r["status"]
        status_style = "white"
        if status == "completed":
            status_style = "green"
        elif status == "failed":
            status_style = "red"
        elif status == "pending":
            status_style = "yellow"
        elif status == "downloading":
            status_style = "cyan blink"

        if not show_all:
            if status == "failed":
                continue
            if r["payload_size"] and r["payload_size"] < 500:
                continue

        # VirusTotal Info
        vt_score_str = "-"
        details = r["payload_md5"] or ""

        vt_res = r["virustotal_result"]
        if vt_res and vt_res.startswith("{"):
            try:
                import json

                j = json.loads(vt_res)
                if "error" in j:
                    # Handle fallback error JSON from PayloadManager
                    vt_score_str = "[bold red]Err[/bold red]"
                    details = f"[red]{j.get('error')}[/red]"
                else:
                    stats = j.get("stats")
                    if stats:
                        malicious = stats.get("malicious", 0)
                        tot = sum(stats.values())

                        color = "green"
                        if malicious > 0:
                            color = "yellow"
                        if malicious > 5:
                            color = "red"
                        if malicious > 20:
                            color = "bold red"

                        vt_score_str = f"[{color}]{malicious}/{tot}[/{color}]"

                    tags = j.get("tags", [])

                # Details Priority: Error > Code Insights > Meaningful Name > Threat Label > Tags > MD5
                m_name = j.get("meaningful_name")
                code_insights = j.get("code_insights")

                classification = j.get("classification", {})
                t_label = classification.get("suggested_threat_label")

                if code_insights:
                    # Truncate insight if too long
                    if len(code_insights) > 80:
                        code_insights = code_insights[:77] + "..."
                    details = f"[bold cyan]{code_insights}[/bold cyan]"
                elif m_name:
                    details = f"[bold red]{m_name}[/bold red]"
                elif t_label:
                    details = f"[red]{t_label}[/red]"
                elif tags:
                    details = f"{', '.join(tags[:3])}"

            except:
                pass
        elif vt_res == "skipped_size":
            vt_score_str = "[dim]Too Small[/dim]"

        if r["error_message"]:
            details = f"[red]{r['error_message']}[/red]"

        size_str = "-"
        if r["payload_size"]:
            size = r["payload_size"]
            if size < 1024:
                size_str = f"{size} B"
            else:
                size_str = f"{size/1024:.1f} KB"

        table.add_row(
            ts,
            f"[{status_style}]{status.upper()}[/{status_style}]",
            r["url"],
            vt_score_str,
            details,
            size_str,
            display_ip,
        )

    console.print(table)
    console.print(f"[dim]Files are located in: data/payloads/[/dim]")


def reset_failed_analysis(db_path=None):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    console.print("[*] Checking for failed analysis records...")
    c.execute(
        "SELECT COUNT(*) FROM command_analysis WHERE explanation LIKE '%Batch Miss%'"
    )
    count = c.fetchone()[0]

    if count == 0:
        console.print("[green][+] No failed analysis records found.[/green]")
        conn.close()
        return

    console.print(f"[bold yellow][!] Found {count} failed records.[/bold yellow]")
    confirm = input("Delete? (y/N) ")
    if confirm.lower() == "y":
        c.execute("DELETE FROM command_analysis WHERE explanation LIKE '%Batch Miss%'")
        conn.commit()
        console.print(f"[green][+] Deleted {c.rowcount} records.[/green]")

    conn.close()


def main():
    parser = argparse.ArgumentParser(description="FauxSSH Analytics")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--sessions", action="store_true", help="List recent sessions")
    group.add_argument("--commands", action="store_true", help="List recent commands")
    group.add_argument(
        "--retry-failed", action="store_true", help="Reset failed analysis"
    )
    group.add_argument(
        "--top-ips", action="store_true", help="Show Top IPs and Frequency"
    )
    group.add_argument(
        "--payloads", action="store_true", help="List captured malicious payloads"
    )
    parser.add_argument(
        "--all", action="store_true", help="Show all payloads (include failed/small)"
    )

    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--no-failed", action="store_true")
    parser.add_argument("--ip", help="Filter by IP")
    parser.add_argument("--session-id", help="Filter by Session ID")
    parser.add_argument(
        "--anon", action="store_true", help="Mask the last octet of IP addresses"
    )
    parser.add_argument("--db", help="Path to SQLite database file")
    parser.add_argument("--sort", help="Sort order (e.g. Risk:Desc,Cmds:Desc)")
    parser.add_argument(
        "--protocol", help="Filter by protocol (ssh, telnet, redis, mcp)"
    )
    parser.add_argument(
        "--output", action="store_true", help="Show command output snippets"
    )

    args = parser.parse_args()

    # Log Database Info
    try:
        db = get_db_backend()
        console.print(f"[bold blue]Database:[/bold blue] {db.get_connection_info()}")
    except:
        pass

    if args.sessions:
        list_sessions(
            limit=args.limit,
            no_failed=args.no_failed,
            anon=args.anon,
            db_path=args.db,
            sort_param=args.sort,
            ip_filter=args.ip,
            protocol_filter=args.protocol,
        )
    elif args.commands:
        list_commands(
            limit=args.limit,
            ip_filter=args.ip,
            session_filter=args.session_id,
            anon=args.anon,
            db_path=args.db,
            sort_param=args.sort,
            protocol_filter=args.protocol,
            show_output=args.output,
        )
    elif args.retry_failed:
        reset_failed_analysis(db_path=args.db)
    elif args.top_ips:
        list_top_ips(limit=args.limit, anon=args.anon, db_path=args.db)
    elif args.payloads:
        list_payloads(
            limit=args.limit, anon=args.anon, db_path=args.db, show_all=args.all
        )

    else:
        if args.ip or args.session_id:
            list_commands(
                limit=args.limit,
                ip_filter=args.ip,
                session_filter=args.session_id,
                anon=args.anon,
                db_path=args.db,
                sort_param=args.sort,
                protocol_filter=args.protocol,
                show_output=args.output,
            )
        else:
            list_sessions(
                limit=args.limit,
                no_failed=args.no_failed,
                anon=args.anon,
                db_path=args.db,
                sort_param=args.sort,
                ip_filter=args.ip,
                protocol_filter=args.protocol,
            )


if __name__ == "__main__":
    main()
