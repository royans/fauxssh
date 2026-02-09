#!/usr/bin/env python3
import hashlib
import sqlite3
import argparse
import os
import sys
import json
import shutil
import textwrap
import re
from datetime import datetime, timedelta
from dateutil import tz, parser


from rich.console import Console, Group
from rich.table import Table
from rich import box
from rich.text import Text
from rich.rule import Rule
from rich.panel import Panel

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

    # Detect test mode to avoid overriding test-defined env vars
    is_test = os.getenv("SSHPOT_TEST_MODE") or "pytest" in sys.modules
    override = not is_test

    env_files = [
        os.path.join(PROJECT_ROOT, ".env"),  # 1. Local (Lower priority)
        os.path.join(
            os.path.dirname(PROJECT_ROOT), ".env"
        ),  # 2. Parent (Higher priority)
    ]
    for env_path in env_files:
        if os.path.exists(env_path):
            load_dotenv(env_path, override=override)
except ImportError:
    pass

try:
    from ssh_honeypot.core.utils import get_data_dir, get_ignored_ips
    from ssh_honeypot.core.config import config
    from ssh_honeypot.core.database import get_db_backend
    from ssh_honeypot.core.analytics_engine import AnalyticsEngine
except ImportError as e:
    console.print(f"[bold red][!] Import Error: {e}[/bold red]")
    sys.exit(1)


def get_engine():
    db = get_db_backend()
    return AnalyticsEngine(db)


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


def get_risk_style(score):
    if score is None:
        return "white"
    try:
        s = float(score)
        if s >= 80:
            return "bold red"
        if s >= 50:
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
    engine = get_engine()
    rows = engine.get_recent_sessions(
        limit=limit, anon=anon, ip_filter=ip_filter, protocol_filter=protocol_filter
    )

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
    table.add_column("ASN", style="cyan")
    table.add_column("ISP/Type", style="dim")
    table.add_column("Risk", justify="right")
    table.add_column("Summary", style="italic white", overflow="fold")
    table.add_column("SessionID", style="dim", no_wrap=True)

    for r in rows:
        start = to_local_time(r.get("start_time"))
        ip = r.get("remote_ip")  # Already cleaned by engine if anon=True
        user = r.get("username")
        proto = r.get("protocol") or "ssh"

        # Special handling for HTTP to show Method+URL
        if proto == "http":
            all_cmds = r.get("all_commands", "")
            if all_cmds:
                # Take the first command
                first_req = all_cmds.split("|||")[0]
                if " GET " in first_req:
                    user = first_req.replace("HTTP GET ", "").strip()
                else:
                    user = first_req.replace("HTTP ", "").strip()  # Keep Method

                # Truncate
                if len(user) > 50:
                    user = user[:47] + "..."

        # Truncate Client
        ver = (r.get("client_version") or "").replace("SSH-2.0-", "")
        if len(ver) > 15:
            ver = ver[:12] + "..."

        cmds = str(r.get("cmd_count", 0))
        llms = str(r.get("llm_count", 0))

        # Calculate Duration
        duration_str = "-"
        if r.get("first_cmd") and r.get("last_cmd") and r.get("cmd_count", 0) > 1:
            try:
                t1 = r["first_cmd"]
                t2 = r["last_cmd"]

                if not isinstance(t1, datetime):
                    t1 = parser.parse(str(t1))
                if not isinstance(t2, datetime):
                    t2 = parser.parse(str(t2))

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
        risk_val = r.get("risk_score")
        if risk_val is None:
            risk_val = r.get("avg_risk")

        risk_str = f"{risk_val:.1f}" if risk_val is not None else "-"
        risk_style = get_risk_style(risk_val)

        summary = r.get("summary") or ""
        if len(summary) > 60:  # Reduced width to fit new columns
            summary = summary[:57] + "..."

        sid = r.get("session_id")

        geo = r.get("country") or "-"
        isp = r.get("org") or r.get("network_type") or "-"
        if len(isp) > 20:
            isp = isp[:17] + "..."

        asn = r.get("asn") or "-"
        if asn != "-" and " " in asn:
            asn = asn.split(" ")[0]

        tags = r.get("abuse_tags")
        if tags and tags != "[]":
            risk_str += " !"  # Flag abuse tags

        table.add_row(
            start,
            ip,
            user,
            proto,
            ver,
            cmds,
            llms,
            duration_str,
            geo,
            asn,
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
    engine = get_engine()
    rows = engine.get_recent_commands(
        limit=limit,
        anon=anon,
        ip_filter=ip_filter,
        session_filter=session_filter,
        protocol_filter=protocol_filter,
        sort_by=sort_param,
    )

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
        ts = to_local_time(r.get("timestamp"))
        ip = r.get("remote_ip") or "-"
        proto = r.get("protocol") or "-"
        user = r.get("username") or "-"
        src = r.get("source") or "-"
        src_style = "yellow"
        if src == "llm":
            src_style = "bold magenta"
        elif src == "llm-cache":
            src_style = "cyan"
        elif "handler" in src:
            src_style = "green"
        elif "chain" in src:
            src_style = "blue"
        elif src == "ratelimit":
            src_style = "bold red"

        src_cell = Text(src, style=src_style)

        # New Size Column
        size_val = r.get("response_size")
        size_str = f"{size_val}" if size_val is not None else "-"

        # Unique%
        unique_pct = r.get("unique_pct", 0.0)
        unique_str = f"{unique_pct:.1f}%"

        risk_val = r.get("risk_score")
        risk_str = f"{risk_val}" if risk_val is not None else "-"
        risk_style = get_risk_style(risk_val)

        cmd_text = r.get("command") or ""
        cmd_styled = Text(cmd_text)

        # Highlight Non-GET HTTP Requests
        if cmd_text.startswith("HTTP ") and " GET " not in cmd_text:
            cmd_styled.stylize("bold magenta")

        cmd_cell = cmd_styled

        # Append Output Snippet if requested
        if show_output:
            resp = r.get("response") or ""
            if resp:
                # Truncate response
                snippet = textwrap.shorten(resp, width=300, placeholder="...")

                # Use Group + Rule for perfect width handling
                cmd_cell = Group(
                    cmd_cell, Rule(style="dim"), Text(snippet, style="italic grey50")
                )

        explanation = r.get("explanation") or ""
        if len(explanation) > 300:
            explanation = textwrap.shorten(explanation, width=300, placeholder="...")

        table.add_row(
            ts,
            ip,
            proto,
            user,
            cmd_cell,
            size_str,
            src_cell,
            unique_str,
            f"[{risk_style}]{risk_str}[/{risk_style}]",
            explanation,
        )

    console.print(table)


def parse_duration(duration_str):
    """Parses duration string like 15m, 14h, 3d into seconds."""
    if not duration_str:
        return 3600  # 1 hour default
    try:
        amount = int(re.sub(r"[^0-9]", "", duration_str))
        unit = re.sub(r"[0-9]", "", duration_str).lower()

        if unit == "m":
            return amount * 60
        if unit == "h":
            return amount * 3600
        if unit == "d":
            return amount * 86400
        return amount  # Default to seconds
    except:
        return 3600


def list_top_commands(
    limit=50,
    duration_str=None,
    ip_filter=None,
    anon=False,
    db_path=None,
    protocol_filter=None,
    show_output=False,
):
    duration_secs = parse_duration(duration_str)
    engine = get_engine()
    rows = engine.get_top_commands(
        limit=limit, duration_seconds=duration_secs, protocol_filter=protocol_filter
    )

    title = f"Top Commands (Last {duration_str or '1h'})"
    table = Table(title=title, box=box.ROUNDED)
    table.add_column("Rank", style="dim", justify="right")
    table.add_column("Command", style="white", overflow="fold")
    table.add_column("Count", justify="right", style="green")
    table.add_column("Unique IPs", justify="right", style="magenta")
    table.add_column("Max Risk", justify="right")
    table.add_column("Protocols", style="cyan")

    rank = 1
    for r in rows:
        cmd = r.get("command") or "-"
        risk = r.get("max_risk")
        risk_str = f"{risk}" if risk is not None else "-"
        risk_style = get_risk_style(risk)

        cmd_cell = Text(cmd)
        if show_output:
            resp = r.get("sample_response") or ""
            if resp:
                snippet = textwrap.shorten(resp, width=300, placeholder="...")
                cmd_cell = Group(
                    cmd_cell, Rule(style="dim"), Text(snippet, style="italic grey50")
                )

        table.add_row(
            str(rank),
            cmd_cell,
            str(r["total_count"]),
            str(r["unique_ips"]),
            f"[{risk_style}]{risk_str}[/{risk_style}]",
            r["protocols"] or "-",
        )
        rank += 1

    console.print(table)


def list_top_ips(limit=50, anon=False, db_path=None):
    engine = get_engine()
    rows = engine.get_top_ips(limit=limit, anon=anon)

    table = Table(title=f"Top IPs (Session Count)", box=box.ROUNDED)
    table.add_column("IP", style="magenta")
    table.add_column("Sessions", justify="right", style="green")
    table.add_column("Last Seen", style="cyan")
    table.add_column("Geo", style="blue")
    table.add_column("ISP/Org", style="dim", overflow="fold")

    for r in rows:
        ip = r.get("remote_ip") or "-"  # Already cleaned

        last = to_local_time(r.get("last_seen"))
        geo = r.get("country") or "-"
        org = r.get("org") or "-"

        table.add_row(
            ip,
            str(r["session_count"]),
            last,
            geo,
            org,
        )

    console.print(table)


def list_payloads(limit=50, anon=False, db_path=None, show_all=False):
    # Use Engine
    engine = get_engine()
    rows = engine.get_recent_payloads(limit=limit, anon=anon)

    table = Table(title=f"Malicious Payloads (Last {limit})", box=box.ROUNDED)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("URL", style="blue underline", overflow="fold")
    table.add_column("Score", style="bold")
    table.add_column("Details", style="dim", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("IPs", style="magenta")

    for r in rows:
        ts = to_local_time(r.get("timestamp"))

        # IP Display
        ip_list = r.get("ip_list", [])
        if len(ip_list) > 3:
            display_ip = f"{', '.join(ip_list[:2])} (+{len(ip_list)-2})"
        else:
            display_ip = ", ".join(ip_list)

        status = r.get("status")
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
            if r.get("payload_size") and r["payload_size"] < 500:
                continue

        # VirusTotal Info
        vt_score_str = "-"
        details = r.get("payload_md5") or ""

        vt_res = r.get("virustotal_result")
        if vt_res and vt_res.startswith("{"):
            try:
                j = json.loads(vt_res)
                if "error" in j:
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

                m_name = j.get("meaningful_name")
                code_insights = j.get("code_insights")
                classification = j.get("classification", {})
                t_label = classification.get("suggested_threat_label")

                if code_insights:
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

        if r.get("error_message"):
            details = f"[red]{r['error_message']}[/red]"

        size_str = "-"
        if r.get("payload_size"):
            size = r["payload_size"]
            if size < 1024:
                size_str = f"{size} B"
            else:
                size_str = f"{size/1024:.1f} KB"

        table.add_row(
            ts,
            f"[{status_style}]{str(status).upper()}[/{status_style}]",
            r.get("url"),
            vt_score_str,
            details,
            size_str,
            display_ip,
        )

    console.print(table)
    console.print(f"[dim]Files are located in: data/payloads/[/dim]")


def reset_failed_analysis(db_path=None):
    # This still sends a write query - we might need to move this to engine or keep specific separate DB conn?
    # For now, let's keep basic connection here OR move to engine.
    # Moving to engine is cleaner.
    # BUT, we need get_db_connection back or use engine.db._get_conn()
    engine = get_engine()
    conn = engine.db._get_conn()
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


def report_efficiency(db_path=None, duration_seconds=None):
    """
    Reports on LLM call efficiency and captures redundant analysis detection.
    """
    engine = get_engine()
    conn = engine.db._get_conn()
    c = conn.cursor()

    title_suffix = ""
    where_clause = ""
    where_clause_was_cached = ""
    params = []
    params_was_cached = []

    if duration_seconds:
        title_suffix = f" (Last {duration_seconds}s)"
        where_clause = "AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '%s seconds')"
        where_clause_base = (
            "WHERE timestamp > (CURRENT_TIMESTAMP - INTERVAL '%s seconds')"
        )

        if engine.db.is_postgres:
            where_clause = "AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '%s seconds')"
            where_clause_base = (
                "WHERE timestamp > (CURRENT_TIMESTAMP - INTERVAL '%s seconds')"
            )
        else:
            where_clause = "AND timestamp > datetime('now', '-%s seconds')"
            where_clause_base = "WHERE timestamp > datetime('now', '-%s seconds')"

        params = [duration_seconds]
        params_was_cached = [duration_seconds]

    console.print(
        Rule(f"LLM EFFICIENCY & REDUNDANCY REPORT{title_suffix}", style="cyan")
    )

    # 1. Total Interactions vs Analysis
    count_query = "SELECT COUNT(*) FROM interactions"
    if duration_seconds:
        count_query += " " + where_clause_base % duration_seconds

    c.execute(count_query)
    total_cmds = c.fetchone()[0]

    if total_cmds == 0:
        console.print(
            "[yellow]No interactions found to analyze efficiency in this period.[/yellow]"
        )
        conn.close()
        return

    analysis_count_query = "SELECT COUNT(*) FROM command_analysis"
    if duration_seconds:
        if engine.db.is_postgres:
            analysis_count_query += f" WHERE analyzed_at > (CURRENT_TIMESTAMP - INTERVAL '{duration_seconds} seconds')"
        else:
            analysis_count_query += (
                f" WHERE analyzed_at > datetime('now', '-{duration_seconds} seconds')"
            )

    c.execute(analysis_count_query)
    total_analysis = c.fetchone()[0]

    # 2. Redundant LLM Interactions
    # To detect redundancy, we look for identical command strings from 'llm' source.
    redundancy_query = f"""
        SELECT command, COUNT(*) as freq 
        FROM interactions 
        WHERE source = 'llm'
        {where_clause % duration_seconds if duration_seconds else ""}
        GROUP BY command 
        HAVING COUNT(*) > 1
        ORDER BY freq DESC 
        LIMIT 20
    """
    c.execute(redundancy_query)
    redundant_cmds = c.fetchall()

    table = Table(title="Top Redundant LLM Interactions", box=box.SIMPLE)
    table.add_column("Command", style="yellow")
    table.add_column("LLM Calls", justify="right")

    saved_calls = 0
    for cmd, freq in redundant_cmds:
        table.add_row(cmd[:50], str(freq))
        saved_calls += freq - 1

    console.print(table)

    # 3. Cache Hits
    cache_hits_query = "SELECT COUNT(*) FROM interactions WHERE was_cached"
    if duration_seconds:
        cache_hits_query += (
            f" AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '{duration_seconds} seconds')"
            if engine.db.is_postgres
            else f" AND timestamp > datetime('now', '-{duration_seconds} seconds')"
        )

    c.execute(cache_hits_query)
    cache_hits = c.fetchone()[0]

    coarse_hits_query = "SELECT COUNT(*) FROM interactions WHERE source = 'llm-coarse'"
    if duration_seconds:
        coarse_hits_query += (
            f" AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '{duration_seconds} seconds')"
            if engine.db.is_postgres
            else f" AND timestamp > datetime('now', '-{duration_seconds} seconds')"
        )

    c.execute(coarse_hits_query)
    coarse_hits = c.fetchone()[0]

    # 4. Summary Stats
    llm_gen_query = "SELECT COUNT(*) FROM interactions WHERE source = 'llm'"
    if duration_seconds:
        if engine.db.is_postgres:
            llm_gen_query += f" AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '{duration_seconds} seconds')"
        else:
            llm_gen_query += (
                f" AND timestamp > datetime('now', '-{duration_seconds} seconds')"
            )

    c.execute(llm_gen_query)
    llm_gens = c.fetchone()[0]

    total_effective = cache_hits + coarse_hits
    efficiency = (total_effective / total_cmds * 100) if total_cmds > 0 else 0

    summary_table = Table(show_header=False, box=box.ROUNDED)
    summary_table.add_column("Statistic")
    summary_table.add_column("Value")
    summary_table.add_row("Total Commands", f"{total_cmds}")
    summary_table.add_row(
        "LLM Generations",
        f"{llm_gens} ({ (llm_gens/total_cmds*100 if total_cmds>0 else 0):.1f}%)",
        style="magenta",
    )
    summary_table.add_row(
        "Total Cache Hits",
        f"{cache_hits} ({ (cache_hits/total_cmds*100 if total_cmds>0 else 0):.1f}%)",
    )
    summary_table.add_row(
        "Coarse Hits (New)",
        f"{coarse_hits} ({ (coarse_hits/total_cmds*100 if total_cmds>0 else 0):.1f}%)",
    )
    summary_table.add_row(
        "Redundant LLM Contexts", f"{saved_calls} (Potential for Optimization)"
    )

    console.print(Panel(summary_table, title="Efficiency Summary", expand=False))
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
    group.add_argument(
        "--redundancy",
        action="store_true",
        help="Report LLM call redundancy and efficiency",
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
    parser.add_argument(
        "--top", action="store_true", help="Show most frequently requested commands"
    )
    parser.add_argument(
        "--duration", help="Time period for analysis (e.g. 15m, 14h, 3d)"
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
        if args.top:
            list_top_commands(
                limit=args.limit,
                duration_str=args.duration,
                ip_filter=args.ip,
                anon=args.anon,
                db_path=args.db,
                protocol_filter=args.protocol,
                show_output=args.output,
            )
        else:
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
    elif args.redundancy:
        duration_secs = parse_duration(args.duration) if args.duration else None
        report_efficiency(db_path=args.db, duration_seconds=duration_secs)

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
