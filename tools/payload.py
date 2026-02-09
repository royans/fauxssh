#!/usr/bin/env python3
import sys
import os
import argparse
import json
import logging
from typing import List

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_honeypot.core.database import get_db_backend
from ssh_honeypot.services.payload_service import PayloadService
from ssh_honeypot.core.logging_setup import setup_logger

# Setup logging
setup_logger()
logger = logging.getLogger("payload_cli")


def print_payload(p: dict):
    if not p:
        print("Payload not found.")
        return

    print(f"\n[Payload Info]")
    print(f"MD5:        {p.get('payload_md5')}")
    print(f"URL:        {p.get('url')}")
    print(f"First Seen: {p.get('timestamp')}")
    print(f"Status:     {p.get('status')}")

    size = p.get("payload_size")
    size_str = f"{size} bytes" if size is not None else "Unknown"
    print(f"Size:       {size_str}")

    print(f"Risk Score: {p.get('risk_score', 0)}")

    # Show Type (Binary/Text) - Dynamic Check
    # We need the service instance to check content.
    # But print_payload is standalone.
    # We should pass the type in or calculate it before calling print_payload?
    # Or refactor print_payload to accept service?
    # Let's return the type from info command instead.
    print(f"Type:       {p.get('calculated_type', 'Unknown')}")

    vt = p.get("virustotal_result")
    if vt and isinstance(vt, dict):
        print(f"VT Tags:    {vt.get('tags', [])}")
        stats = vt.get("stats", {})
        if stats:
            print(
                f"VT Stats:   Malicious: {stats.get('malicious', 0)}, Harmless: {stats.get('harmless', 0)}"
            )
    elif vt:
        print(f"VT Data:    {str(vt)[:100]}...")

    # Analysis summary if available
    if p.get("analysis_summary"):
        print(f"Summary:    {p.get('analysis_summary')}")

    # Recent Sessions
    sessions = p.get("recent_sessions", [])
    if sessions:
        print("\n[Recent Sessions]")
        print(f"{'Time':<25} {'IP':<16} {'Proto':<8} {'User':<15} {'Session ID'}")
        print("-" * 80)
        for s in sessions:
            ts = str(s.get("start_time", ""))[:23]
            ip = s.get("remote_ip", "Unknown")
            proto = s.get("protocol", "ssh")
            user = s.get("username", "nm") or "nm"
            sid = s.get("session_id", "")
            print(f"{ts:<25} {ip:<16} {proto:<8} {user:<15} {sid}")
    print("-" * 60)


def cmd_info(service, args):
    p = service.get_payload_by_md5(args.md5)
    if p:
        p["calculated_type"] = service.detect_payload_type(args.md5)
    print_payload(p)


def cmd_score(service, args):
    if service.update_payload_risk_score(args.md5, args.score):
        print(f"[SUCCESS] Updated risk score for {args.md5} to {args.score}.")
    else:
        print(f"[ERROR] Failed to update risk score for {args.md5}.")
        sys.exit(1)


def cmd_tag(service, args):
    tags = args.tags.split(",")
    tags = [t.strip() for t in tags if t.strip()]
    if service.update_payload_tags(args.md5, tags):
        print(f"[SUCCESS] Updated tags for {args.md5} to {tags}.")
    else:
        print(f"[ERROR] Failed to update tags for {args.md5}.")
        sys.exit(1)


def cmd_scan(service, args):
    print(f"Submitting {args.md5} to VirusTotal...")
    # ... (existing scan logic) ...
    # We could try to find content if upload is requested
    content = None
    if args.upload:
        p = service.get_payload_by_md5(args.md5)
        if p and p.get("file_path") and os.path.exists(p["file_path"]):
            try:
                with open(p["file_path"], "rb") as f:
                    content = f.read()
            except Exception as e:
                print(f"[WARNING] Could not read file for upload: {e}")
        else:
            print("[WARNING] File path not found or invalid, cannot upload.")

    result = service.submit_to_virustotal(args.md5, raw_content=content)
    print(json.dumps(result, indent=2))


def cmd_stats(service, args):
    # ... (existing stats logic) ...
    print(f"Generating stats for last {args.hours} hours...\n")
    stats = service.get_payload_stats(hours=args.hours)

    print(f"=== Payload Statistics (Last {stats['period_hours']}h) ===")
    print(f"Total New Payloads:      {stats['total_new']}")
    print(f"Pending Review:          {stats['pending_review']} (Global)")

    print("\n[Service Breakdown]")
    if stats["service_breakdown"]:
        for svc, count in stats["service_breakdown"].items():
            print(f"  {svc:<15}: {count}")
    else:
        print("  None")

    print("\n[Risk Distribution (Global)]")
    rd = stats["risk_distribution"]
    total_scored = sum(rd.values())
    if total_scored > 0:
        print(f"  High (>=70)    : {rd['high']} ({rd['high']/total_scored*100:.1f}%)")
        print(
            f"  Medium (30-69) : {rd['medium']} ({rd['medium']/total_scored*100:.1f}%)"
        )
        print(f"  Low (<30)      : {rd['low']} ({rd['low']/total_scored*100:.1f}%)")
    else:
        print("  No scored payloads.")
    print("==========================================")


def cmd_dump(service, args):
    # Dump RAW content to stdout. NO print() calls here.
    content = service.get_payload_content(args.md5)
    if content:
        sys.stdout.buffer.write(content)
        sys.stdout.flush()
    else:
        sys.stderr.write(f"Error: Content not found for {args.md5}\n")
        sys.exit(1)


def cmd_list(service, args):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
    except ImportError:
        print("Error: 'rich' library not found. Please install it to use this view.")
        return

    console = Console()
    rows = service.list_payloads(limit=args.limit)

    table = Table(title=f"Recent Payloads (Last {args.limit})", box=box.ROUNDED)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("URL", style="blue underline", overflow="fold")
    table.add_column("Score", style="bold")
    table.add_column("Proto", style="magenta")
    table.add_column("Details (MD5)", style="dim", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("Type", style="cyan")
    table.add_column("IPs", style="magenta")

    for r in rows:
        ts = str(r.get("timestamp"))

        # IP Display
        ip_list = r.get("ip_list", [])
        if len(ip_list) > 2:
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

        # VT Info / Error
        vt_score_str = "-"
        if r.get("error_message"):
            # Show error in details if present, but keep score empty
            pass
        else:
            risk = r.get("risk_score")
            if risk is not None:
                color = "green"
                if risk > 50:
                    color = "yellow"
                if risk > 80:
                    color = "red"
                vt_score_str = f"[{color}]{risk}[/{color}]"

        details = r.get("payload_md5") or ""
        if r.get("error_message"):
            details = f"[red]{r['error_message']}[/red]"

        # Size
        size_str = "-"
        size = r.get("payload_size")
        if size is not None:
            if size < 1024:
                size_str = f"{size} B"
            else:
                size_str = f"{size/1024:.1f} KB"

        # Calculate Type
        md5 = r.get("payload_md5")
        p_type = "-"
        if md5:
            p_type = service.detect_payload_type(md5)
            if "Binary" in p_type:
                p_type = "[bold red]Binary[/bold red]"
            elif "Text" in p_type:
                p_type = "[green]Text[/green]"

        table.add_row(
            ts,
            f"[{status_style}]{str(status).upper()}[/{status_style}]",
            r.get("url"),
            vt_score_str,
            r.get("method") or "-",
            details,
            size_str,
            p_type,
            display_ip,
        )

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Payload Management CLI")
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Command to run"
    )

    # LIST
    p_list = subparsers.add_parser("list", help="List recent payloads")
    p_list.add_argument(
        "--limit", type=int, default=50, help="Number of payloads to show"
    )

    # INFO
    p_info = subparsers.add_parser("info", help="Get payload details")
    p_info.add_argument("md5", help="MD5 hash of the payload")

    # SCORE
    p_score = subparsers.add_parser("score", help="Update risk score")
    p_score.add_argument("md5", help="MD5 hash of the payload")
    p_score.add_argument("score", type=int, help="New risk score (0-100)")

    # TAG
    p_tag = subparsers.add_parser("tag", help="Update tags")
    p_tag.add_argument("md5", help="MD5 hash of the payload")
    p_tag.add_argument("tags", help="Comma-separated tags (e.g., 'trojan,mining')")

    # SCAN
    p_scan = subparsers.add_parser("scan", help="Submit to VirusTotal")
    p_scan.add_argument("md5", help="MD5 hash of the payload")
    p_scan.add_argument(
        "--upload", action="store_true", help="Upload file if available locally"
    )

    # STATS
    p_stats = subparsers.add_parser("stats", help="Show payload statistics")
    p_stats.add_argument(
        "--hours", type=int, default=24, help="Time period in hours (default: 24)"
    )

    # DUMP
    p_dump = subparsers.add_parser("dump", help="Dump payload content to stdout")
    p_dump.add_argument("md5", help="MD5 hash of the payload")

    args = parser.parse_args()

    try:
        service = PayloadService()

        if args.command == "list":
            cmd_list(service, args)
        elif args.command == "info":
            cmd_info(service, args)
        elif args.command == "score":
            cmd_score(service, args)
        elif args.command == "tag":
            cmd_tag(service, args)
        elif args.command == "scan":
            cmd_scan(service, args)
        elif args.command == "stats":
            cmd_stats(service, args)
        elif args.command == "dump":
            cmd_dump(service, args)

    except Exception as e:
        if isinstance(e, BrokenPipeError):
            sys.stderr.close()
            sys.exit(0)
        print(f"[CRITICAL ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
