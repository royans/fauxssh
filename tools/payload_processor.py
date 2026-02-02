#!/usr/bin/env python3
import sys
import os
import argparse
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_honeypot.core.database import get_db_backend
from ssh_honeypot.core.payload_manager import PayloadManager
from ssh_honeypot.core.logging_setup import setup_logger

# Setup logging
setup_logger()
logger = logging.getLogger("payload_processor")


def list_pending_downloads(db):
    print("\n[Pending Downloads]")
    # Accessing internal method or adding a public one?
    # db.get_pending_payloads is available
    pending = db.get_pending_payloads(limit=50)
    if not pending:
        print("No pending downloads.")
        return

    print(f"{'ID':<6} {'Timestamp':<20} {'Status':<12} {'URL'}")
    print("-" * 92)
    for p in pending:
        # Highlight checking for stuck
        status = p.get("status", "unknown")
        if status == "downloading":
            status = "STUCK/RETRY"
        print(f"{p['id']:<6} {str(p['timestamp'])[:19]:<20} {status:<12} {p['url']}")
    print("-" * 92)


def list_pending_analysis(db):
    print("\n[Pending Analysis (Downloaded but not Analyzed)]")
    pending = db.get_pending_analysis_payloads(limit=50)
    if not pending:
        print("No pending analysis items.")
        return

    print(f"{'ID':<6} {'MD5':<34} {'Size':<10} {'File Path'}")
    print("-" * 80)
    for p in pending:
        fname = os.path.basename(p["file_path"]) if p.get("file_path") else "N/A"
        print(f"{p['id']:<6} {p['payload_md5']:<34} {p['payload_size']:<10} {fname}")
    print("-" * 80)


def main():
    parser = argparse.ArgumentParser(description="Manual Payload Processor")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # List Downloads
    subparsers.add_parser("list-downloads", help="List pending downloads")

    # Process Downloads
    dl_parser = subparsers.add_parser(
        "process-downloads", help="Process pending downloads"
    )
    dl_parser.add_argument(
        "--limit", type=int, default=5, help="Number of payloads to download"
    )

    # List Analysis
    subparsers.add_parser("list-analysis", help="List pending analysis")

    # Process Analysis
    an_parser = subparsers.add_parser(
        "process-analysis", help="Process pending analysis"
    )
    an_parser.add_argument(
        "--limit", type=int, default=1, help="Number of payloads to analyze"
    )
    an_parser.add_argument(
        "--force", action="store_true", help="Force analysis even if disabled in config"
    )

    args = parser.parse_args()

    # Init DB
    db = get_db_backend()
    pm = PayloadManager(db)

    if args.command == "list-downloads":
        list_pending_downloads(db)
    elif args.command == "process-downloads":
        print(f"Processing up to {args.limit} downloads...")
        results = pm.process_queue(limit=args.limit)
        if results:
            print(f"\nProcessed {len(results)} items:")
            for r in results:
                status = r.get("status", "Unknown")
                err = f" ({r['error']})" if "error" in r else ""
                print(f" - [{status}] ID: {r['id']} URL: {r.get('url')}{err}")
        else:
            print("No items processed.")

    elif args.command == "list-analysis":
        list_pending_analysis(db)
    elif args.command == "process-analysis":
        print(f"Processing up to {args.limit} analysis items (Force={args.force})...")
        results = pm.process_analysis_queue(limit=args.limit, force=args.force)
        if results:
            print(f"\nProcessed {len(results)} items:")
            for r in results:
                status = r.get("status", "Unknown")
                err = f" ({r['error']})" if "error" in r else ""
                print(f" - [{status}] ID: {r['id']} MD5: {r.get('md5')}{err}")
        else:
            print("No items processed (or VirusTotal disabled/cached).")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
