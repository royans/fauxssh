#!/usr/bin/env python3
import sys
import os
import time
import argparse

# Fix Path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.ip_enrichment import IPEnricher
from ssh_honeypot.core.logging_setup import log

def main():
    parser = argparse.ArgumentParser(description="Manually run IP Enrichment")
    parser.add_argument("--limit", type=int, default=10, help="Max IPs to process")
    parser.add_argument("--all", action="store_true", help="Process all unenriched IPs (Warning: Slow)")
    args = parser.parse_args()
    
    db = HoneyDB()
    enricher = IPEnricher()
    
    limit = 1000 if args.all else args.limit
    
    print(f"[*] Fetching up to {limit} unenriched IPs...")
    # Fetch in batches if needed, but here simple list
    ips = db.get_unenriched_ips(limit=limit)
    
    if not ips:
        print("[*] No unenriched IPs found.")
        return

    print(f"[*] Found {len(ips)} IPs. Starting enrichment (Rate Limit: 6s delay)...")
    
    for i, ip in enumerate(ips):
        try:
            print(f"[{i+1}/{len(ips)}] Processing {ip}...")
            result = enricher.enrich_ip(ip)
            if result:
                db.save_ip_intelligence(ip, result)
                print(f"    -> Success: {result.get('network_type')} / {result.get('org')}")
            else:
                print("    -> Failed to enrich.")
            
            # Rate Limit Delay (6 seconds)
            time.sleep(6)
            
        except KeyboardInterrupt:
            print("\n[!] Aborted by user.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
