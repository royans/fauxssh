#!/usr/bin/env python3
import sqlite3
import os
import sys
import argparse
import json
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
sys.path.append(os.path.join(PROJECT_ROOT, "ssh_honeypot"))

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

try:
    from config_manager import get_data_dir
    DB_PATH = os.path.join(get_data_dir(), "honeypot.sqlite")
except ImportError:
    DB_PATH = os.path.join(PROJECT_ROOT, "data", "honeypot.sqlite")

def get_conn():
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found at {DB_PATH}")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)

def correlate(by_cred=True, by_hassh=True):
    conn = get_conn()
    c = conn.cursor()
    
    # 1. Correlate by Credentials (actors using same password/key)
    if by_cred:
        print("\n=== Correlating by Credentials (Password/Key) ===")
        print("Finding credentials used by multiple distinct IPs...")
        c.execute("SELECT client_ip, auth_data, success FROM auth_events")
        rows = c.fetchall()
        
        cred_map = defaultdict(set)
        for ip, cred, success in rows:
            if not cred or len(cred) < 3: continue # Skip empty/short
            cred_map[cred].add(ip)
            
        found = False
        sorted_creds = sorted(cred_map.items(), key=lambda x: len(x[1]), reverse=True)
        
        for cred, ips in sorted_creds:
            if len(ips) > 1:
                found = True
                display_cred = cred[:40] + "..." if len(cred) > 40 else cred
                print(f"[-] Credential: '{display_cred}' used by {len(ips)} IPs: {', '.join(list(ips)[:5])}...")
        
        if not found:
            print("No multi-IP credential correlations found.")

    # 2. Correlate by HASSH (Fingerprint)
    if by_hassh:
        print("\n=== Correlating by SSH Fingerprint (HASSH) ===")
        print("Finding Client Fingerprints (HASSH) seen from multiple IPs...")
        
        # Check sessions
        try:
            c.execute("SELECT remote_ip, fingerprint FROM sessions")
            rows = c.fetchall()
        except: rows = []
        
        hassh_map = defaultdict(set)
        hassh_details = {}
        
        for ip, fp_json in rows:
            if not fp_json: continue
            try:
                fp = json.loads(fp_json)
                hassh = fp.get('hassh')
                if hassh:
                    hassh_map[hassh].add(ip)
                    if hassh not in hassh_details:
                         hassh_details[hassh] = fp.get('hassh_algorithms', 'unknown')
            except: pass

        found = False
        sorted_hassh = sorted(hassh_map.items(), key=lambda x: len(x[1]), reverse=True)
        
        for hassh, ips in sorted_hassh:
            clients = len(ips)
            algo_str = hassh_details.get(hassh, "")
            # Truncate algo string
            algo_display = algo_str.split(';')[0] + ";..." # Just KEX
            
            print(f"[-] HASSH: {hassh} ({algo_display})")
            print(f"    Seen from {clients} IPs: {', '.join(list(ips)[:5])}")
            if clients > 1: found = True

        if not found:
            print("No HASSH correlations found (or feature not active long enough).")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Correlate actors by credentials and fingerprints.")
    parser.add_argument("--all", action="store_true", help="Run all correlations")
    args = parser.parse_args()
    
    correlate(by_cred=True, by_hassh=True)
