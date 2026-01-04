#!/usr/bin/env python3
import sqlite3
import argparse
import os
import sys
import json
from datetime import datetime
from dateutil import tz

from rich.console import Console
from rich.table import Table
from rich import box
from rich.tree import Tree
from rich.prompt import Confirm

# Helper imports for path resolution (borrowed from analyze.py pattern)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))
sys.path.append(os.path.join(PROJECT_ROOT, "ssh_honeypot"))

try:
    from config_manager import get_data_dir
    DEFAULT_DB_PATH = os.path.join(get_data_dir(), "honeypot.sqlite")
except ImportError:
    DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "data", "honeypot.sqlite")

console = Console()

def get_db_connection(db_path):
    if not os.path.exists(db_path):
        console.print(f"[bold red][!] Database not found at {db_path}[/bold red]")
        sys.exit(1)
    conn = sqlite3.connect(db_path)
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

def list_user_files(conn, ip=None, username=None, tree_view=False):
    c = conn.cursor()
    
    query = "SELECT * FROM user_filesystem WHERE 1=1"
    params = []
    
    if ip:
        query += " AND ip = ?"
        params.append(ip)
    
    if username:
        query += " AND username = ?"
        params.append(username)
        
    query += " ORDER BY ip, username, path"
    
    c.execute(query, params)
    rows = c.fetchall()
    
    if not rows:
        console.print("[yellow]No records found matching criteria.[/yellow]")
        return

    if tree_view:
        # Group by IP/User
        grouped = {}
        for r in rows:
            key = f"{r['ip']} ({r['username']})"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(r)
            
        for key, files in grouped.items():
            tree = Tree(f"[bold cyan]{key}[/bold cyan]")
            
            # Simple flat path addition for now, real tree logic compliant with parents is complex
            # if we have missing parent nodes in DB.
            # We'll just list paths sorted.
            
            for f in files:
                ftype = "📂" if f['type'] == 'directory' else "📄"
                meta = {}
                try:
                    meta = json.loads(f['metadata'])
                except: pass
                
                size = meta.get('size', 0)
                ts = to_local_time(f['created_at'])
                accessed = to_local_time(f['last_accessed']) if f['last_accessed'] else "Never"
                
                label = f"{ftype} {f['path']} [dim]({size}b, Created: {ts}, Accessed: {accessed})[/dim]"
                tree.add(label)
                
            console.print(tree)
            console.print("")
            
    else:
        table = Table(title="User Filesystem Modifications", box=box.ROUNDED)
        table.add_column("IP", style="magenta")
        table.add_column("User", style="green")
        table.add_column("Status", width=8)
        table.add_column("Type", width=4)
        table.add_column("Path", style="white")
        table.add_column("Size", justify="right")
        table.add_column("Created", style="dim")
        table.add_column("Accessed", style="cyan")
        
        for r in rows:
            ip_val = r['ip']
            user_val = r['username']
            path_val = r['path']
            
            is_deleted = False
            # Check if column exists (backward compat) but we know it does
            if 'is_deleted' in r.keys() and r['is_deleted']:
                is_deleted = True
                
            status_val = "DELETED" if is_deleted else "ACTIVE"
            status_style = "bold red" if is_deleted else "green"
            
            type_icon = "DIR" if r['type'] == 'directory' else "FILE"
            type_style = "blue" if r['type'] == 'directory' else "white"
            
            meta = {}
            try:
                meta = json.loads(r['metadata'])
            except: pass
            
            size_val = str(meta.get('size', '-'))
            ts_val = to_local_time(r['created_at'])
            accessed_val = to_local_time(r['last_accessed']) if r['last_accessed'] else "-"
            
            table.add_row(ip_val, user_val, f"[{status_style}]{status_val}[/{status_style}]", f"[{type_style}]{type_icon}[/{type_style}]", path_val, size_val, ts_val, accessed_val)
            
        console.print(table)

def show_file_content(conn, ip, username, path):
    c = conn.cursor()
    c.execute("SELECT content, type FROM user_filesystem WHERE ip=? AND username=? AND path=?", (ip, username, path))
    row = c.fetchone()
    
    if not row:
        console.print(f"[red]File not found: {path} for {username}@{ip}[/red]")
        return
        
    if row['type'] == 'directory':
        console.print(f"[yellow]{path} is a directory.[/yellow]")
        return
        
    content = row['content']
    if content is None:
        console.print("[dim](Empty content)[/dim]")
    else:
        console.print(f"[bold]Content of {path}:[/bold]")
        console.print(content)

def delete_user_files(conn, ip=None, username=None, filepath=None, skip_confirm=False):
    c = conn.cursor()
    
    # 1. Fetch Candidates
    query = "SELECT ip, username, path FROM user_filesystem WHERE 1=1"
    params = []
    
    if ip:
        query += " AND ip = ?"
        params.append(ip)
    
    if username:
        query += " AND username = ?"
        params.append(username)
        
    if filepath:
        query += " AND path = ?"
        params.append(filepath)
        
    c.execute(query, params)
    rows = c.fetchall()
    
    if not rows:
        console.print("[yellow]No matching files found to delete.[/yellow]")
        return
        
    # 2. Confirm
    count = len(rows)
    console.print(f"[bold red]WARNING:[/bold red] You are about to delete [bold]{count}[/bold] files.")
    if ip: console.print(f"  Filter IP: {ip}")
    if username: console.print(f"  Filter User: {username}")
    if filepath: console.print(f"  Target File: {filepath}")
    if not ip and not username and not filepath: console.print("  [bold red]Filter: ALL FILES (No filters applied!)[/bold red]")
    
    if not skip_confirm:
        if not Confirm.ask("Are you sure you want to proceed?"):
            console.print("[yellow]Deletion cancelled.[/yellow]")
            return

    # 3. Execute
    del_query = "DELETE FROM user_filesystem WHERE 1=1"
    if ip: del_query += " AND ip = ?"
    if username: del_query += " AND username = ?"
    if filepath: del_query += " AND path = ?"
    
    try:
        c.execute(del_query, params)
        conn.commit()
        console.print(f"[green]Successfully deleted {c.rowcount} files.[/green]")
    except Exception as e:
        console.print(f"[bold red]Error deleting files: {e}[/bold red]")

def main():
    parser = argparse.ArgumentParser(description="FauxSSH Filesystem Inspector")
    parser.add_argument("--db", help="Path to SQLite database", default=DEFAULT_DB_PATH)
    parser.add_argument("--ip", help="Filter by IP address")
    parser.add_argument("--user", help="Filter by Username")
    parser.add_argument("--tree", action="store_true", help="Show as tree view (grouped by session)")
    parser.add_argument("--cat", help="Show content of a specific file (requires --ip and --user)")
    parser.add_argument("--file", help="Alias for --cat")
    parser.add_argument("--delete", action="store_true", help="Delete matching files")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation for deletion")
    
    args = parser.parse_args()
    
    conn = get_db_connection(args.db)
    
    try:
        # Handle Aliases
        target_file = args.cat or args.file
        
        if args.delete:
             # Delete Mode (Bulk or Single)
             if target_file and (not args.ip or not args.user):
                  # If targeting a specific file for deletion, strictly require filters to avoid mistakes?
                  # Actually, maybe user wants to delete a file path across ALL users? (e.g. removing a known bad binary)
                  # Let's verify expectations. The previous cat logic was strict.
                  # For safety, let's keep it strict if they specify a file.
                  if not args.ip or not args.user:
                       console.print("[red]Error: Deleting a specific file requires --ip and --user for safety.[/red]")
                       sys.exit(1)
                       
             delete_user_files(conn, ip=args.ip, username=args.user, filepath=target_file, skip_confirm=args.yes)
             
        elif target_file:
            # View Mode
            if not args.ip or not args.user:
                console.print("[red]Error: --cat/--file requires --ip and --user to uniquely identify the file.[/red]")
                sys.exit(1)
            show_file_content(conn, args.ip, args.user, target_file)
            
        else:
            # List Mode
            list_user_files(conn, ip=args.ip, username=args.user, tree_view=args.tree)
            
    finally:
        conn.close()

if __name__ == "__main__":
    main()
