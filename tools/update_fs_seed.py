#!/usr/bin/env python3
import os
import json
import stat
import datetime
import grp
import pwd
import sys

# Configuration
# Path relative to the tools/ directory or absolute
DEFAULT_OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "../ssh_honeypot/static_fs_seed.json")

# Directories to scan recursively (non-recursive in current logic, but we can make it recursive if needed)
# For safety/size, we often stick to top-level of these dirs or specific depth.
TARGET_DIRS = [
    '/bin',
    '/sbin',
    '/usr/bin',
    '/usr/sbin',
    '/etc',
    '/var/log',
    # Common libraries can be huge, pick carefully
    # '/lib/x86_64-linux-gnu' 
]

# Max files per directory to prevent seed bloat
MAX_FILES_PER_DIR = 200

# Files to actually read content from (text files only)
# BE CAREFUL: Do not include sensitive host files!
CAPTURE_CONTENT = {
    '/etc/shells',
    '/etc/issue.net',
    '/etc/debian_version',
    '/etc/host.conf',
    '/etc/nsswitch.conf',
    '/etc/profile',
    '/etc/bash.bashrc',
    '/etc/timezone',
    '/etc/lsb-release', 
    '/etc/os-release' # We might override this in code, but reading host is a fallback
}

# Custom content overrides to ensure Honeypot Persona (Debian 9)
# regardless of Host OS.
CONTENT_OVERRIDES = {
    "/etc/os-release": """PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
""",
    "/etc/issue": "Debian GNU/Linux 12 \\n \\l\n\n",
    "/etc/hostname": "npc-main-server-01\n",
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
_apt:x:103:65534::/nonexistent:/bin/false
alabaster:x:1000:1000:Alabaster Snowball,,,:/home/alabaster:/bin/bash
"""
}

def get_metadata(path):
    try:
        st = os.stat(path)
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
            
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = str(st.st_gid)

        mode = stat.filemode(st.st_mode)
        mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%b %d %H:%M")

        return {
            "permissions": mode,
            "size": st.st_size,
            "owner": owner,
            "group": group,
            "modified": mtime
        }
    except Exception as e:
        # print(f"Error stating {path}: {e}")
        return None

def harvest():
    entries = []
    seen_paths = set()

    # 1. Base Structure (Root Dirs)
    root_dirs = ['/', '/bin', '/etc', '/home', '/lib', '/mnt', '/opt', '/proc', 
                 '/root', '/run', '/sbin', '/sys', '/tmp', '/usr', '/var']
    
    for p in root_dirs:
        entries.append({
            "path": p,
            "parent_path": os.path.dirname(p) or '/',
            "type": "directory",
            "metadata": {"permissions": "drwxr-xr-x", "size": 4096, "owner": "root", "group": "root"}
        })
        seen_paths.add(p)

    # 2. Iterate Target Paths
    for target_dir in TARGET_DIRS:
        if not os.path.exists(target_dir):
            continue
            
        print(f"[*] Scanning {target_dir}...")
        
        # Ensure parent exists in list
        if target_dir not in seen_paths:
             entries.append({
                "path": target_dir,
                "parent_path": os.path.dirname(target_dir),
                "type": "directory",
                "metadata": get_metadata(target_dir) or {"permissions": "drwxr-xr-x", "size": 4096, "owner": "root", "group": "root"}
            })
             seen_paths.add(target_dir)

        count = 0
        try:
            with os.scandir(target_dir) as it:
                for entry in it:
                    if count >= MAX_FILES_PER_DIR:
                        break
                    
                    full_path = entry.path
                    if full_path in seen_paths: continue

                    meta = get_metadata(full_path)
                    if not meta: continue

                    # Determine type
                    ftype = 'file'
                    if entry.is_dir():
                        ftype = 'directory'
                    elif entry.is_symlink():
                        # Treat symlinks as files for VFS simplicity, or could handle properly later
                        ftype = 'file'

                    # Content Logic
                    content = ""
                    
                    # A. Check Overrides First
                    if full_path in CONTENT_OVERRIDES:
                        content = CONTENT_OVERRIDES[full_path]
                    
                    # B. Check Capture List
                    elif full_path in CAPTURE_CONTENT:
                        try:
                            # Safety: Limit read size
                            with open(full_path, 'r', errors='ignore') as f:
                                # Read max 4KB
                                content = f.read(4096) 
                        except: pass
                    
                    entries.append({
                        "path": full_path,
                        "parent_path": target_dir,
                        "type": ftype,
                        "metadata": meta,
                        "content": content
                    })
                    seen_paths.add(full_path)
                    count += 1
        except PermissionError:
            print(f"[!] Permission denied: {target_dir}")

    # 3. Add explicit overrides if they weren't found in scan
    # (e.g. if we didn't scan /etc but have an override for /etc/passwd, we should add it)
    for path, content in CONTENT_OVERRIDES.items():
        if path not in seen_paths:
            parent = os.path.dirname(path)
            # Ensure parent struct exists roughly (optional, VFS is flat-ish but good for DB)
            entries.append({
                "path": path,
                "parent_path": parent,
                "type": "file",
                "metadata": {"permissions": "-rw-r--r--", "size": len(content), "owner": "root", "group": "root"},
                "content": content
            })
            seen_paths.add(path)

    # 4. Sort for Determinism (Git friendly)
    entries.sort(key=lambda x: x['path'])

    # 5. Output
    output_path = os.path.abspath(DEFAULT_OUTPUT_FILE)
    print(f"[*] Writing {len(entries)} entries to {output_path}")
    
    with open(output_path, 'w') as f:
        json.dump(entries, f, indent=2)

if __name__ == "__main__":
    harvest()
