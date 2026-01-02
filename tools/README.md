# FauxSSH Utilities

This directory contains utility scripts to help manage, analyze, and extend the FauxSSH honeypot.

## 1. Analytics Tools (`tools/analytics/`)
These tools are designed for security researchers to extract insights from the honeypot data.

### Log Viewer (`log_viewer.py`)
Replay attacker sessions to see exactly what commands were run and how the AI responded.

```bash
# List recent sessions
python3 tools/analytics/log_viewer.py --list

# Replay a specific session
python3 tools/analytics/log_viewer.py --replay <SESSION_ID>
```

### Upload Inspector (`inspect_uploads.py`)
Analyze files uploaded by attackers (e.g., malware, scripts).

```bash
# List uploaded files and their SHA256 hashes
python3 tools/analytics/inspect_uploads.py --list

# Export a file for analysis
python3 tools/analytics/inspect_uploads.py --export <IP> <USER> <PATH> --out malware_sample.bin
```

### Password Dumper (`dump_passwords.py`)
Quickly view all captured credentials (passwords and SSH keys) tried by attackers, sourced from the `honey_db`.

```bash
# Show recent 50 logins (success and fail)
python3 tools/analytics/dump_passwords.py

# Show only successful logins
python3 tools/analytics/dump_passwords.py --success-only
```

### Actor Correlation (`correlate_actors.py`)
Identifies potential recurring actors by correlating sessions that share:
1.  **Credentials**: Same password or SSH key used from different IPs.
2.  **Software Fingerprint (HASSH)**: Same advanced client fingerprint (based on ordered negotiation algorithms).

```bash
python3 tools/analytics/correlate_actors.py
```

## 2. Public Tools (`tools/public/`)

### Startup Script (`startup.sh`)
The recommended way to run FauxSSH in production. It handles logging, auto-restarts on crash, and file watching.

```bash
./tools/public/startup.sh
```

### Filesystem Seeder (`update_fs_seed.py`)
This script helps you update the `static_fs_seed.json` file, which defines the initial state of the virtual filesystem.

```bash
# Scan a local directory and generate a seed JSON
python3 tools/public/update_fs_seed.py --scan /path/to/template_dir --out ssh_honeypot/static_fs_seed.json
```


