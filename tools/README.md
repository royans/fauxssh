# FauxSSH Utilities

This directory contains utility scripts to help manage, analyze, and extend the FauxSSH honeypot.

## 1. Analytics Tools (`tools/analytics/`)
These tools are designed for security researchers to extract insights from the honeypot data.

### Unified Analytics Tool (`anayze.py`)
A comprehensive CLI for querying sessions, commands, and threat analysis data.

```bash
# List all sessions
python3 tools/analytics/analyze.py --sessions

# Show command history with risk scores
python3 tools/analytics/analyze.py --commands --limit 20

# List captured malware payloads
python3 tools/analytics/analyze.py --payloads
```

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

```

### IP Intelligence (`enrich_ips.py`)
Backfill or manually trigger IP enrichment (GeoIP/ASN lookups). Useful if background enrichment is too slow or you want to process historical data.

```bash
# Process all unenriched IPs (Rate limited to 10/min)
python3 tools/analytics/enrich_ips.py --all
```

## 2. Deployment Tools (Root & `tools/`)

### Main Scripts (Root)
- **`install.sh`**: The One-Line Installer.
- **`start.sh`**: The primary launcher (Foreground/Interactive).

### Utilities (`tools/`)
- **`check_config.py`**: Validates environment (API Keys, Permissions).
- **`setup_service.sh`**: Installs FauxSSH as a Systemd User Service.
- **`validate_persona.py`**: Validator for persona YAML files.

## 3. Data Management (`tools/`)

### Log Importer (`import_logs.py`)
Import JSON-formatted legacy logs or exported archives into the live database (SQLite or Postgres).
```bash
python3 tools/import_logs.py backup.json.log
```

### Log Exporter (`export_logs.py`)
Export all interactions from the current database to a JSON stream. Useful for migrations or backups.
```bash
python3 tools/export_logs.py export.json.log
```

## 4. Internal Developer Tools (`tools/internal/`)

Scripts for debugging, filesystem seeding, and legacy references (e.g., `legacy_startup.sh`) have been moved to `tools/internal/` to reduce clutter.


