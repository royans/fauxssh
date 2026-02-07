# FauxSSH

![License](https://img.shields.io/github/license/royans/fauxssh)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![CI](https://github.com/royans/fauxssh/actions/workflows/ci.yml/badge.svg)

**A high-interaction SSH honeypot powered by Google Gemini.**

FauxSSH deceptively emulates a realistic Linux server, engaging attackers in long, hallucinated sessions while recording every keystroke, file upload, and command output for threat intelligence analysis.

## Key Features

- **🧠 LLM-Powered Realism**: Uses Google Gemini to dynamically generate file contents (`cat`, `ls`), command responses (`ps aux`, `docker ps`), and error messages.
- **🎭 Dynamic Persona Generation**: Create bespoke personas on-the-fly using natural language descriptions (e.g., "A secret build server for XYZ Corp"). The system generates a custom filesystem and behaves accordingly.
- **✨ Researcher Intel Suite**: Includes **Common FS** (global honeytokens) and **Smart Session Summary** (LLM-generated narratives & Risk Scores).
- **🛡️ Evasion Features**: Features **Latency Jitter** (randomized network delays) and **Dynamic SSH Banners** (persona-specific strings) to evade scanner fingerprinting.
- **🔌 Telnet Support**: Optional Telnet listener to capture attacks on legacy protocols, sharing the same persona and intelligence engine.
- **🌐 HTTP Honeypot**: A realistic web server (Port 8080) that dynamically generates HTML, logins, and error pages using the LLM.
- **🟥 High-Interaction Redis**: A realistic Redis honeypot that supports standard commands (`PING`, `INFO`) and uses LLM hallucination for data store queries (`GET`, `SET`).
- **🐬 LLM-Driven MySQL**: A realistic MySQL server (Port 3306) with a hybrid query engine. Simple queries (`SELECT @@version`) are handled locally for speed, while complex SQL (`SELECT * FROM users`) is forwarded to the LLM to generate realistic rows.
- **Network Emulation**: Simulates `curl`/`wget` with realistic delays and firewalls.
- **IP Intelligence**: Automatically tracks and enriches attacker IPs with GeoIP, ASN, and ISP data (Rate-limited to 600 req/hr).
- **Dynamic Filesystem**: Persists user changes per session.
- **🔒 Safe & Isolated**: All uploaded files are sandboxed. The "filesystem" is virtual and strictly isolated from the host.
- **🚨 Real-Time Alerting**: Stream high-risk sessions live to Discord or Slack.
- **📊 Built-in Analytics**: CLI tools to visualize sessions, inspect malware, and correlate threat actors.


## Recent Improvements (Feb 6)
- **UI Integrity Testing**: Added automated linting (`tests/core/test_ui_integrity.py`) to ensure all HTML and Vue templates are syntactically valid and error-free, preventing runtime template crashes.
- **Dashboard UX Refinements**:
    - **Density & Layout**: Optimized table layouts for higher information density (abbreviated time stamps, stacked columns).
    - **Auto-Refresh**: Dashboard now auto-refreshes every 5 minutes for hands-off monitoring.
    - **Risk Scoring**: Visualized risk scores normalized to 0-100 scale directly in the session list.
- **Security Hardening**:
    - **Strict CSP**: Implemented Content Security Policy headers to mitigate XSS risks.
    - **Proxy Trust**: Restricted `X-Forwarded-For` header processing to trusted proxies only.
- **Deployment Reliability**: Fixed critical test failures (`test_payload_consolidation.py`) and resolved `mysql-mimic` compatibility issues to ensure stable deployments.
- **Analytics Debugging**: Fixed an issue where LLM commands were not being correctly analyzed for risk scores.

- **Multi-Service Protocol Filters**: Added dynamic filters to the dashboard (About -> Personalization). Researchers can now toggle visibility for SSH, Telnet, HTTP, MySQL, and Redis to focus on specific threat vectors.
- **Smart Dashboard Visibility**: The dashboard now automatically hides cards for inactive services or unselected protocols, ensuring a clean, high-signal UI.
- **Enhanced Persona Robustness**: Improved the persona engine to automatically handle diverse user data structures (String, List, Dict), preventing crashes during legacy command simulation (`last`, `who`).

## Recent Improvements (Jan 23)
- **Risk Scoring Alignment**: Normalized all threat detection and reporting to a 0-100 scale for better granularity and alerting accuracy.
- **Analytics Power-Tools**: Added `--top` and `--duration` flags to `analyze.py`, enabling rapid triage of frequent commands over specific time periods (e.g., last 15m, 14h, 3d).
- **Auto-Formatting Hooks**: Enhanced the smart test runner to automatically correct code style issues in a loop, ensuring CI/CD compliance.

## Quick Start

### 1. One-Line Installation (Recommended)
Fastest way to get started. Handles dependencies, virtualenv, and configuration.
**Now includes interactive setup** to configure your Gemini API Key and generate your first custom persona automatically.

```bash
env bash -c "$(curl -sL https://raw.githubusercontent.com/royans/fauxssh/main/install.sh)"
```

### 1.5 Three-Line Quick Installation (Customized)
Create a custom persona with help from LLM

```bash
GOOGLE_API_KEY="your_key_here"; export GOOGLE_API_KEY
FAUX_PERSONA="Ubuntu 12.5 server with 12 CPU Cores, 24 GB RAM, 500 GB SSD" ; export FAUX_PERSONA 
env bash -c "$(curl -sL https://raw.githubusercontent.com/royans/fauxssh/main/install.sh)"
```


### 2. Manual Installation
For developers who prefer full control.

```bash
# Clone & Install
git clone https://github.com/royans/fauxssh.git
cd fauxssh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env to add GOOGLE_API_KEY

# Run
./start.sh
```

### 2. Production Startup
Use the included script for robust background execution and logging.

```bash
./tools/startup.sh
```

### 3. Dynamic Persona Generation
Generate and run a custom persona instantly. For full details, see the [Persona System Guide](personas/README.md).

```bash
# Create and start a new persona
./start.sh --create-persona "A banking server involves in SWIFT transactions with sensitive CSVs in /var/data"

# Future runs will automatically use this last-created persona
./start.sh
```

## Analytics Examples

FauxSSH includes powerful CLI tools to visualize captured data. See [Logging & Analytics](docs/LOGGING.md) for details.

### Recent Sessions
`./tools/analyze.sh --sessions --anon --sort Risk:Desc`
![Recent Sessions](docs/images/report_sessions.png)

### Command History
`./tools/analyze.sh --commands --limit 100 --sort Risk:Desc,Unique:Desc`
![Command History](docs/images/report_commands.png)

### Advanced Filtering
Filter by IP (supports IPv4 and mapped IPv6), Session ID, or Protocol:
`./tools/analyze.sh --ip 111.222.333.444`
`./tools/analyze.sh --commands --session-id 49b8ac`
`./tools/analyze.sh --sessions --protocol telnet`

### Filesystem Forensics
Inspect and manage attacker uploads in real-time.
`python3 tools/analytics/fs_inspector.py --tree`
`python3 tools/analytics/fs_inspector.py --ip <IP> --cat /path/to/malware.sh`
`python3 tools/analytics/fs_inspector.py --ip <IP> --delete`

## CLI Tools Reference

In addition to the analytics, FauxSSH includes several utility scripts in `tools/`:

- **`tools/analyze.sh`**: The main entry point for analytics (handles virtualenv automatically).
- **`tools/export_logs.py`**: Export database logs to JSON/CSV for external analysis.
- **`tools/import_logs.py`**: Import legacy logs or merge databases.
- **`tools/check_config.py`**: Validate your configuration and persona settings without starting the server.
- **`tools/validate_persona.py`**: Strict validation for custom persona definitions.
- **`tools/setup_service.sh`**: Helper to generate a `systemd` service file for production.


## Documentation

*   **[Persona System Guide](personas/README.md)**: Master the art of dynamic personas and custom templates.
*   [**Configuration Guide**](docs/CONFIGURATION.md): `.env` settings, port binding, and model tuning.
*   [**Deployment Guide**](docs/DEPLOYMENT.md): Production startup, cron jobs, and port forwarding (Port 22).
*   [**Alerting Setup**](docs/ALERTING.md): Configure Discord/Slack webhooks and keyword triggers.
*   [**Logging & Data**](docs/LOGGING.md): understanding the database schema, JSON logs, and uploaded files.
*   [**Changelog**](docs/CHANGELOG.md): Version history and recent features.
*   [**Educational Use**](docs/EDUCATIONAL.md): A guide for researchers and students.

## Security Warning

> [!WARNING]
> This software is designed to be attacked. While FauxSSH is built with isolation in mind, **never run honeypots on critical production infrastructure** or networks containing sensitive data. Always use a dedicated VPS or isolated VLAN.

## Disclaimer

This tool is for educational and defensive research purposes only. The authors are not responsible for any misuse or damage caused by this software.
