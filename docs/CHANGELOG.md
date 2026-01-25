# Changelog

## Weekly Changelog: Jan 25th 2026

### New Features
- **Risk Scoring Normalization**: Standardized risk scoring across all services to a 0-100 scale, significantly improving alerting accuracy and reporting consistency.
- **Advanced Data Triage**:
    - **Top Command Analysis**: New analytics capabilities to identify and group the most frequent attacker command patterns.
    - **Time-Window Filtering**: Added granular time-based filtering to isolation recent attack surges.

### Enhancements
- **Multi-Protocol Persistence**: Unified database abstraction layer now supports PostgreSQL and SQLite with consistent schema enforcement.
- **Service Resilience**: Integrated a low-interaction MySQL honeypot and hardened Telnet session handling.

### Reliability & Quality
- **Automated Quality Assurance**: Integrated smart test monitors and linting into the deployment pipeline to ensure zero-regression releases.
- **Performance Optimization**: Enhanced database indexing for high-volume execution streams.
- **Bug Fixes**: Resolved critical session hanging and analytics clipping issues.


### New Features
- **Database Abstraction**: Implemented `DatabaseBackend` interface allowing switchable storage engines.
- **Postgres Support**: Backend now supports PostgreSQL for centralized logging, dynamically selectable via config.
- **Log Consolidation**: Unified ad-hoc file logging into `EventLogger`, producing consistent `events.json.log` outputs.
- **Data Tools**: 
    - `tools/import_logs.py`: Backfill legacy JSON logs into SQLite or Postgres.
    - `tools/export_logs.py`: Stream unified logs from any DB backend to JSON.

### Enhancements
- **Configuration**: Refactored `config.py` to support automatic recursive environment variable mapping (e.g., `DATABASE_POSTGRES_PASSWORD` -> `database.postgres.password`).
- **Dependencies**: Added `psycopg2-binary` for PostgreSQL support.
- **MySQL Service**: Added low-interaction MySQL honeypot (port 3306) with LLM query support.
- **Throttling**: Fixed `DoSProtector` configuration (disabled defaults) and added explicit connection limits to `Telnet`.
- **Installer**: Enhanced `install.sh` with interactive API key validation and automatic persona generation.

## Weekly Changelog: Jan 11th 2026

### New Features
- **Apache Frontend Support**: Added `docs/internal/apache_blogofy.conf` for reverse proxy setup.
- **HTTP Realism**:
  - Valid `X-Forwarded-For` IP resolution.
  - Support for POST/PUT/PATCH request bodies.
  - **Risk Analysis**: Integrated risk scoring into LLM generation and SQLite persistence.
- **Deep Hardware Simulation**: `PersonaGenerator` now extracts and simulates precise CPU, RAM, Disk, GPU, and Service details.
- **🌐 HTTP Honeypot**: Added a new service (Port 8080) mimicking Apache/Nginx with LLM-generated content and caching.
- **🔌 Telnet Support**: Added full Telnet protocol support (optional listener).
- **Deep Hardware Simulation**: `PersonaGenerator` now extracts and simulates precise CPU, RAM, Disk, GPU, and Service details.
- **IP Intelligence**: Integrated `ip-api.com` and `python-whois` to enrich attacker IP data.
- **IPv6 Support**: Improved analytics filtering for IPv4-mapped addresses.
- **Network Configuration**: Personas now support detailed network settings (Type, CIDR, Gateway, DNS) for enhanced `ip a` simulation.
- **LLMv2 Architecture**: Refactored `llm_v2.py` using Google GenAI SDK and a Provider Pattern for future extensibility.
- **Robust Startup**: `start.sh` now strictly validates personas and defaults, adding critical error handling.

### Enhancements
- **Advanced Shell Features**:
    - **Variable Persistence**: Fixed environment variables persisting across commands.
    - **Complex Assignments**: Support for recursive command execution `cpus=$(...)`.
    - **New Tools**: Native implementation of `cut`, `tr`, `head`, `tail`.
- **📊 Analytics Upgrade**: Added "Unique%" score and advanced sorting.
- **Security**: Added automated Secret Scanning to CI (`test_codebase_security.py`).
- **Documentation**: Refactored project structure; moved Personas guide to `../personas/README.md` and manual tools to `../tests/manual/`.
- **Release Engineering**: Hardened `publish_fauxssh.sh` to support public CI workflows while strictly stripping user data.
- **Log Clarity**: Improved attribution in error logs (`[SSH]`, `[Telnet]`).

### Reliability
- **Rate Limiting**: Implemented HTTP LLM Rate Limiting (RPM/RPD) backed by SQLite persistence.
- **Robust Telnet**: Rewrote `TelnetHelper` to handle fragmentation and "Enter key hangs".
- **Error Suppression**: Automatically silenced "Incompatible ssh peer" and other Paramiko scanner noise.
- **Anti-Harvesting**: Confirmed IP-based isolation for anti-harvesting rules.
- **Maintenance**: Added automatic cleanup of legacy artifact files on startup.

### Fixes
- **UnboundLocalError**: Fixed variable scope issue in `server.py`.
- **DoS Protection**: Fixed bug where local proxy IP (127.0.0.1) was rate-limited instead of real client IP.
- **SQL Syntax**: Fixed `HAVING` clause error in `analyze.py`.
- **Command Dispatch**: Fixed empty output for `apt-get` by normalizing hyphens to underscores.
- **Startup Logic**: Enhanced `start.sh` with `--restart` (atomic restart) and reliable PID content verification.


## Weekly Changelog: Jan 3rd 2026

### New Features
- **🔔 Real-time Alerting**: Implemented Webhook integration and Keyword-based Discord alerts.
- **📁 Native SCP & Forensic Tooling**: Full SCP upload/download support, "Access Tracking" for files, and enhanced `fs_inspector` for managing malware.
- **📁 Native SCP & Forensic Tooling**: Full SCP upload/download support, "Access Tracking" for files, and enhanced `fs_inspector` for managing malware.
- **🖥️ Hardware Emulation**: Handlers for `dmidecode`/`lspci` simulating High-Performance Computing (H100) hardware.

### Enhancements
- **Performance**: Refactored to Copy-On-Write (COW) filesystem and implemented aggressive auto-pruning.
- **Deception**: Added "Sticky" network tarpitting and Recon Script Interception.
- **Shell Features**: Support for complex chains (`|`, `&&`, `;`, `>`) and local IO handlers (`df`, `free`, `mount`).
- **Security**: Prompt Injection Hardening and increased input processing limits (50k chars).

### Reliability
- **Startup**: Enhanced `startup.sh` with cron support.
- **UX**: Fixed `cd` behavior and session chaining.
