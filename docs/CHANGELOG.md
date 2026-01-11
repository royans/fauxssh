# Changelog

## Weekly Changelog: Jan 11th 2026

### New Features
- **Deep Hardware Simulation**: `PersonaGenerator` now extracts and simulates precise CPU, RAM, Disk, GPU, and Service details from descriptions.
- **🌐 HTTP Honeypot**: Added a new service (Port 8080) mimicking Apache/Nginx with LLM-generated content and caching.
- **🔌 Telnet Support**: Added full Telnet protocol support (optional listener).
- **📼 Session Replay**: Implemented full TTY session recording in `asciinema` v2 format.
- **🦠 Malicious Payload Analysis**: Automated detection, queuing, downloading, and isolation of dropped payloads.
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


## Weekly Changelog: Jan 3rd 2026

### New Features
- **🔔 Real-time Alerting**: Implemented Webhook integration and Keyword-based Discord alerts.
- **📁 Native SCP & Forensic Tooling**: Full SCP upload/download support, "Access Tracking" for files, and enhanced `fs_inspector` for managing malware.
- **🦠 Malware Analysis**: Uploaded files are quarantined but can be "executed" (simulated) for behavioral study.
- **🖥️ Hardware Emulation**: Handlers for `dmidecode`/`lspci` simulating High-Performance Computing (H100) hardware.

### Enhancements
- **Performance**: Refactored to Copy-On-Write (COW) filesystem and implemented aggressive auto-pruning.
- **Deception**: Added "Sticky" network tarpitting and Recon Script Interception.
- **Shell Features**: Support for complex chains (`|`, `&&`, `;`, `>`) and local IO handlers (`df`, `free`, `mount`).
- **Security**: Prompt Injection Hardening and increased input processing limits (50k chars).

### Reliability
- **Startup**: Enhanced `startup.sh` with cron support.
- **UX**: Fixed `cd` behavior and session chaining.
