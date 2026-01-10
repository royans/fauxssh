# Changelog

## Weekly Changelog: Jan 10th 2026

### New Features
- **🌐 HTTP Honeypot**: Added a new service (Port 8080) mimicking Apache/Nginx with LLM-generated content and caching.
- **🔌 Telnet Support**: Added full Telnet protocol support (optional listener), sharing the same high-interaction persona and intelligence engine as the SSH service.
- **📼 Session Replay**: Implemented full TTY session recording in `asciinema` v2 format.
- **IPv6 Support**: Improved analytics filtering for IPv4-mapped addresses.

### Enhancements
- **Advanced Shell Features**:
    - **Variable Persistence**: Fixed environment variables (`VAR=val`) persisting across commands.
    - **Complex Assignments**: Support for recursive command execution in assignments (`cpus=$(...)`).
    - **New Tools**: Native implementation of `cut`, `tr`, `head`, `tail`.
- **📊 Analytics Upgrade**: Added "Unique%" score, removed truncation, and implemented advanced sorting.
- **Robust Telnet**: Rewrote `TelnetHelper` to handle fragmentation and "Enter key hangs".
- **Log Clarity**: Improved attribution in error logs (`[SSH]`, `[Telnet]`, `(Protocol: ...)`).

### Reliability
- **Rate Limiting**: Implemented HTTP LLM Rate Limiting (RPM/RPD) backed by SQLite persistence.
- **Silence**: Silenced noisy "Unique constraint failed" errors for valid HTTP session updates.

### Security & Maintenance
- **Error Suppression**: Added log filtering to automatically silence "Incompatible ssh peer" and other Paramiko scanner noise.
- **Anti-Harvesting**: Confirmed and tested IP-based isolation for anti-harvesting rules.
- **Security**: Hardened internal debug commands (`debug_env`) and verified codebase against SQL injection.
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
