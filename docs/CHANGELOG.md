# Changelog

## Jan 2nd 2026
- **Keyword Alerts**: Support for immediate Discord alerts based on configured keywords or regex patterns.
- **Webhook Integration**: Real-time session streaming and alerting via Discord webhooks.
- **Startup Script**: Enhanced `startup.sh` with `--cron` mode and parent directory `.env` discovery.
- **Bug Fixes**: Resolved critical runtime errors in analysis loop and webhook payload formatting.

## Jan 1st 2026
- **Hardware Emulation**: Added handlers for `dmidecode`, `lspci`, and `lscpu` to simulate a dual NVIDIA H100 server.
- **Enhanced Realism**: Implemented Recon Script Interception and smarter "Alabaster" persona aliases.
- **Security Scaling**: Increased input processing limit to 50,000 characters to support analyzing large malware payloads.

## Dec 31st 2025
- **Native SCP Protocol**: Full support for `scp` file uploads (quarantined locally) and downloads.
- **Malware Persistence**: Uploaded files can now be "executed" (simulated via LLM) to observe behavioral analysis.
- **Prompt Injection Hardening**: New framework to detect and neutralize adversarial LLM prompts.

## Dec 30th 2025
- **Network Tarpitting**: Implemented "sticky" connections and honeytokens to slow down automated scanners.
- **Advanced Chaining**: Support for complex command chains (`|`, `&&`, `;`) and redirections (`>`).
- **Local IO Handlers**: Added fast, deterministic handlers for `disk` operations (`df`, `free`, `mount`, `wc`).
