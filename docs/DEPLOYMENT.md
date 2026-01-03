# Deployment Guide

## Production Startup

For long-running deployments, use the included startup script. It handles:
- Background execution
- PID management
- Logging to `data/server_startup.log`
- Auto-restart on crash or file changes

```bash
./tools/startup.sh
```

To run via cron (ensures it stays up after reboot):
```bash
* * * * * /path/to/fauxssh/tools/startup.sh --cron
```

## Port Forwarding (Running on Port 22)

By default, FauxSSH runs on port 2222 to avoid requiring root privileges. To expose it on the standard SSH port (22), use `iptables` NAT redirection:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

> **Warning**: Ensure your real SSH server is moved to a different port or restricted by IP whitelist before doing this, otherwise you will lock yourself out!

## Data Directory Isolation

You can store all honeypot data (databases, logs, uploaded files) in a separate location by setting `FAUXSSH_DATA_DIR` in your `.env` file.

```bash
FAUXSSH_DATA_DIR=/mnt/volume_nyc1_01/honeypot_data
```
