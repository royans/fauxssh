#!/bin/bash
# interactive script to setup systemd service for current user

set -e
PROJECT_ROOT=$(readlink -f "$(dirname "$0")/..")
USER_SYSTEMD_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$USER_SYSTEMD_DIR/fauxssh.service"

echo "--- FauxSSH Systemd Setup ---"
echo "Project Path: $PROJECT_ROOT"
echo "Target: $SERVICE_FILE"

read -p "Create systemd service? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Ensure directory exists
mkdir -p "$USER_SYSTEMD_DIR"

# Detect python interpreter
if [ -f "$PROJECT_ROOT/venv/bin/python3" ]; then
    PYTHON_EXEC="$PROJECT_ROOT/venv/bin/python3"
else
    PYTHON_EXEC=$(which python3)
fi

# Create Service File
cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=FauxSSH Honeypot
After=network.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_ROOT
ExecStart=$PROJECT_ROOT/start.sh --foreground
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
# EnvironmentFile=$PROJECT_ROOT/.env

[Install]
WantedBy=default.target
EOF

echo "Created $SERVICE_FILE"

# Reload and Enable
systemctl --user daemon-reload
systemctl --user enable fauxssh

echo "Service enabled."
echo "To start now: systemctl --user start fauxssh"
echo "To view logs: journalctl --user -u fauxssh -f"
