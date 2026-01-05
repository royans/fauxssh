#!/bin/bash
# Deploy v3.2 - 2025-11-15
# Author: Royans

set -e

echo "[*] Starting deployment of Blogofy v3..."

# Backup current
if [ -d "/var/www/blogofy" ]; then
    echo "[*] Backing up current version..."
    tar -czf /var/backups/blogofy_$(date +%Y%m%d).tar.gz /var/www/blogofy
fi

# Pull latest
# git pull origin master

# DB Migration
echo "[*] Running DB migrations..."
# python3 manage.py migrate

# Restart services
echo "[*] Restarting Nginx & Gunicorn..."
# systemctl restart nginx
# systemctl restart gunicorn

echo "[+] Deployment Complete."
