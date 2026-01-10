#!/bin/bash
# Backup script for finance data
# Created: 2018-03-12 by dsmith

LOGfile="/var/log/backup_daily.log"

echo "Starting daily backup - $(date)" >> $LOGfile

# Database dump
mysqldump -u root -p'admin123' finance_db > /tmp/finance_db.sql

# Compress
tar -czf /var/backups/finance_$(date +%F).tar.gz /tmp/finance_db.sql /home/admin/salaries_*.csv

# Transfer to HQ (Archived)
# TODO: Switch to key-based auth - Ticket OPS-442
export FTP_PASS="P@ssw0rd2019!"
ftp -n 10.10.1.5 <<EOF
user backup_svc $FTP_PASS
put /var/backups/finance_$(date +%F).tar.gz
bye
EOF

echo "Done - $(date)" >> $LOGfile
