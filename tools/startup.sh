#!/bin/bash
# Startup script for SSH Honeypot
# Starts the server and restarts it if ssh_honeypot/server.py changes (e.g. on deploy).

set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# export SSHPOT_PORT=2222 # Unleash to change port
SERVER_CMD="python3 ssh_honeypot/server.py"
WATCH_FILE="ssh_honeypot/restart_trigger"
LOG_FILE="data/server_startup.log"


# Singleton execution via lockfile
LOCK_FILE="/tmp/sshpot_startup.lock"

# Note: We use file descriptor 200 for the lock
exec 200>"$LOCK_FILE"
flock -n 200 || { echo "Startup script is already running."; exit 1; }

cd "$PROJECT_ROOT"

# Security Check: Ensure .env exists
if [ ! -f ".env" ]; then
    echo "[ERROR] .env file not found in $PROJECT_ROOT."
    echo "Please create one from .env.example before starting."
    exit 1
fi

mkdir -p data


echo "SSH Honeypot Startup Script"
echo "Watching: $WATCH_FILE"

# Trap to kill child process on exit
cleanup() {
    echo "Stopping startup script..."
    if [ -n "${PID:-}" ]; then
        kill $PID 2>/dev/null
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM


while true; do
  
  # Auto-detect IPv6 availability
  if [ -f /proc/net/if_inet6 ]; then
      echo "[$(date)] IPv6 detected. Enabling Dual Stack (::)."
      export SSHPOT_BIND_IP="::"
  else
      echo "[$(date)] IPv6 NOT detected. Using IPv4 (0.0.0.0)."
      export SSHPOT_BIND_IP="0.0.0.0"
  fi

  echo "[$(date)] Starting server..."
  $SERVER_CMD >> "$LOG_FILE" 2>&1 &
  PID=$!
  echo "[$(date)] Server started with PID: $PID"

  # Initial timestamp
  if [ -f "$WATCH_FILE" ]; then
      LAST_MTIME=$(stat -c %Y "$WATCH_FILE")
  else
      LAST_MTIME=0
  fi

  # Monitor loop
  while kill -0 $PID 2>/dev/null; do
      if [ -f "$WATCH_FILE" ]; then
          curr_mtime=$(stat -c %Y "$WATCH_FILE")
          if [ "$curr_mtime" != "$LAST_MTIME" ]; then
              echo "[$(date)] Detected change in $WATCH_FILE. Restarting..."
              kill $PID
              wait $PID 2>/dev/null
              break
          fi
      fi
      sleep 5
  done

  # If server crashed/exited on its own, wait a bit before restart
  if ! kill -0 $PID 2>/dev/null; then
      echo "[$(date)] Server exited unexpectedly. Restarting in 2 seconds..."
      sleep 2
  else
      # We broke out of loop due to restart trigger
      sleep 1
  fi
done
