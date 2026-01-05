#!/bin/bash
# Simplified Startup Script for SSH Honeypot
# Usage: ./tools/startup.sh [--restart]

set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
export PYTHONPATH="$PROJECT_ROOT"

# Resolve Data Directory
DATA_DIR=$(python3 -c "from ssh_honeypot.config_manager import get_data_dir; print(get_data_dir())" 2>/dev/null | tail -n 1)

if [ -z "$DATA_DIR" ]; then
    # Fallback if python fails (e.g. imports)
    DATA_DIR="$PROJECT_ROOT/data"
fi

mkdir -p "$DATA_DIR"

PID_FILE="$DATA_DIR/server.pid"
LOG_FILE="$DATA_DIR/server_startup.log"
SERVER_CMD="python3 -m ssh_honeypot.server"

# Check arguments
RESTART=false

for arg in "$@"; do
    case $arg in
        --restart|--force)
            RESTART=true
            ;;
    esac
done

# Helper to check if PID is valid
is_running() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
            return 0 # True
        fi
    fi
    return 1 # False
}

# Stop logic
if [ "$RESTART" = true ]; then
    echo "Restart requested. Stopping existing server..."
    if is_running; then
        PID=$(cat "$PID_FILE")
        kill "$PID" 2>/dev/null
        # Wait a moment
        sleep 2
        
        # Force kill if still running
        if kill -0 "$PID" 2>/dev/null; then
             kill -9 "$PID" 2>/dev/null
        fi
    fi
    rm -f "$PID_FILE"
fi

# Start logic
if is_running; then
    echo "Server is already running (PID: $(cat "$PID_FILE"))"
    exit 0
else
    echo "Starting server..."
    
    # IPv6 Check
    if [ -f /proc/net/if_inet6 ]; then
        export SSHPOT_BIND_IP="::"
    else
        export SSHPOT_BIND_IP="0.0.0.0"
    fi

    # Start in background
    # We use nohup logic explicitly or just background?
    # Original used: $SERVER_CMD >> "$LOG_FILE" 2>&1 &
    # We want it to survive shell exit if run manually
    nohup $SERVER_CMD >> "$LOG_FILE" 2>&1 &
    
    NEW_PID=$!
    echo "$NEW_PID" > "$PID_FILE"
    echo "Server started with PID: $NEW_PID"
fi
