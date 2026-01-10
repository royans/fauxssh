#!/bin/bash
# Wrapper to start FauxSSH correctly
set -e

# Resolve Project Root
PROJECT_ROOT="$(dirname "$(readlink -f "$0")")"
cd "$PROJECT_ROOT"

# Export PYTHONPATH to ensure modules are found
export PYTHONPATH="$PROJECT_ROOT"

# Auto-Detect IPv6
if [ -z "${SSHPOT_BIND_IP:-}" ]; then
    if [ -f /proc/net/if_inet6 ]; then
        # echo "IPv6 detected. Binding to ::"
        export SSHPOT_BIND_IP="::"
    else
        export SSHPOT_BIND_IP="0.0.0.0"
    fi
fi

# Activate Virtual Environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
else
    if [ -z "$VIRTUAL_ENV" ]; then
        echo "[INFO] No venv found and VIRTUAL_ENV not set. Using system python3."
    fi
fi

# Source .env if present (to support shell environment variables)
# This allows usage without python-dotenv if needed, or overriding
if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

# Parse Arguments
FOREGROUND=false
for arg in "$@"; do
    case $arg in
        --foreground|-f)
            FOREGROUND=true
            ;;
    esac
done

if [ "$FOREGROUND" = true ]; then
    # Run in foreground (for Systemd or debugging)
    exec python3 -m ssh_honeypot.main "$@"
else
    # Run in background (Default)
    DATA_DIR="$PROJECT_ROOT/data"
    mkdir -p "$DATA_DIR"
    LOG_FILE="$DATA_DIR/server_startup.log"
    PID_FILE="$DATA_DIR/server.pid"
    
    echo "[INFO] Starting FauxSSH in background..."
    echo "[INFO] logs: $LOG_FILE"
    
    nohup python3 -m ssh_honeypot.main "$@" >> "$LOG_FILE" 2>&1 &
    PID=$!
    echo "$PID" > "$PID_FILE"
    echo "[OK] Started. PID: $PID"
fi
