#!/bin/bash
# Wrapper to start FauxSSH correctly
set -e

# Resolve Project Root
PROJECT_ROOT="$(dirname "$(readlink -f "$0")")"
cd "$PROJECT_ROOT"

# Export PYTHONPATH to ensure modules are found
export PYTHONPATH="$PROJECT_ROOT"

# Auto-Detect IPv6
if [ -z "${FAUXSSH_BIND_IP:-}" ]; then
    if [ -f /proc/net/if_inet6 ]; then
        # echo "IPv6 detected. Binding to ::"
        export FAUXSSH_BIND_IP="::"
    else
        export FAUXSSH_BIND_IP="0.0.0.0"
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
# Cascading load: Parent first, then Local (overrides)
if [ -f "../.env" ]; then
    set -a
    source ../.env
    set +a
fi

if [ -f ".env" ]; then
    set -a
    source .env
    set +a
fi

# Parse Arguments
FOREGROUND=false
RESTART=false
ARGS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --foreground|-f|--help|-h|--create-persona)
            FOREGROUND=true
            ARGS+=("$1")
            shift
            ;;
        --restart)
            RESTART=true
            shift
            ;;
        --persona)
            ARGS+=("$1")
            shift
            if [[ $# -gt 0 ]]; then
                ARGS+=("$1")
                PERSONA_REQ="$1"
                shift
            fi
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# Set args back for python
set -- "${ARGS[@]}"

# --- Robust Startup Logic ---
# 1. Determine Requested Persona
# (Already captured PERSONA_REQ if passed)

# 2. Env Var Priority
if [ -z "$PERSONA_REQ" ] && [ -n "$SSH_PERSONA" ]; then
    PERSONA_REQ="$SSH_PERSONA"
fi

# 3. Fallback to Last Used
DATA_ROOT="${FAUXSSH_DATA_DIR:-$PROJECT_ROOT/data}"
# Ensure we set DATA_DIR consistently for PID check too
if [ -n "${FAUXSSH_DATA_DIR:-}" ]; then
    DATA_DIR="$FAUXSSH_DATA_DIR"
elif [ -d "$PROJECT_ROOT/../data" ]; then
    DATA_DIR="$(readlink -f "$PROJECT_ROOT/../data")"
else
    DATA_DIR="$PROJECT_ROOT/data"
fi
LAST_FILE="$DATA_DIR/.last_persona"

if [ -z "$PERSONA_REQ" ] && [ -f "$LAST_FILE" ]; then
    PERSONA_REQ=$(cat "$LAST_FILE" | tr -d '[:space:]')
fi

# 4. Fallback to Default
DEFAULT_PERSONA="CentOS7_Legacy_Compute"
if [ -z "$PERSONA_REQ" ]; then
    PERSONA_REQ="$DEFAULT_PERSONA"
fi

# --- Validation ---
echo "[INFO] Startup Persona Check: '$PERSONA_REQ'"
VALID=false

# Check Built-in
if [ -d "$PROJECT_ROOT/personas/$PERSONA_REQ" ]; then
    VALID=true
    echo "[INFO] Found Built-in Persona: $PERSONA_REQ"
fi

# Check Dynamic
if [ "$VALID" = false ] && [ -d "$DATA_DIR/personas/$PERSONA_REQ" ]; then
    VALID=true
    echo "[INFO] Found Dynamic Persona: $PERSONA_REQ"
fi

# Critical Failure Handling
if [ "$VALID" = false ]; then
    echo "[WARN] Persona '$PERSONA_REQ' not found!"
    
    if [ "$PERSONA_REQ" != "$DEFAULT_PERSONA" ]; then
        echo "[INFO] Attempting fallback to Default: $DEFAULT_PERSONA"
        if [ -d "$PROJECT_ROOT/personas/$DEFAULT_PERSONA" ]; then
             rm -f "$LAST_FILE"
             echo "[INFO] Fallback successful. Launching..."
        else
             echo "[CRITICAL] Default Persona '$DEFAULT_PERSONA' is MISSING! Reinstall application."
             exit 1
        fi
    else
         echo "[CRITICAL] Default Persona '$DEFAULT_PERSONA' is MISSING! Reinstall application."
         exit 1
    fi
fi
# --------------------------

# --- Database Check ---
DB_TYPE="sqlite" # Default
echo "[DEBUG] Checking for config.yaml..."
if [ -f "config.yaml" ]; then
    echo "[DEBUG] config.yaml found. Parsing..."
    # Use python to safely parse yaml if possible, suppressing errors
    DB_CHECK=$(python3 -c "import yaml; print(yaml.safe_load(open('config.yaml')).get('database', {}).get('type', 'sqlite'))" 2>/dev/null)
    echo "[DEBUG] Python check finished. Result: '$DB_CHECK'"
    if [ -n "$DB_CHECK" ]; then
        DB_TYPE="$DB_CHECK"
    fi
else
    echo "[DEBUG] config.yaml NOT found."
fi

# Env Var Override
if [ -n "$DATABASE_TYPE" ]; then
    DB_TYPE="$DATABASE_TYPE"
fi

echo "[INFO] Database Mode: $DB_TYPE"
# ----------------------

if [ "$FOREGROUND" = true ]; then
    # Run in foreground (for Systemd or debugging)
    exec python3 -m ssh_honeypot.main "$@"
else
    # Run in background (Default)
    mkdir -p "$DATA_DIR"
    LOG_FILE="$DATA_DIR/fauxssh.log"
    PID_FILE="$DATA_DIR/server.pid"
    
    # Check if running
    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE")
        if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
            if [ "$RESTART" = true ]; then
                echo "[INFO] Service already running (PID: $OLD_PID). Restart requested. Killing..."
                kill "$OLD_PID"
                # Wait for it to die
                for i in {1..10}; do
                    if ! kill -0 "$OLD_PID" 2>/dev/null; then
                        break
                    fi
                    sleep 0.5
                done
                # Force kill if needed?
                if kill -0 "$OLD_PID" 2>/dev/null; then
                    echo "[WARN] Forced kill..."
                    kill -9 "$OLD_PID"
                fi
                rm -f "$PID_FILE"
            else
                echo "[INFO] Service is already running (PID: $OLD_PID). Use --restart to force restart."
                exit 0
            fi
        else
            # Stale PID file
            echo "[INFO] Removing stale PID file."
            rm -f "$PID_FILE"
        fi
    fi

    echo "[INFO] Starting FauxSSH in background..."
    echo "[INFO] logs: $LOG_FILE"
    
    nohup python3 -m ssh_honeypot.main "$@" >> "$LOG_FILE" 2>&1 &
    PID=$!
    echo "$PID" > "$PID_FILE"
    echo "[OK] Started. PID: $PID"
fi

# Post-Startup Verification
echo "Verifying service status..."
sleep 2
python3 tools/analytics/analyze.py --limit 5
