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
        --foreground|-f|--help|-h|--create-persona)
            FOREGROUND=true
            ;;
    esac
done

# --- Robust Startup Logic ---
# 1. Determine Requested Persona
PERSONA_REQ=""
# Extract --persona arg if present (simple parse)
for ((i=1; i<=$#; i++)); do
    if [[ "${!i}" == "--persona" ]]; then
        j=$((i+1))
        PERSONA_REQ="${!j}"
        break
    fi
done

# 2. Env Var Priority
if [ -z "$PERSONA_REQ" ] && [ -n "$SSH_PERSONA" ]; then
    PERSONA_REQ="$SSH_PERSONA"
fi

# 3. Fallback to Last Used
DATA_ROOT="${FAUXSSH_DATA_DIR:-$PROJECT_ROOT/data}"
LAST_FILE="$DATA_ROOT/.last_persona"
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
if [ "$VALID" = false ] && [ -d "$DATA_ROOT/personas/$PERSONA_REQ" ]; then
    VALID=true
    echo "[INFO] Found Dynamic Persona: $PERSONA_REQ"
fi

# Critical Failure Handling
if [ "$VALID" = false ]; then
    echo "[WARN] Persona '$PERSONA_REQ' not found!"
    
    if [ "$PERSONA_REQ" != "$DEFAULT_PERSONA" ]; then
        echo "[INFO] Attempting fallback to Default: $DEFAULT_PERSONA"
        if [ -d "$PROJECT_ROOT/personas/$DEFAULT_PERSONA" ]; then
             # Remove stale state if it pointed to a missing persona
             rm -f "$LAST_FILE"
             # We don't change arguments passed to python, main.py handles fallback too, 
             # but this check ensures we don't crash silently or confusingly.
             # Ideally we should probably warn user.
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

if [ "$FOREGROUND" = true ]; then
    # Run in foreground (for Systemd or debugging)
    exec python3 -m ssh_honeypot.main "$@"
else
    # Run in background (Default)
    if [ -n "${FAUXSSH_DATA_DIR:-}" ]; then
        DATA_DIR="$FAUXSSH_DATA_DIR"
    elif [ -d "$PROJECT_ROOT/../data" ]; then
        # Auto-detect sibling (Production layout)
        DATA_DIR="$(readlink -f "$PROJECT_ROOT/../data")"
    else
        DATA_DIR="$PROJECT_ROOT/data"
    fi
    
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
