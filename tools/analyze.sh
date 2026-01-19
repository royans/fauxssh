#!/bin/bash
# Wrapper to run analyze.py with the correct virtual environment

# Resolve directory of this script
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check for venv
if [ -f "$PROJECT_ROOT/venv/bin/python" ]; then
    PYTHON_CMD="$PROJECT_ROOT/venv/bin/python"
elif [ -f "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON_CMD="$PROJECT_ROOT/.venv/bin/python"
else
    # Check if we are already in a venv
    if [ -n "$VIRTUAL_ENV" ]; then
         PYTHON_CMD="python3"
    else
        echo -e "\033[0;33m[!] Warning: Virtual environment not found in venv or .venv\033[0m"
        echo -e "    Attempting to run with system python3..."
        PYTHON_CMD="python3"
    fi
fi

# Execute
exec "$PYTHON_CMD" "$SCRIPT_DIR/analytics/analyze.py" "$@"
