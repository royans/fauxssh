#!/bin/bash
# FauxSSH Updater Script
# Handles code updates, dependency refreshes, and database migrations via restart.

set -e

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Resolve Project Root
PROJECT_ROOT="$(dirname "$(readlink -f "$0")")"
cd "$PROJECT_ROOT"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Update Codebase
if [ -d ".git" ]; then
    log_info "Git repository detected. Pulling latest changes..."
    # Check for local changes
    if ! git diff-index --quiet HEAD --; then
        log_warn "Local changes detected. Stashing changes..."
        git stash
        git pull --rebase
        git stash pop || log_warn "Stash pop encountered conflicts. Please resolve manually."
    else
        git pull
    fi
    log_ok "Code updated via Git."
else
    # Fallback to Tarball/Zip update
    log_info "Manual installation detected. Fetching latest bundle from GitHub..."
    ZIP_URL="https://github.com/royans/fauxssh/archive/refs/heads/main.zip"
    TMP_ZIP="/tmp/fauxssh_update.zip"
    TMP_EXTRACT="/tmp/fauxssh_update_extract"

    rm -f "$TMP_ZIP"
    rm -rf "$TMP_EXTRACT"

    if command -v curl >/dev/null 2>&1; then
        curl -sL "$ZIP_URL" -o "$TMP_ZIP"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$ZIP_URL" -O "$TMP_ZIP"
    else
        log_err "No download tools (git, curl, wget) found. Cannot update."
        exit 1
    fi

    # Extract
    mkdir -p "$TMP_EXTRACT"
    PYTHON_CMD="python3"
    if ! command -v python3 >/dev/null 2>&1; then PYTHON_CMD="python"; fi
    "$PYTHON_CMD" -c "import zipfile, sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$TMP_ZIP" "$TMP_EXTRACT"

    # Overlay files (Preserving critical files)
    # The zip contains a folder like fauxssh-main/
    INNER_DIR=$(ls "$TMP_EXTRACT" | head -n 1)
    FULL_SRC="$TMP_EXTRACT/$INNER_DIR"

    if [ -d "$FULL_SRC" ]; then
        log_info "Applying update (Preserving database and configs)..."
        # We use rsync if available for better control, otherwise manual copies
        if command -v rsync >/dev/null 2>&1; then
            rsync -av --exclude='data/' --exclude='config.yaml' --exclude='.env' --exclude='venv/' "$FULL_SRC/" "./"
        else
            # Manual copy with exclusions
            # This is a bit safer: copy everything EXCEPT the protected ones
            for f in "$FULL_SRC"/* "$FULL_SRC"/.*; do
                # Ignore special paths
                basename_f=$(basename "$f")
                if [[ "$basename_f" == "data" || "$basename_f" == "config.yaml" || "$basename_f" == ".env" || "$basename_f" == "venv" || "$basename_f" == "." || "$basename_f" == ".." ]]; then
                    continue
                fi
                cp -rf "$f" "./" 2>/dev/null || true
            done
        fi
        log_ok "Code updated via manual bundle."
    else
        log_err "Failed to extract update bundle."
        exit 1
    fi

    # Cleanup
    rm -f "$TMP_ZIP"
    rm -rf "$TMP_EXTRACT"
fi

# 2. Update Dependencies
if [ -d "venv" ]; then
    log_info "Refreshing Python dependencies in virtual environment..."
    VENV_PYTHON="./venv/bin/python"
    if [ ! -x "$VENV_PYTHON" ] && [ -x "./venv/bin/python3" ]; then VENV_PYTHON="./venv/bin/python3"; fi
    
    if [ -x "$VENV_PYTHON" ]; then
        "$VENV_PYTHON" -m pip install --upgrade pip --quiet || true
        if ! "$VENV_PYTHON" -m pip install -r requirements.txt --quiet; then
            log_warn "Dependency update encountered issues. Check requirements.txt."
        else
            log_ok "Dependencies refreshed."
        fi
    else
        log_warn "Virtual environment found but interpreter is not executable. Skipping pip update."
    fi
else
    log_info "No venv found. Skipping dependency update (Install/Start will handle this)."
fi

# 3. Restart Service & Migrations
log_info "Restarting FauxSSH Service..."
log_info "Note: Database schema migrations will be applied automatically on startup."

if [ -x "./start.sh" ]; then
    ./start.sh --restart
    log_ok "FauxSSH has been updated and restarted."
else
    log_err "start.sh not found or not executable. Please restart the service manually."
fi

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}          Update Successful!              ${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
