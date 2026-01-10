#!/bin/bash
# FauxSSH Professional Installer
# Usage: ./install.sh [INSTALL_DIR]

set -e

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

BANNER="
${BLUE}    ______                 _____ _____ __  __
   / ____/___ ___  __  _  / ___// ___// / / /
  / /_  / __ \`/ / / / |/_/\__ \ \__ \/ /_/ / 
 / __/ / /_/ / /_/ />  < ___/ /___/ / __  /  
/_/    \__,_/\__,_/_/|_|/____//____/_/ /_/   
${NC}
            High-Interaction HoneyPot
"

echo -e "$BANNER"

# Vars
REPO_URL="https://github.com/royans/fauxssh.git"
DEFAULT_DIR="$HOME/fauxssh"
INSTALL_DIR="${1:-$DEFAULT_DIR}"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Prerequisites Report
log_info "Running Pre-flight Checks..."

BLOCKERS=0
AUTOFIX=0

# Check Python3
if command -v python3 >/dev/null 2>&1; then
    echo -e "  [${GREEN}OK${NC}] Python 3 detected."
else
    echo -e "  [${RED}FAIL${NC}] Python 3 is missing. (Action Required)"
    BLOCKERS=$((BLOCKERS+1))
fi

# Check Venv Capability (Try creating a temp one)
if command -v python3 >/dev/null 2>&1; then
    if python3 -m venv /tmp/test_fauxssh_venv >/dev/null 2>&1; then
        echo -e "  [${GREEN}OK${NC}] Python Venv module (with pip) is working."
        rm -rf /tmp/test_fauxssh_venv
    else
        echo -e "  [${RED}FAIL${NC}] Python Venv creation failed. (Action Required: likely 'sudo apt install python3-venv')"
        BLOCKERS=$((BLOCKERS+1))
    fi
fi

# Check Network Tools
if command -v git >/dev/null 2>&1; then
    echo -e "  [${GREEN}OK${NC}] Git detected."
    HAS_GIT=true
elif command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
    echo -e "  [${YELLOW}WARN${NC}] Git missing. Will attempt auto-fix using curl/wget."
    HAS_GIT=false
    AUTOFIX=$((AUTOFIX+1))
else
    echo -e "  [${RED}FAIL${NC}] No download tools (git, curl, wget) found. (Action Required)"
    BLOCKERS=$((BLOCKERS+1))
fi

echo ""
if [ "$BLOCKERS" -gt 0 ]; then
    log_err "$BLOCKERS Blocker(s) found. Please fix the items marked [FAIL] above and retry."
    exit 1
fi
if [ "$AUTOFIX" -gt 0 ]; then
    log_info "Proceeding with $AUTOFIX auto-correction(s)..."
fi

# 2. Setup Directory
if [ -d "$INSTALL_DIR" ] && [ -d "$INSTALL_DIR/.git" ] && [ "$HAS_GIT" = true ]; then
    log_info "Updating existing installation at $INSTALL_DIR..."
    cd "$INSTALL_DIR"
    git pull --quiet
    log_ok "Updated."
elif [ "$HAS_GIT" = true ]; then
    log_info "Installing to $INSTALL_DIR (via Git)..."
    git clone --quiet "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    log_ok "Cloned repository."
else
    log_info "Installing to $INSTALL_DIR (via Zip Bundle)..."
    # Download Zip
    ZIP_URL="https://github.com/royans/fauxssh/archive/refs/heads/main.zip"
    TMP_ZIP="/tmp/fauxssh_install.zip"
    TMP_EXTRACT="/tmp/fauxssh_extract"
    
    rm -f "$TMP_ZIP"
    rm -rf "$TMP_EXTRACT"
    
    if command -v curl >/dev/null 2>&1; then
        curl -sL "$ZIP_URL" -o "$TMP_ZIP"
    else
        wget -q "$ZIP_URL" -O "$TMP_ZIP"
    fi
    
    # Extract using Python (reliable)
    python3 -c "import zipfile, sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$TMP_ZIP" "$TMP_EXTRACT"
    
    # Move files
    # Zip contains fauxssh-main/ folder. We need to flatten it.
    mkdir -p "$INSTALL_DIR"
    
    # Identify the inner directory (e.g. fauxssh-main)
    INNER_DIR=$(ls "$TMP_EXTRACT" | head -n 1)
    FULL_SRC="$TMP_EXTRACT/$INNER_DIR"
    
    if [ -d "$FULL_SRC" ]; then
        # Move normal files and hidden files using dotglob if supported, else manual
        cp -r "$FULL_SRC"/* "$INSTALL_DIR/"
        cp -r "$FULL_SRC"/.* "$INSTALL_DIR/" 2>/dev/null || true
    else
        log_err "Failed to locate extracted bundle."
        exit 1
    fi
    
    # Cleanup
    rm -f "$TMP_ZIP"
    rm -rf "$TMP_EXTRACT"
    
    cd "$INSTALL_DIR"
    log_ok "Downloaded and extracted bundle."
fi

# 3. Virtual Environment
if [ ! -d "venv" ]; then
    log_info "Creating virtual environment..."
    if ! python3 -m venv venv; then
        log_err "Failed to create virtual environment."
        echo ""
        echo -e "${YELLOW}Common Fix for Debian/Ubuntu:${NC}"
        echo "  The 'venv' module requires the python3-venv package."
        echo "  Please run:"
        echo -e "    ${GREEN}sudo apt-get install python3-venv${NC}"
        echo ""
        echo "  (If using a specific python version, e.g. 3.11, install python3.11-venv)"
        exit 1
    fi
fi

# 4. Dependencies
log_info "Installing Python dependencies (this may take a moment)..."

PIP_CMD="./venv/bin/pip"
PIP_VALID=false

# Check if pip exists and runs
if [ -x "$PIP_CMD" ] && "$PIP_CMD" --version >/dev/null 2>&1; then
    PIP_VALID=true
elif [ -x "./venv/bin/pip3" ] && ./venv/bin/pip3 --version >/dev/null 2>&1; then
    PIP_CMD="./venv/bin/pip3"
    PIP_VALID=true
fi

if [ "$PIP_VALID" = false ]; then
    log_err "pip is broken or missing in ./venv/bin/. The virtual environment is corrupted."
    log_info "Removing broken virtual environment..."
    rm -rf venv
    log_info "Please run this installer again to re-create it correctly."
    exit 1
fi

# Upgrade pip first
"$PIP_CMD" install --upgrade pip >/dev/null 2>&1 || true

if ! "$PIP_CMD" install -r requirements.txt --quiet; then
    log_err "Failed to install dependencies."
    exit 1
fi
log_ok "Dependencies installed."

# 5. Configuration
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        log_info "Initialized .env configuration."
    fi
fi

# 6. Config Check
log_info "Running system check..."
if ./venv/bin/python3 tools/check_config.py; then
    log_ok "System Check Passed."
else
    log_warn "System Check Warnings (Review above)."
fi

# 7. Final Instructions
echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}       Installation Complete!             ${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "1. Start FauxSSH:     ${YELLOW}$INSTALL_DIR/start.sh${NC}"
echo -e "2. Enable Service:    ${YELLOW}$INSTALL_DIR/tools/setup_service.sh${NC}"
echo ""
echo -e "${BLUE}Permissions Note:${NC}"
echo "   FauxSSH runs on standard user ports (2222, 8080) by default."
echo "   To accept traffic on Port 22 (SSH) without root, use port forwarding:"
echo ""
echo -e "   ${YELLOW}sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222${NC}"
echo ""
