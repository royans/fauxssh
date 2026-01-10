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

# 1. Prerequisites Check
log_info "Checking prerequisites..."

command -v python3 >/dev/null 2>&1 || { log_err "Python3 is not installed."; exit 1; }

# Check for venv module 
if ! python3 -c "import venv" 2>/dev/null; then
    log_err "Python3 venv module is missing."
    echo "  Please run: sudo apt-get install python3-venv"
    exit 1
fi

HAS_GIT=false
if command -v git >/dev/null 2>&1; then
    HAS_GIT=true
else
    log_warn "Git not found. Will attempt download via curl/wget."
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        log_err "Neither git, curl, nor wget found. Cannot proceed."
        exit 1
    fi
fi

log_ok "Prerequisites met."

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
    python3 -m venv venv
fi

# 4. Dependencies
log_info "Installing Python dependencies (this may take a moment)..."
./venv/bin/pip install --upgrade pip --quiet
./venv/bin/pip install -r requirements.txt --quiet
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
