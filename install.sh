#!/bin/bash
# FauxSSH Professional Installer
# Usage: ./install.sh [INSTALL_DIR] [-y|--non-interactive]

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

# Vars & Args Parsing
REPO_URL="https://github.com/royans/fauxssh.git"
DEFAULT_DIR="$HOME/fauxssh"

NON_INTERACTIVE=false
ARGS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -y|--yes|--non-interactive)
            NON_INTERACTIVE=true
            shift
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

# Restore positional arguments (INSTALL_DIR)
set -- "${ARGS[@]}"
INSTALL_DIR="${1:-$DEFAULT_DIR}"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

# 1. Prerequisites Report
log_info "Running Pre-flight Checks..."

BLOCKERS=0
AUTOFIX=0

# Check Python3 or Python
PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    # Verify version 3
    if python -c "import sys; sys.exit(0 if sys.version_info.major == 3 else 1)" 2>/dev/null; then
        PYTHON_CMD="python"
    fi
fi

if [ -n "$PYTHON_CMD" ]; then
    echo -e "  [${GREEN}OK${NC}] Python 3 detected ($PYTHON_CMD)."
else
    echo -e "  [${RED}FAIL${NC}] Python 3 is missing. (Action Required)"
    BLOCKERS=$((BLOCKERS+1))
fi

# Check Venv Capability (Try creating a temp one)
if [ -n "$PYTHON_CMD" ]; then
    if $PYTHON_CMD -m venv /tmp/test_fauxssh_venv >/dev/null 2>&1; then
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
    $PYTHON_CMD -c "import zipfile, sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$TMP_ZIP" "$TMP_EXTRACT"
    
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
    if ! $PYTHON_CMD -m venv venv; then
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

# Use python -m pip for maximum compatibility (avoids pip vs pip3 issues)
VENV_PYTHON="./venv/bin/python"
if [ ! -x "$VENV_PYTHON" ] && [ -x "./venv/bin/python3" ]; then
    VENV_PYTHON="./venv/bin/python3"
fi

if [ ! -x "$VENV_PYTHON" ]; then
     log_err "Virtual Environment python interpreter not found."
     exit 1
fi

# Upgrade pip
"$VENV_PYTHON" -m pip install --upgrade pip --quiet >/dev/null 2>&1 || true

if ! "$VENV_PYTHON" -m pip install -r requirements.txt --quiet; then
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

# 5.5 Gemini Setup
echo ""
log_info "Configuring AI Features..."

USER_KEY=""
NEED_VALIDATION=false
FROM_ENV_VAR=false
SKIP_PROMPT=false

# 1. Check Environment Variable
if [ -n "$GOOGLE_API_KEY" ]; then
    log_info "Found GOOGLE_API_KEY in environment variables."
    USER_KEY="$GOOGLE_API_KEY"
    NEED_VALIDATION=true
    FROM_ENV_VAR=true
    SKIP_PROMPT=true
fi

# 2. Check .env (Only if not in Env Var)
if [ -z "$USER_KEY" ]; then
    CURRENT_KEY=$(grep "^GOOGLE_API_KEY=" .env 2>/dev/null | cut -d '=' -f2 | tr -d '"' | tr -d "'")
    if [ -n "$CURRENT_KEY" ] && [ "$CURRENT_KEY" != "your_key_here" ]; then
         log_info "Gemini API Key already configured in .env."
         SKIP_PROMPT=true
         # We validation skip for existing .env to avoid blocking updates/re-installs
    fi
fi

# 3. Prompt User (Only if no Key found anywhere)
if [ "$SKIP_PROMPT" = false ]; then
    if [ "$NON_INTERACTIVE" = true ]; then
        echo "  [Non-interactive] No Gemini Key found in environment or .env. Skipping configuration."
    else
        echo "  FauxSSH uses Google Gemini for dynamic persona generation and chat."
        echo "  (Get a key for free at https://aistudio.google.com/)"
        echo ""
        # Ensure tty for prompt
        if [ -t 0 ]; then
            read -p "  Enter your Gemini API Key (or press Enter to skip): " USER_KEY
        else
            echo "  [Non-interactive shell] Skipping Gemini Prompt."
        fi
        
        if [ -n "$USER_KEY" ]; then
            NEED_VALIDATION=true
        fi
    fi
fi

# 4. Validate and Save
if [ "$NEED_VALIDATION" = true ]; then
    log_info "Validating API Key..."
    
    VALIDATOR_SCRIPT=$(cat <<EOF
import sys
import google.generativeai as genai
try:
    genai.configure(api_key=sys.argv[1])
    model = genai.GenerativeModel('gemma-3-27b-it')
    r = model.generate_content('test', generation_config={'max_output_tokens': 1})
    print("OK")
except Exception as e:
    print(f"FAIL: {e}")
    sys.exit(1)
EOF
)
    # Use || true to prevent set -e from exiting on validation failure
    # Use ./venv/bin/python for venv correctness
    VALIDATION_OUT=$(./venv/bin/python -c "$VALIDATOR_SCRIPT" "$USER_KEY" 2>&1 || true)
    
    if [[ "$VALIDATION_OUT" == *"OK"* ]]; then
         log_ok "API Key is valid."
         
         # Persist to .env (Always, checking if different)
         if grep -q "GOOGLE_API_KEY=" .env; then
             REPLACE_SCRIPT="import sys; lines = open('.env').readlines(); out = [l if not l.startswith('GOOGLE_API_KEY=') else f'GOOGLE_API_KEY={sys.argv[1]}\n' for l in lines]; open('.env', 'w').writelines(out)"
             ./venv/bin/python -c "$REPLACE_SCRIPT" "$USER_KEY"
         else
             echo "GOOGLE_API_KEY=$USER_KEY" >> .env
         fi
         if [ "$FROM_ENV_VAR" = true ]; then
             log_info "Saved environment variable key to .env for persistence."
         fi
         
         # Ask for Persona Generation
         SHOULD_GENERATE=false
         PERSONA_DESC=""
         
         # Logic: If FAUX_PERSONA env var is set, use it. Else if Interactive, prompt.
         if [ -n "$FAUX_PERSONA" ]; then
             SHOULD_GENERATE=true
             PERSONA_DESC="$FAUX_PERSONA"
             log_info "Found FAUX_PERSONA environment variable. Auto-generating persona..."
         elif [ "$NON_INTERACTIVE" = true ]; then
             log_info "Non-interactive mode: Skipping persona generation prompt."
         elif [ -t 0 ]; then
             echo ""
             read -p "  Do you want to generate a custom persona now? [y/N] " GEN_CHOICE
             if [[ "$GEN_CHOICE" =~ ^[Yy]$ ]]; then
                 SHOULD_GENERATE=true
                 read -p "  Describe the persona (e.g. 'Production DB Server for a bank'): " PERSONA_DESC
             fi
         fi
         
         if [ "$SHOULD_GENERATE" = true ]; then
             if [ -z "$PERSONA_DESC" ]; then PERSONA_DESC="Standard enterprise linux server"; fi
             
             log_info "Generating persona via LLM (this may take 10-20s)..."
             
             GEN_SCRIPT=$(cat <<EOF
import sys
import os
sys.path.append(os.getcwd())
try:
    # Ensure config reloads env
    from dotenv import load_dotenv
    load_dotenv(override=True)
    from ssh_honeypot.core.llm import LLMInterface
    from ssh_honeypot.core.persona_generator import PersonaGenerator
    llm = LLMInterface()
    pg = PersonaGenerator(llm)
    name = pg.generate_persona(sys.argv[1])
    print(f"CREATED:{name}")
except Exception as e:
    print(f"FAIL:{e}")
    sys.exit(1)
EOF
)
             GEN_OUT=$(./venv/bin/python -c "$GEN_SCRIPT" "$PERSONA_DESC" 2>&1 || true)
             
             if [[ "$GEN_OUT" == *"CREATED:"* ]]; then
                  P_NAME=$(echo "$GEN_OUT" | cut -d':' -f2)
                  log_ok "Persona '$P_NAME' created and set active."
             else
                  log_err "Generation failed: $GEN_OUT"
             fi
         fi
         
    else
         log_warn "API Key validation failed ($VALIDATION_OUT)."
         if [ "$FROM_ENV_VAR" = true ]; then
             log_err "The provided GOOGLE_API_KEY environment variable is invalid."
         fi
    fi
elif [ -z "$USER_KEY" ] && [ -n "$CURRENT_KEY" ] && [ "$CURRENT_KEY" != "your_key_here" ]; then
    log_info "Gemini API Key already configured (Skipping validation)."
else
    log_info "Skipping AI setup. You can configure .env later."
fi

# 6. Config Check
log_info "Running system check..."
if ./venv/bin/python tools/check_config.py; then
    log_ok "System Check Passed."
else
    log_warn "System Check Warnings (Review above)."
fi

# 7. Auto-Start
echo ""
log_info "Starting FauxSSH Service..."
if ./start.sh; then
    log_ok "Service started in background."
else
    log_err "Failed to start service."
fi

# 8. Final Instructions
echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}       Installation Complete!             ${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "1. Service Status:    ${YELLOW}ps aux | grep main.py${NC}"
echo -e "2. View Logs/Stats:   ${YELLOW}$INSTALL_DIR/tools/analyze.sh${NC}"
echo -e "3. Enable Service:    ${YELLOW}$INSTALL_DIR/tools/setup_service.sh${NC}"
echo ""
echo -e "${BLUE}Active Services (Default Ports):${NC}"
echo "   - SSH:     2222"
echo "   - Telnet:  2323"
echo "   - HTTP:    8080"
echo "   - Redis:   6379"
echo "   - MCP:     8000 (Model Context Protocol)"
echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "   Edit .env to change ports or API keys."
echo "   See $INSTALL_DIR/docs/CONFIGURATION.md for details."
echo ""
echo -e "${BLUE}Permissions Note:${NC}"
echo "   To accept traffic on privileged ports (22, 23, 80) without root,"
echo "   use port forwarding:"
echo ""
echo -e "   ${YELLOW}sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222${NC}"
echo ""
