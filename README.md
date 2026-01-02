# FauxSSH

**FauxSSH** is a high-interaction SSH honeypot that leverages Generative AI (Google Gemini) to simulate a realistic Linux environment. It traps attackers in a simulated shell where their commands are processed by an LLM, generating believable responses without putting your real system at risk.

## Features

- **Dynamic AI Responses**: Uses Google Gemini to generate believable output for shell commands.
- **Virtual Filesystem (VFS)**: Maintains an in-memory filesystem state per session.
- **Session Persistence**: Tracks working directory, environment variables, and command history.
- **SFTP Support**: Accepts file uploads (quarantined safely) and allows simulated file browsing.
- **DoS Protection**: Rate limiting per IP and global session limits.
- **Secure**: Isolates attackers from the host system; explicitly forbids `root` login.

## Prerequisites

- **Python 3.8+**
- **Google Cloud API Key** with Gemini API enabled.


## ⚠️ Security & Disclaimer

> [!CAUTION]
> **Use at your own risk.** FauxSSH is a honeypot designed to attract attackers. It should **ONLY** be run in a strictly isolated environment (dedicated VPS, VM, or sandbox) that you are willing to lose.

See [SECURITY.md](SECURITY.md) for detailed risk warnings and reporting instructions.

**Do not run this on your personal workstation or mission-critical servers.**



## Recent Improvements

### Jan 1st 2026
- **Hardware Emulation**: Added handlers for `dmidecode`, `lspci`, and `lscpu` to simulate a dual NVIDIA H100 server.
- **Enhanced Realism**: Implemented Recon Script Interception and smarter "Alabaster" persona aliases.
- **Security Scaling**: Increased input processing limit to 50,000 characters to support analyzing large malware payloads.

### Dec 31st 2025
- **Native SCP Protocol**: Full support for `scp` file uploads (quarantined locally) and downloads.
- **Malware Persistence**: Uploaded files can now be "executed" (simulated via LLM) to observe behavioral analysis.
- **Prompt Injection Hardening**: New framework to detect and neutralize adversarial LLM prompts.

### Dec 30th 2025
- **Network Tarpitting**: Implemented "sticky" connections and honeytokens to slow down automated scanners.
- **Advanced Chaining**: Support for complex command chains (`|`, `&&`, `;`) and redirections (`>`).
- **Local IO Handlers**: Added fast, deterministic handlers for `disk` operations (`df`, `free`, `mount`, `wc`).


## Quick Start

### 🌐 Live Demo
You can try FauxSSH right now! It is running on **blogofy.com** on standard port 22.
```bash
ssh blogofy.com
# Password: any (except root)
```

### 1. Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/royans/fauxssh.git
    cd fauxssh
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment:**
    Create a `.env` file in the root directory.
    ```bash
    echo "GOOGLE_API_KEY=your_actual_api_key_here" > .env
    ```

## Configuration

You can override default settings by creating a `config.yaml` file in the root directory.

**Example `config.yaml` (with defaults shown):**

```yaml
server:
  port: 2222
  bind_ip: "0.0.0.0"
  hostname: "web.blogofy.com"   # Fake hostname shown in prompt
  host_key_file: "data/host.key"

llm:
  model_name: "gemma-3-27b-it"  # Google Gemini model
  max_tokens: 2048
  temperature: 1.0

upload:
  max_file_size: 1048576        # 1MB limit for SFTP/SCP
  max_quota_per_ip: 1048576     # Total upload quota per IP
  cleanup_days: 30              # Upload retention period
```

## Usage

### 1. Start the Server

Run the server module. By default, it listens on port **2222** to avoid requiring root privileges.

```bash
python -m ssh_honeypot.server
```

### 2. Connect

Test the honeypot from another terminal:

```bash
ssh -p 2222 user@localhost
```
*Note: You can use any username/password combination (except `root`).*

### 3. Production Deployment

For long-running deployments, use the included startup script which handles logging and auto-restarts:

```bash
./tools/public/startup.sh
```

## Deployment (Port Forwarding)

To make FauxSSH reachable on the standard SSH port (22) without running the Python script as root, use `iptables` to forward traffic.

**Redirect port 22 to 2222:**

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

*Note: Make sure your real SSH server is moved to a different port or restricted by other rules to avoid locking yourself out if you are configuring this remotely.*

## Real-time Alerting

FauxSSH can send real-time webhooks (e.g., Slack, Discord) when high-risk activity is detected.

### Configuration
Add to your `.env` file:
```bash
# Webhook URL (Discord/Slack/Etc)
WEBHOOK_URL="https://discord.com/api/webhooks/..."

# Tier 1: Notify Only (Risk >= 6). Default: 6
ALERT_THRESHOLD_NOTIFY=6

# Tier 2: Stream Session (Risk >= 7). Default: 7
ALERT_THRESHOLD_SESSION=7

# Tier 3: Stream IP (Risk >= 9). Default: 9
ALERT_THRESHOLD_IP=9
```

### ⚠️ Security Warning (Alerting)
> [!WARNING]
> Enabling this feature causes the honeypot to generate outbound HTTP traffic to the configured URL.
> 1. Ensure `WEBHOOK_URL` is **HTTPS** to protect payload data.
> 2. Sophisticated attackers monitoring network traffic from the collection point might correlate command execution with outbound bursts (timing attack). Use with caution in covert deployments.

## Logging

All logs and captured data are stored in the `data/` directory:
- `data/honeypot.json.log`: Structured application logs (JSON format).
- `data/honeypot.sqlite`: SQLite database containing:
    - `sessions`: Session metadata and client fingerprints.
    - `auth_events`: Log of all login attempts (passwords/keys).
    - `interactions`: Full command/response history.
- `data/uploaded_files/`: Quarantined files uploaded by attackers.

## 🎓 For Researchers & Educators

FauxSSH can serve as an interesting case study for **Deception Technology** and **LLM Behavior**. We have prepared a dedicated guide for students and researchers exploring this concept:

*   **[Educational Guide (EDUCATIONAL.md)](EDUCATIONAL.md)**: Explains the concepts of Simulated High-Interaction Honeypots and suggested experiments.


## Security Warning

> [!WARNING]
> **This is a honeypot designed to be attacked.**
> *   **Isolation**: Run this in an isolated environment (VM, VPS, or container).
> *   **Monitoring**: High traffic or scripted attacks can consume your API quota quickly.
> *   **Network**: Be careful exposing this on your primary network.

## Contact

For questions, feedback, or educational collaboration:
*   **Email**: royans@gmail.com
