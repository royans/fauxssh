# Configuration Guide

FauxSSH is configured via a combination of a `.env` file (for secrets and environment-specific paths) and a `config.yaml` file (for feature tuning).

## 1. Environment Variables (`.env`)

Create a `.env` file in the project root:

```bash
# Required: Google Gemini API Key
GOOGLE_API_KEY=your_key_here

# Optional: Data Directory Override
# Optional: Data Directory Override (Defaults to 'data/' or '../data')
# If not set, the system checks for a sibling 'data' directory (production layout) before defaulting to local 'data/'.
FAUXSSH_DATA_DIR=/absolute/path/to/data

# Optional: Telnet Support (Default: On)
FAUXSSH_ENABLE_TELNET=true
FAUXSSH_TELNET_PORT=2323

# Optional: Redis Support (Default: On)
FAUXSSH_ENABLE_REDIS=true
FAUXSSH_REDIS_PORT=6379

# Optional: MCP Control Plane (Default: On)
FAUXSSH_ENABLE_MCP=true
FAUXSSH_MCP_PORT=8000
FAUXSSH_MCP_MAX_LLM_CALLS=20      # Limit LLM calls per session
FAUXSSH_MCP_THROTTLE_DELAY=2.0    # Delay (sec) for throttling

# Optional: HTTP Honeypot (Default: On, Port 8080)
FAUXSSH_ENABLE_HTTP=true
FAUXSSH_HTTP_PORT=8080

# Optional: Analytics Privacy
ANALYTICS_IGNORE_IPS=127.0.0.1,192.168.1.5,10.0.0.1
```

## 2. Application Config (`config.yaml`)

Create `config.yaml` in the project root to override defaults:

```yaml
server:
  port: 2222
  bind_ip: "0.0.0.0"
  hostname: "web.blogofy.com"   # Fake hostname shown in prompt
  host_key_file: "data/host.key"
  banner_default: "SSH-2.0-OpenSSH_..." # Fallback banner if persona undefined

realism:
  latency:
    enabled: true
    min_ms: 20
    max_ms: 300                 # Randomize output delay (Anti-Fingerprint)

llm:
  model_name: "gemma-3-27b-it"  # Google Gemini model
  max_tokens: 2048
  temperature: 1.0

upload:
  max_file_size: 1048576        # 1MB limit for SFTP/SCP
  max_quota_per_ip: 1048576     # Total upload quota per IP
  cleanup_days: 30              # Upload retention period
```

## 3. Advanced Configuration (PostgreSQL)

For high-volume deployments or centralized logging, FauxSSH supports PostgreSQL. See the [Advanced Configuration Guide](ADVANCED_CONFIGURATION.md) for setup and migration instructions.

## 4. Alerting Configuration


See [Alerting Guide](ALERTING.md) for webhook and keyword notification setup.
