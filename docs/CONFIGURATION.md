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

# Optional: MySQL Support (Default: On)
FAUXSSH_ENABLE_MYSQL=true
FAUXSSH_MYSQL_PORT=3306

# Optional: Service Fallbacks

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
  force_ipv4: false             # Force IPv4 for API calls (useful if IPv6 geolocation fails)

upload:
  max_file_size: 1048576        # 1MB limit for SFTP/SCP
  max_quota_per_ip: 1048576     # Total upload quota per IP
  cleanup_days: 30              # Upload retention period

analytics:
  batch_size: 10                # Max commands to analyze per LLM call (Higher = better token use, Lower = faster dashboard updates)
  process_timeout: 600          # Kill analysis for commands older than this (in seconds)
```

## 3. Advanced Configuration (PostgreSQL)

For high-volume deployments or centralized logging, FauxSSH supports PostgreSQL. See the [Advanced Configuration Guide](ADVANCED_CONFIGURATION.md) for setup and migration instructions.

## 4. Alerting Configuration


See [Alerting Guide](ALERTING.md) for webhook and keyword notification setup.
