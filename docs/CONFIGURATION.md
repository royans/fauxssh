# Configuration Guide

FauxSSH is configured via a combination of a `.env` file (for secrets and environment-specific paths) and a `config.yaml` file (for feature tuning).

## 1. Environment Variables (`.env`)

Create a `.env` file in the project root:

```bash
# Required: Google Gemini API Key
GOOGLE_API_KEY=your_key_here

# Optional: Data Directory Override
FAUXSSH_DATA_DIR=/absolute/path/to/data

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

llm:
  model_name: "gemma-3-27b-it"  # Google Gemini model
  max_tokens: 2048
  temperature: 1.0

upload:
  max_file_size: 1048576        # 1MB limit for SFTP/SCP
  max_quota_per_ip: 1048576     # Total upload quota per IP
  cleanup_days: 30              # Upload retention period
```

## 3. Alerting Configuration

See [Alerting Guide](ALERTING.md) for webhook and keyword notification setup.
