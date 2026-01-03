# Real-time Alerting

FauxSSH can stream high-risk activity to Discord, Slack, or any webhook-compatible service.

## Setup

Add the following to your `.env` file:

```bash
# Webhook URL (Discord Example)
WEBHOOK_URL="https://discord.com/api/webhooks/12345/abcdef..."

# Thresholds (0-10 Risk Score)
# ==========================================

# Tier 1: Notify Only (Risk >= 6)
# Sends a simple alert that a high-risk command was executed.
ALERT_THRESHOLD_NOTIFY=6

# Tier 2: Stream Session (Risk >= 7)
# Automatically enables real-time streaming of ALL commands for this session.
ALERT_THRESHOLD_SESSION=7

# Tier 3: IP Intelligence (Risk >= 9)
# Highest alert level.
ALERT_THRESHOLD_IP=9

# Keyword Triggers
# Regex patterns that trigger an immediate alert regardless of risk score.
ALERT_KEYWORDS="hackblogofy|bashcrack|root|wget|curl"
```

## Security Warning

> [!WARNING]
> Enabling this feature causes the honeypot to generate outbound HTTP traffic to the specified URL. 
> 1.  Use **HTTPS** URLs.
> 2.  Sophisticated attackers monitoring network traffic might correlate command execution with your outbound webhook requests (timing analysis). Use with caution in covert operations.
