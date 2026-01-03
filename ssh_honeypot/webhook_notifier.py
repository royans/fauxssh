import urllib.request
import urllib.parse
import json
import threading
import time
try:
    from .logger import log
except ImportError:
    from logger import log

class WebhookNotifier:
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    def send_alert(self, session_id, ip, reason, score):
        """Sends a high priority alert about a session."""
        # Discord format: Needs 'content' or 'embeds'
        msg = f"🚨 **High Risk Alert** (Score: {score})\n**Reason:** {reason}\n**IP:** `{ip}`\n**Session:** `{session_id}`"
        
        payload = {
            "content": msg,
            "username": "FauxSSH Alert",
            "avatar_url": "https://i.imgur.com/4M34hi2.png"
        }
        self._send_async(payload)

    def send_interaction(self, session_id, ip, command, response):
        """Streams a specific interaction."""
        # Truncate response to avoid massive payloads
        snippet = response[:1000] + "..." if len(response) > 1000 else response
        # Escape backticks in snippet to avoid breaking markdown
        snippet = snippet.replace('`', "'")
        
        msg = f"📡 **Stream** `{session_id}` (`{ip}`)\n**$** `{command}`\n```\n{snippet}\n```"
        
        payload = {
            "content": msg,
            "username": "FauxSSH Stream"
        }
        self._send_async(payload)

    def _send_async(self, payload):
        if not self.webhook_url:
            return

        def _worker():
            try:
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(
                    self.webhook_url, 
                    data=data, 
                    headers={'Content-Type': 'application/json', 'User-Agent': 'FauxSSH-Webhook/1.0'}
                )
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status >= 400:
                        log.warning(f"[Webhook] Failed to send payload. Status: {r.status}")
            except Exception as e:
                log.error(f"[Webhook] Connection Error: {e}")

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
