import threading

try:
    from .webhook_notifier import WebhookNotifier
    from .config import config
    from .logging_setup import log
except ImportError:
    from webhook_notifier import WebhookNotifier
    from config_manager import config
    from ssh_honeypot.core.logging_setup import log


class AlertManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(AlertManager, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        # Load Config
        webhook_url = config.get("alerting", "webhook_url")
        self.notifier = WebhookNotifier(webhook_url)

        self.notify_threshold = int(config.get("alerting", "notify_threshold") or 6)
        self.session_threshold = int(config.get("alerting", "session_threshold") or 7)
        self.ip_threshold = int(config.get("alerting", "ip_threshold") or 9)
        self.keywords = config.get("alerting", "keywords") or []

        self.service_thresholds = config.get("alerting", "service_thresholds") or {}

        if webhook_url:
            log.info(
                f"[AlertManager] Initialized. URL: ...{webhook_url[-5:]}, Levels: [N:{self.notify_threshold}, S:{self.session_threshold}, I:{self.ip_threshold}]"
            )
        else:
            log.info("[AlertManager] Initialized (Disabled: No URL).")

        # Runtime State
        self.monitored_sessions = set()
        self.monitored_ips = set()
        self.msg_history_1h = []  # Timestamps of sent messages

        # Hardcoded Rate Limits (Safety)
        self.limit_hour = 20
        self.limit_min = 5

    def _check_rate_limit(self):
        """Returns True if message can be sent, False otherwise."""
        import time

        now = time.time()

        # Prune old
        self.msg_history_1h = [t for t in self.msg_history_1h if now - t < 3600]

        # Check Hour Limit
        if len(self.msg_history_1h) >= self.limit_hour:
            return False

        # Check Minute Limit
        msgs_last_min = [t for t in self.msg_history_1h if now - t < 60]
        if len(msgs_last_min) >= self.limit_min:
            return False

        return True

    def _record_sent(self):
        import time

        self.msg_history_1h.append(time.time())

    def send_ban_alert(self, ip, duration, reason):
        if not self.notifier.webhook_url:
            return
        if not self._check_rate_limit():
            log.warning(
                f"[AlertManager] Rate Limit Exceeded. Suppressing Ban Alert for {ip}"
            )
            return

        self._record_sent()
        msg = f"**🚫 DoS BAN TRIGGERED**\n**IP:** `{ip}`\n**Duration:** {duration}s\n**Reason:** {reason}"
        # We assume WebhookNotifier has a generic send method or we reuse send_alert
        # WebhookNotifier.send_alert takes (session, ip, explanation, risk).
        # We might need to extend WebhookNotifier or abuse send_alert.
        # Let's inspect WebhookNotifier. Assuming send_alert(session_id, ip, explanation, risk)
        # We can pass "SYSTEM" as session_id.
        self.notifier.send_alert("SYSTEM", ip, f"DoS Ban: {reason} ({duration}s)", 99)

    def reload_config(self):
        """Reloads config from manager (useful if .env changes dynamically, though unlikely)"""
        self.__init__()

    def check_risk_score(
        self, session_id, ip, score, explanation="High Risk Activity", protocol="ssh"
    ):
        """Evaluates if a risk score should trigger an alert/monitoring based on Tiers."""
        if not self.notifier.webhook_url:
            return

        # Determine Thresholds
        notify_limit = self.notify_threshold
        session_limit = self.session_threshold
        ip_limit = self.ip_threshold

        # Override if protocol specific config exists
        if protocol and protocol in self.service_thresholds:
            t = self.service_thresholds[protocol]
            notify_limit = t.get("notify_threshold", notify_limit)
            session_limit = t.get("session_threshold", session_limit)
            ip_limit = t.get("ip_threshold", ip_limit)

        # Tier 1: Notify
        if score >= notify_limit:
            if self._check_rate_limit():
                self.notifier.send_alert(session_id, ip, explanation, score)
                self._record_sent()
            else:
                log.warning(
                    f"[AlertManager] Rate Limit Exceeded. Suppressing Risk Alert for {session_id}"
                )

        # Tier 2: Monitor Session
        if score >= session_limit:
            if session_id not in self.monitored_sessions:
                log.info(
                    f"[AlertManager] Enabling Stream for Session {session_id} (Risk: {score} >= {session_limit})"
                )
                self.monitored_sessions.add(session_id)

        # Tier 3: Monitor IP
        if score >= ip_limit:
            if ip not in self.monitored_ips:
                log.info(
                    f"[AlertManager] Flagging IP {ip} for future monitoring (Risk: {score} >= {ip_limit})"
                )
                self.monitored_ips.add(ip)

    def handle_interaction(self, session_id, ip, cmd, response):
        """Called after every command. Checks if we should stream it."""
        if not self.notifier.webhook_url:
            return

        # Tier 0: Keyword Trigger
        for keyword in self.keywords:
            if keyword.lower() in cmd.lower():
                log.warning(
                    f"[AlertManager] Keyword Trigger: '{keyword}' in session {session_id}"
                )
                if self._check_rate_limit():
                    self.notifier.send_alert(
                        session_id, ip, f"Keyword Trigger: {keyword}", 10
                    )
                    self._record_sent()
                else:
                    log.warning(
                        f"[AlertManager] Rate Limit Exceeded. Suppressing Keyword Alert."
                    )
                # Auto-monitor this session
                self.monitored_sessions.add(session_id)
                break

        should_stream = False

        if session_id in self.monitored_sessions:
            should_stream = True
        elif ip in self.monitored_ips:
            should_stream = True

        if should_stream:
            self.notifier.send_interaction(session_id, ip, cmd, response)
