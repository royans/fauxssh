import threading
try:
    from .webhook_notifier import WebhookNotifier
    from .config_manager import config
    from .logger import log
except ImportError:
    from webhook_notifier import WebhookNotifier
    from config_manager import config
    from logger import log

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
        if self._initialized: return
        self._initialized = True
        
        # Load Config
        webhook_url = config.get('alerting', 'webhook_url')
        
        self.notify_threshold = int(config.get('alerting', 'notify_threshold') or 6)
        self.session_threshold = int(config.get('alerting', 'session_threshold') or 7)
        self.ip_threshold = int(config.get('alerting', 'ip_threshold') or 9)
        self.keywords = config.get('alerting', 'keywords') or []
        
        self.notifier = WebhookNotifier(webhook_url)
        
        # State
        self.monitored_ips = set()
        self.monitored_sessions = set()
        
        if webhook_url:
            log.info(f"[AlertManager] Initialized. URL: ...{webhook_url[-5:]}, Levels: [N:{self.notify_threshold}, S:{self.session_threshold}, I:{self.ip_threshold}]")
        else:
            log.info("[AlertManager] Initialized (Disabled: No URL).")

    def reload_config(self):
        """Reloads config from manager (useful if .env changes dynamically, though unlikely)"""
        self.__init__()

    def check_risk_score(self, session_id, ip, score, explanation="High Risk Activity"):
        """Evaluates if a risk score should trigger an alert/monitoring based on Tiers."""
        if not self.notifier.webhook_url: return

        # Tier 1: Notify
        if score >= self.notify_threshold:
            self.notifier.send_alert(session_id, ip, explanation, score)
            
        # Tier 2: Monitor Session
        if score >= self.session_threshold:
            if session_id not in self.monitored_sessions:
                log.info(f"[AlertManager] Enabling Stream for Session {session_id} (Risk: {score} >= {self.session_threshold})")
                self.monitored_sessions.add(session_id)
        
        # Tier 3: Monitor IP
        if score >= self.ip_threshold:
            if ip not in self.monitored_ips:
                log.info(f"[AlertManager] Flagging IP {ip} for future monitoring (Risk: {score} >= {self.ip_threshold})")
                self.monitored_ips.add(ip)

    def handle_interaction(self, session_id, ip, cmd, response):
        """Called after every command. Checks if we should stream it."""
        if not self.notifier.webhook_url: return

        # Tier 0: Keyword Trigger
        for keyword in self.keywords:
            if keyword.lower() in cmd.lower():
                log.warning(f"[AlertManager] Keyword Trigger: '{keyword}' in session {session_id}")
                self.notifier.send_alert(session_id, ip, f"Keyword Trigger: {keyword}", 10)
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
