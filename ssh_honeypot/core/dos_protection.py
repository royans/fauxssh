import time
import logging
from collections import defaultdict

import json
import os
from ssh_honeypot.core.utils import get_data_dir

log = logging.getLogger(__name__)


class DoSProtector:
    def __init__(self, limit_rpm=1000, ban_time_sec=3600):
        self.limit_rpm = limit_rpm
        self.ban_time_sec = ban_time_sec
        # Structure: ip -> {'count': int, 'window_start': float, 'banned_until': float}
        self.tracking = defaultdict(
            lambda: {"count": 0, "window_start": 0, "banned_until": 0}
        )

        self.ban_file = os.path.join(get_data_dir(), "banned_ips.json")
        self._load_bans()

    def _load_bans(self):
        try:
            if os.path.exists(self.ban_file):
                with open(self.ban_file, "r") as f:
                    data = json.load(f)
                    now = time.time()
                    count = 0
                    for ip, until in data.items():
                        if until > now:
                            self.tracking[ip]["banned_until"] = until
                            count += 1
                    if count > 0:
                        log.info(
                            f"[DoS Protection] Loadded {count} active bans from persistence."
                        )
        except Exception as e:
            log.error(f"[DoS Protection] Failed to load bans: {e}")

    def _save_ban(self, ip, until):
        # We append/update the single IP in file to avoid race conditions?
        # Or just rewrite file? Rewriting is safer for consistency, albeit heavier.
        # Given low frequency of bans (hopefully), rewrite is fine.
        try:
            # Load existing first to merge (if multiple processes? No, threaded)
            # Just verify we keep all valid bans from memory
            active_bans = {}
            now = time.time()
            for t_ip, record in self.tracking.items():
                if record["banned_until"] > now:
                    active_bans[t_ip] = record["banned_until"]

            # Ensure current one is in there (might update self.tracking before calling this)
            active_bans[ip] = until

            with open(self.ban_file, "w") as f:
                json.dump(active_bans, f)
        except Exception as e:
            log.error(f"[DoS Protection] Failed to save ban: {e}")

    def is_allowed(self, ip, service_name="unknown"):
        """
        Check if IP is allowed.
        Returns: True (Allowed), False (Blocked)
        Side Effects: Increments counters, logs ban events.
        """
        now = time.time()
        record = self.tracking[ip]

        # 1. Check if Banned
        if record["banned_until"] > now:
            return False

        # 2. Reset Window if needed
        # We use a 60-second fixed window starting from the first request
        if now - record["window_start"] > 60:
            record["count"] = 0
            record["window_start"] = now

        # 3. Increment
        record["count"] += 1

        # 4. Check Threshold
        if record["count"] > self.limit_rpm:
            banned_until = now + self.ban_time_sec
            record["banned_until"] = banned_until

            # Persist
            self._save_ban(ip, banned_until)

            # Format times for clear logging
            start_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
            end_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(banned_until))

            log.warning(
                f"[DoS Protection] BANNED IP {ip} from {start_str} until {end_str} ({self.ban_time_sec}s). Reason: Exceeded {self.limit_rpm} RPM on {service_name}."
            )

            # Send Discord Alert
            try:
                from ssh_honeypot.core.alert_manager import AlertManager

                AlertManager().send_ban_alert(
                    ip,
                    self.ban_time_sec,
                    f"Exceeded {self.limit_rpm} RPM on {service_name}",
                )
            except Exception as e:
                log.error(f"[DoS Protection] Alert Failed: {e}")

            return False

        return True


# Global Instance
dos_protector = DoSProtector()
