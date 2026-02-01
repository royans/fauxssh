import logging
import vt
import time
import os
import hashlib
import json
import datetime
from ssh_honeypot.core.config import config, get_data_dir

logger = logging.getLogger(__name__)


class VirusTotalAnalyzer:
    def __init__(self):
        self.api_key = config.get("virustotal", "api_key")
        self.client = None
        if self.api_key:
            self.client = vt.Client(self.api_key)

        self.last_request_time = 0
        self.min_delay = 15.0  # 4 req/min = 15s

    def _check_rate_limit(self):
        """Returns True if we can make a request using DB tracking."""
        try:
            from ssh_honeypot.core.database import get_db_backend

            db = get_db_backend()

            l_rpm = config.get("throttling", "global", "virustotal", "rpm") or 1
            l_rph = config.get("throttling", "global", "virustotal", "rph") or 30
            l_rpd = config.get("throttling", "global", "virustotal", "rpd") or 125

            allowed, reason = db.check_api_rate_limit(
                "virustotal", "GLOBAL", l_rpm, l_rph, l_rpd
            )
            if not allowed:
                logger.warning(f"[VirusTotal] Global Rate Limit Block: {reason}")
                return False
            return True
        except Exception as e:
            logger.error(f"[VirusTotal] Error checking DB rate limit: {e}")
            return False

    def _increment_usage(self):
        try:
            from ssh_honeypot.core.database import get_db_backend

            db = get_db_backend()
            db.record_api_usage("virustotal", "GLOBAL")
        except:
            pass

    def close(self):
        if self.client:
            self.client.close()

    def verify_auth_at_startup(self):
        """
        Runs a lightweight query to verify API key works.
        Returns True/False.
        Note: This counts towards the quota.
        """
        if not self.client:
            return False

        if not self._check_rate_limit():
            return False

        try:
            # Checking a known safe hash (EICAR) just to test auth
            logger.info("[VirusTotal] Verifying API Key with test query...")

            # Use EICAR MD5 as requested
            eicar_md5 = "59ce0baba11893f90527fc951ac69912"
            file_obj = self.client.get_object(f"/files/{eicar_md5}")

            # Log stats as requested
            stats = file_obj.last_analysis_stats
            logger.info(
                f"[VirusTotal] EICAR Check - Malicious: {stats.get('malicious', 0)}"
            )
            logger.info(
                f"[VirusTotal] EICAR Check - Harmless:  {stats.get('harmless', 0)}"
            )
            logger.info(f"[VirusTotal] EICAR Check - Total:     {sum(stats.values())}")

            self._increment_usage()
            logger.info("[VirusTotal] Startup Check Passed.")
            return True

        except vt.APIError as e:
            if e.code == "QuotaExceededError":
                logger.error("[VirusTotal] Startup Check Failed: Quota Exceeded")
            elif e.code == "AuthenticationRequiredError":
                logger.error("[VirusTotal] Startup Check Failed: Invalid API Key")
            else:
                logger.error(f"[VirusTotal] Startup Check Failed: {e}")
            return False
        except Exception as e:
            logger.error(f"[VirusTotal] Startup Check Failed: {e}")
            return False

    def _wait_for_rate_limit(self):
        """Enforces strictly 4 requests/minute."""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.min_delay:
            wait_time = self.min_delay - elapsed
            logger.debug(f"[VirusTotal] Rate limit sleep: {wait_time:.2f}s")
            time.sleep(wait_time)
        self.last_request_time = time.time()

    def check_hash(self, file_hash):
        """
        Checks if a file hash is already known in VT.
        Returns the object or None.
        """
        if not self.client:
            return None

        if not self._check_rate_limit():
            return None

        self._wait_for_rate_limit()
        try:
            obj = self.client.get_object(f"/files/{file_hash}")
            self._increment_usage()
            return obj
        except vt.APIError as e:
            if e.code == "NotFoundError":
                # Not found is "success" in terms of API call but "None" for result
                self._increment_usage()  # Confirm if 404 counts against quota? Usually yes.
                return None
            logger.error(f"[VirusTotal] API Error checking hash {file_hash}: {e}")
            return None
        except Exception as e:
            logger.error(f"[VirusTotal] Error checking hash {file_hash}: {e}")
            return None

    def scan_file(self, file_path):
        """
        Uploads and scans a file.
        Returns the analysis object or None.
        """
        if not self.client:
            return None

        if not self._check_rate_limit():
            return None

        self._wait_for_rate_limit()
        try:
            with open(file_path, "rb") as f:
                analysis = self.client.scan_file(f, wait_for_completion=False)
                self._increment_usage()
                return analysis
        except Exception as e:
            logger.error(f"[VirusTotal] Upload Error for {file_path}: {e}")
            return None
