import os
import re
import hashlib
import time
import requests
import logging
import json
from urllib.parse import urlparse
from datetime import datetime, timedelta

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.config import config, get_data_dir

try:
    from ssh_honeypot.core.analyzers.virustotal import VirusTotalAnalyzer
except ImportError:
    VirusTotalAnalyzer = None


logger = logging.getLogger(__name__)

PAYLOAD_DIR = os.path.join(get_data_dir(), "payloads")


class PayloadManager:
    def __init__(self, db: HoneyDB):
        self.db = db
        self._ensure_payload_dir()

        self.vt_analyzer = None
        if VirusTotalAnalyzer and config.get("virustotal", "enabled"):
            try:
                self.vt_analyzer = VirusTotalAnalyzer()
                if not self.vt_analyzer.verify_auth_at_startup():
                    logger.error("[PayloadManager] VirusTotal Disabled: Auth Failed.")
                    self.vt_analyzer = None
                else:
                    logger.info("[PayloadManager] VirusTotal Analyzer Enabled.")
            except Exception as e:
                logger.error(f"[PayloadManager] Failed to init VirusTotal: {e}")

    def _ensure_payload_dir(self):
        if not os.path.exists(PAYLOAD_DIR):
            try:
                os.makedirs(PAYLOAD_DIR, mode=0o750)
            except Exception as e:
                logger.error(f"Failed to create payload directory: {e}")

    def extract_urls(self, text):
        """Extracts http/https URLs and IP-based paths from text."""
        if not text:
            return []

        urls = set()

        # 0. Quoted URLs (High confidence, allow special chars like > ; etc)
        # Matches "http://..." or "1.2.3.4/..."
        quoted_pattern = re.compile(
            r'["\']((?:https?://|(?:[0-9]{1,3}\.){3}[0-9]{1,3}/)[^"\']+)["\']'
        )
        for match in quoted_pattern.findall(text):
            if not match.startswith("http") and not match.startswith("https"):
                match = "http://" + match
            urls.add(match)

        # 1. Standard http/https/www URLs (Unquoted, stricter chars)
        # ... existing logic ...
        standard_pattern = re.compile(r'(?:https?://|www\.)[^\s<>"\';|&]+')
        for match in standard_pattern.findall(text):
            # Cleanup trailing punctuation sometimes caught
            match = match.rstrip(".,;:)")
            if not match.startswith("http"):
                match = "http://" + match
            urls.add(match)

        # 2. Schemeless IP URLs (e.g. 192.168.1.1/malware.sh)
        # Often used with curl/wget without http://
        # Pattern: IP Address + "/" + Path
        # We enforce at least one slash to avoid matching plain IPs in logs
        ip_url_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[^\s<>"\';|&]+')
        for match in ip_url_pattern.findall(text):
            match = match.rstrip(".,;:)")
            urls.add("http://" + match)  # Assume http for raw IPs

        return list(urls)

    def queue_payload(self, url, session_id, ip, timestamp=None):
        """
        Adds a URL to the download queue if permitted.
        Enforces 1 request per host per day logic.
        """
        try:
            # 1. Deduplicate by exact URL (processed already?)
            url_hash = hashlib.md5(url.encode()).hexdigest()

            existing = self.db.get_payload_by_hash(url_hash)
            if existing:
                # Already tracked
                return

            # 2. Host Rate Limiting (1 per day)
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return  # Invalid URL

            if self.db.is_payload_host_rate_limited(hostname):
                logger.info(
                    f"Skipping URL {url} - Host {hostname} rate limited (1/day)"
                )
                return

            # 3. Queue it
            self.db.add_malicious_payload(
                url=url,
                url_hash=url_hash,
                session_id=session_id,
                ip=ip,
                timestamp=timestamp,
            )
            logger.info(f"[PayloadManager] Queued suspicious URL: {url}")

        except Exception as e:
            logger.error(f"Error queuing payload {url}: {e}")

    def process_queue(self):
        """
        Main worker function. fetches pending items and downloads them.
        """
        pending = self.db.get_pending_payloads(limit=5)

        for item in pending:
            payload_id = item["id"]
            url = item["url"]

            logger.info(f"[PayloadManager] Processing payload ID {payload_id}: {url}")
            self.db.update_payload_status(payload_id, "downloading")

            try:
                # Download
                content = self._download_file(url)
                if not content:
                    self.db.update_payload_status(
                        payload_id, "failed", error="Empty or failed download"
                    )
                    continue

                # Analyze
                md5 = hashlib.md5(content).hexdigest()
                size = len(content)

                # Check Local Cache (Dedup)
                filename = f"dangerous_{md5}.txt"
                file_path = os.path.join(PAYLOAD_DIR, filename)

                if os.path.exists(file_path):
                    logger.info(
                        f"[PayloadManager] Payload {url} is duplicate of existing {filename}"
                    )
                    # Update DB to point to existing file
                else:
                    # Save
                    with open(file_path, "wb") as f:
                        f.write(content)
                    logger.info(f"[PayloadManager] Saved new payload to {file_path}")

                self.db.update_payload_status(
                    payload_id,
                    "completed",
                    payload_md5=md5,
                    payload_size=size,
                    file_path=file_path,
                )

            except Exception as e:
                logger.error(f"Failed to download payload {url}: {e}")
                self.db.update_payload_status(payload_id, "failed", error=str(e))

    def process_analysis_queue(self):
        """
        Background job to analyze downloaded payloads with VT.
        Rate Limit is enforced by the Analyzer class.
        """
        if not self.vt_analyzer:
            return

        # Fetch Unanalyzed, Completed Payloads
        # We need to implement get_unanalyzed_payloads in DB or query manually
        # For now, let's assume we can add a method to DB or do raw query
        # But to keep it clean, let's use a simpler approach:
        # We can implement a method in DB to fetch one pending analysis
        item = self.db.get_next_payload_for_analysis()

        if not item:
            return

        payload_id = item["id"]
        file_path = item["file_path"]
        file_hash = item["payload_md5"]
        file_size = item["payload_size"] or 0

        logger.info(f"[PayloadManager] Analyzing Payload {payload_id} ({file_hash})...")

        # 1. Size Check
        min_size = config.get("virustotal", "min_file_size") or 500
        if file_size < min_size:
            logger.info(
                f"[PayloadManager] Skipping VT analysis for {payload_id}: Too small ({file_size}b)"
            )
            self.db.update_payload_vt_status(payload_id, result="skipped_size")
            return

        result_json = None
        scan_id = None

        try:
            # 2. Check Hash First
            report = self.vt_analyzer.check_hash(file_hash)
            if report:
                logger.info(
                    f"[PayloadManager] Found existing VT report for {file_hash}"
                )

                # Extract useful summary or store full object?
                # vt-py objects are complex. Let's serialize what we can or just storing raw text is risky.
                # Let's try to extract stats.
                try:
                    stats = getattr(report, "last_analysis_stats", {})
                    tags = getattr(report, "tags", [])
                    # Enhanced extraction
                    meaningful_name = getattr(report, "meaningful_name", None)

                    # Extract Code Insights (Google Security Ops / AI)
                    code_insights = None
                    ai_results = getattr(report, "crowdsourced_ai_results", [])
                    if (
                        ai_results
                        and isinstance(ai_results, list)
                        and len(ai_results) > 0
                    ):
                        # Take the first available analysis
                        code_insights = ai_results[0].get("analysis")

                    range_classification = {}
                    ptc = getattr(report, "popular_threat_classification", None)
                    if ptc:
                        classification = {
                            "suggested_threat_label": getattr(
                                ptc, "suggested_threat_label", None
                            ),
                            "popular_threat_category": getattr(
                                ptc, "popular_threat_category", []
                            ),
                        }

                    summary = {
                        "stats": dict(stats) if stats else {},
                        "tags": list(tags) if tags else [],
                        "sha256": getattr(report, "sha256", file_hash),
                        "meaningful_name": meaningful_name,
                        "classification": classification,
                        "code_insights": code_insights,
                    }

                    # Ensure classification nested objects are serializable
                    if classification:
                        # popular_threat_category is usually a list or dict
                        ptc = classification.get("popular_threat_category")
                        if ptc:
                            try:
                                # Try to cast to list if iterable, or dict if mapping
                                # vt-py returns a list of objects usually? or dict?
                                # Safer to just not crash.
                                if hasattr(ptc, "items"):
                                    classification["popular_threat_category"] = dict(
                                        ptc
                                    )
                                elif hasattr(ptc, "__iter__"):
                                    classification["popular_threat_category"] = [
                                        dict(x) if hasattr(x, "items") else str(x)
                                        for x in ptc
                                    ]
                            except:
                                classification["popular_threat_category"] = str(ptc)

                    result_json = json.dumps(summary)
                except Exception as e:
                    logger.error(f"[PayloadManager] Parsing Error: {e}")
                    # Save error as JSON so analyze.py can read it
                    result_json = json.dumps(
                        {"error": f"Parse Error: {e}", "raw": str(report)}
                    )

            # 3. Upload if enabled
            elif config.get("virustotal", "upload_files"):
                if file_path and os.path.exists(file_path):
                    logger.info(f"[PayloadManager] Uploading {file_path} to VT...")
                    analysis = self.vt_analyzer.scan_file(file_path)
                    if analysis:
                        scan_id = analysis.id
                        result_json = json.dumps(
                            {"status": "queued", "scan_id": scan_id}
                        )
                    else:
                        result_json = json.dumps({"error": "upload_failed"})
                else:
                    result_json = json.dumps({"error": "file_not_found"})

            else:
                result_json = json.dumps({"status": "unknown_hash_no_upload"})

            self.db.update_payload_vt_status(payload_id, result_json, scan_id)

        except Exception as e:
            logger.error(f"[PayloadManager] Analysis Error: {e}")
            self.db.update_payload_vt_status(
                payload_id, result=json.dumps({"error": str(e)})
            )

    def _download_file(self, url, timeout=10, max_size=10 * 1024 * 1024):
        """Helper to download with safety limits."""
        try:
            headers = {"User-Agent": "curl/7.68.0"}  # Pretend to be legitimate tool
            with requests.get(
                url, headers=headers, stream=True, timeout=timeout, verify=False
            ) as r:
                r.raise_for_status()

                content = b""
                for chunk in r.iter_content(chunk_size=8192):
                    content += chunk
                    if len(content) > max_size:
                        raise ValueError(f"File exceeds max size ({max_size} bytes)")
                return content
        except Exception as e:
            logger.warning(f"Download failed for {url}: {e}")
            raise e

    def backfill_from_interactions(self):
        """
        One-time scan of interactions table to find missed URLs.
        """
        logger.info("[PayloadManager] Starting historical backfill...")
        try:
            # We fetch all commands. In a huge DB this should be paginated,
            # but for this specific "remove in 1 week" task, we'll strip it simple.
            # Only fetch meaningful commands (e.g. contain http)
            rows = self.db.get_interactions_with_http()

            count = 0
            for row in rows:
                sid = row["session_id"]
                cmd = row["command"]
                ts = row["timestamp"]

                urls = self.extract_urls(cmd)
                for u in urls:
                    # Queue logic handles dedupe
                    # We need IP... finding IP from session might be expensive per row.
                    # We'll rely on DB helper or just pass None and let DB fill it if possible?
                    # Ideally we fetch IP in the query.
                    ip = row.get("remote_ip")
                    self.queue_payload(u, sid, ip, timestamp=ts)
                    count += 1

            logger.info(
                f"[PayloadManager] Backfill complete. Queued {count} potential payloads."
            )

        except Exception as e:
            logger.error(f"Backfill error: {e}")
