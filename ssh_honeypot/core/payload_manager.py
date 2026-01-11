
import os
import re
import hashlib
import time
import requests
import logging
from urllib.parse import urlparse
from datetime import datetime, timedelta

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.config import config, get_data_dir

logger = logging.getLogger(__name__)

PAYLOAD_DIR = os.path.join(get_data_dir(), "payloads")

class PayloadManager:
    def __init__(self, db: HoneyDB):
        self.db = db
        self._ensure_payload_dir()

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
        quoted_pattern = re.compile(r'["\']((?:https?://|(?:[0-9]{1,3}\.){3}[0-9]{1,3}/)[^"\']+)["\']')
        for match in quoted_pattern.findall(text):
             if not match.startswith('http') and not match.startswith('https'):
                  match = 'http://' + match
             urls.add(match)

        # 1. Standard http/https/www URLs (Unquoted, stricter chars)
        # ... existing logic ...
        standard_pattern = re.compile(r'(?:https?://|www\.)[^\s<>"\';|&]+')
        for match in standard_pattern.findall(text):
             # Cleanup trailing punctuation sometimes caught
             match = match.rstrip(".,;:)")
             if not match.startswith('http'):
                 match = 'http://' + match
             urls.add(match)

        # 2. Schemeless IP URLs (e.g. 192.168.1.1/malware.sh)
        # Often used with curl/wget without http://
        # Pattern: IP Address + "/" + Path
        # We enforce at least one slash to avoid matching plain IPs in logs
        ip_url_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[^\s<>"\';|&]+')
        for match in ip_url_pattern.findall(text):
             match = match.rstrip(".,;:)")
             urls.add('http://' + match) # Assume http for raw IPs

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
                return # Invalid URL
                
            if self.db.is_payload_host_rate_limited(hostname):
                logger.info(f"Skipping URL {url} - Host {hostname} rate limited (1/day)")
                return

            # 3. Queue it
            self.db.add_malicious_payload(
                url=url,
                url_hash=url_hash,
                session_id=session_id,
                ip=ip,
                timestamp=timestamp
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
            payload_id = item['id']
            url = item['url']
            
            logger.info(f"[PayloadManager] Processing payload ID {payload_id}: {url}")
            self.db.update_payload_status(payload_id, 'downloading')
            
            try:
                # Download
                content = self._download_file(url)
                if not content:
                    self.db.update_payload_status(payload_id, 'failed', error="Empty or failed download")
                    continue

                # Analyze
                md5 = hashlib.md5(content).hexdigest()
                size = len(content)
                
                # Check Local Cache (Dedup)
                filename = f"dangerous_{md5}.txt"
                file_path = os.path.join(PAYLOAD_DIR, filename)
                
                if os.path.exists(file_path):
                    logger.info(f"[PayloadManager] Payload {url} is duplicate of existing {filename}")
                    # Update DB to point to existing file
                else:
                    # Save
                    with open(file_path, 'wb') as f:
                        f.write(content)
                    logger.info(f"[PayloadManager] Saved new payload to {file_path}")

                self.db.update_payload_status(
                    payload_id, 
                    'completed', 
                    payload_md5=md5, 
                    payload_size=size, 
                    file_path=file_path
                )

            except Exception as e:
                logger.error(f"Failed to download payload {url}: {e}")
                self.db.update_payload_status(payload_id, 'failed', error=str(e))

    def _download_file(self, url, timeout=10, max_size=10*1024*1024):
        """Helper to download with safety limits."""
        try:
            headers = {'User-Agent': 'curl/7.68.0'} # Pretend to be legitimate tool
            with requests.get(url, headers=headers, stream=True, timeout=timeout, verify=False) as r:
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
                sid = row['session_id']
                cmd = row['command']
                ts = row['timestamp']
                
                urls = self.extract_urls(cmd)
                for u in urls:
                    # Queue logic handles dedupe
                    # We need IP... finding IP from session might be expensive per row.
                    # We'll rely on DB helper or just pass None and let DB fill it if possible?
                    # Ideally we fetch IP in the query.
                    ip = row.get('remote_ip')
                    self.queue_payload(u, sid, ip, timestamp=ts)
                    count += 1
            
            logger.info(f"[PayloadManager] Backfill complete. Queued {count} potential payloads.")
            
        except Exception as e:
            logger.error(f"Backfill error: {e}")

