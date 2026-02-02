import os
import re
import hashlib
import time
import requests
import logging
import json
import ipaddress
import socket
from urllib.parse import urlparse
from datetime import datetime, timedelta

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.config import config, get_data_dir
from ssh_honeypot.core.utils import (
    sanitize_path,
    extract_snippet,
    get_storable_content,
    resolve_sanitized_path,
)
from ssh_honeypot.core.universal_cache import universal_cache

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
                    self.vt_analyzer.close()
                    self.vt_analyzer = None
                else:
                    logger.info("[PayloadManager] VirusTotal Analyzer Enabled.")
            except Exception as e:
                if self.vt_analyzer:
                    self.vt_analyzer.close()
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

    def queue_payload(
        self,
        url,
        session_id,
        ip,
        timestamp=None,
        method="GET",
        user_agent=None,
        command_text=None,
    ):
        """
        Adds a URL to the download queue if permitted.
        Enforces 1 request per host per day logic.
        """
        try:
            # 1. Deduplicate by exact URL
            url_hash = hashlib.md5(url.encode()).hexdigest()

            # 2. Host Rate Limiting (1 per day)
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False  # Invalid URL

            if self.db.is_payload_host_rate_limited(hostname):
                logger.debug(f"Skipping URL {url} - Host {hostname} rate limited")
                return False

            # 3. Smart Deduplication & Backoff
            existing = self.db.get_malicious_payload_by_hash(url_hash)
            if existing:
                status = existing.get("status")
                last_attempt = existing.get("timestamp")

                # Case A: Already pending/downloading
                if status in ["pending", "downloading", "discovered"]:
                    logger.debug(
                        f"Skipping URL {url} - Already in queue (status: {status})"
                    )
                    return False

                # Case B: Recently failed (Backoff 48h)
                if status == "failed" and last_attempt:
                    # Parse timestamp if it's a string (Postgres might return string)
                    if isinstance(last_attempt, str):
                        try:
                            last_attempt = datetime.fromisoformat(
                                last_attempt.split(".")[0]
                            )
                        except:
                            last_attempt = datetime.now()

                    backoff_limit = datetime.now() - timedelta(hours=48)
                    if last_attempt > backoff_limit:
                        logger.debug(
                            f"Skipping URL {url} - Recently failed (Backoff until {last_attempt + timedelta(hours=48)})"
                        )
                        return False

                # Case C: Completed/Analyzed - We might still want to log the "hit" for stats
                # but we don't necessarily need to re-download.
                # add_malicious_payload handles hitting the DB anyway.

            # 4. Queue it
            added = self.db.add_malicious_payload(
                url=url,
                url_hash=url_hash,
                session_id=session_id,
                ip=ip,
                timestamp=timestamp,
                method=method,
                user_agent=user_agent,
                command_text=command_text,
            )
            if added:
                logger.info(f"[PayloadManager] Queued suspicious URL: {url}")
                return True
            return False

        except Exception as e:
            logger.error(f"Error queuing payload {url}: {e}")
            return False

    def queue_upload(self, filename, content, session_id, ip, timestamp=None):
        """
        Integrates an uploaded file into the payload analysis system.
        Skips downloading since we already have the content.
        """
        try:
            if not content:
                return False

            if isinstance(content, str):
                content_bytes = content.encode("utf-8")
            else:
                content_bytes = content

            md5 = hashlib.md5(content_bytes).hexdigest()
            size = len(content_bytes)

            # Use filename in the "URL" column to identify source
            url = f"upload://{filename}"
            url_hash = hashlib.md5(url.encode()).hexdigest()

            # Save to payload directory
            storage_filename = f"dangerous_{md5}.txt"
            file_path = os.path.join(PAYLOAD_DIR, storage_filename)

            if not os.path.exists(file_path):
                with open(file_path, "wb") as f:
                    f.write(content_bytes)
                logger.info(
                    f"[PayloadManager] Saved uploaded payload to {sanitize_path(file_path)}"
                )

            snippet = extract_snippet(content_bytes)
            db_content, is_binary = get_storable_content(content_bytes)

            # Add to DB as 'completed' (ready for analysis)
            added = self.db.add_malicious_payload(
                url=url,
                url_hash=url_hash,
                session_id=session_id,
                ip=ip,
                timestamp=timestamp or datetime.now(),
                status="completed",
                analysis_stage="Analyzed",  # Already have content
                file_path=file_path,
                payload_md5=md5,
                payload_size=size,
                snippet=snippet,
                content=db_content,
                is_binary=is_binary,
            )

            if added:
                # Update status if already exists (deduplication case)
                payload = self.db.get_payload_by_hash(url_hash)
                if payload:
                    self.db.update_payload_status(
                        payload["id"],
                        "completed",
                        analysis_stage="Analyzed",
                        payload_md5=md5,
                        payload_size=size,
                        file_path=file_path,
                        snippet=snippet,
                        content=db_content,
                        is_binary=is_binary,
                    )
                logger.info(
                    f"[PayloadManager] Queued uploaded file for analysis: {filename}"
                )
                return True
            return False

        except Exception as e:
            logger.error(f"Error queuing upload {filename}: {e}")
            return False

    def process_queue(self, limit=5):
        """
        Main worker function. fetches pending items and downloads them.
        Returns list of processed items summary.
        """
        pending = self.db.get_pending_payloads(limit=limit)
        results = []

        for item in pending:
            payload_id = item["id"]
            url = item["url"]

            logger.info(f"[PayloadManager] Processing payload ID {payload_id}: {url}")
            self.db.update_payload_status(payload_id, "downloading")

            try:
                # Download
                content = self.download_file(url)
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
                        f"[PayloadManager] Payload {url} is duplicate of existing {filename} (MD5: {md5}). Skipping download/save."
                    )
                    # Update DB to point to existing file
                else:
                    # Save
                    with open(file_path, "wb") as f:
                        f.write(content)
                    logger.info(
                        f"[PayloadManager] Saved new payload to {sanitize_path(file_path)}"
                    )

                # Capture snippet and full content (up to 1MB)
                snippet = extract_snippet(content)
                db_content, is_binary = get_storable_content(content)

                self.db.update_payload_status(
                    payload_id,
                    "completed",
                    analysis_stage="Downloaded",
                    payload_md5=md5,
                    payload_size=size,
                    file_path=file_path,
                    snippet=snippet,
                    content=db_content,
                    is_binary=is_binary,
                )

                results.append(
                    {"id": payload_id, "url": url, "status": "Downloaded", "size": size}
                )

            except Exception as e:
                logger.error(f"Failed to download payload {url}: {e}")
                self.db.update_payload_status(payload_id, "failed", error=str(e))
                results.append(
                    {"id": payload_id, "url": url, "status": "Failed", "error": str(e)}
                )

        return results

    def process_analysis_queue(self, limit=1, force=False):
        """
        Background job to analyze downloaded payloads with VT.
        Rate Limit is enforced by the Analyzer class.
        Returns list of processed items.
        """
        if not force and not config.get("virustotal", "enabled"):
            return []

        if not self.vt_analyzer:
            # Try to init if forced or just available
            if VirusTotalAnalyzer:
                try:
                    self.vt_analyzer = VirusTotalAnalyzer()
                except:
                    pass

            if not self.vt_analyzer:
                return []

        # Check rate limit before fetching items to avoid log spam if we are already blocked
        if not force and not self.vt_analyzer._check_rate_limit():
            return []

        # Fetch Unanalyzed, Completed Payloads
        items = self.db.get_pending_analysis_payloads(limit=limit)
        results = []

        for item in items:
            try:
                self.analyze_payload(item, force=force)
                results.append(
                    {"id": item["id"], "md5": item["payload_md5"], "status": "Analyzed"}
                )
            except Exception as e:
                results.append(
                    {
                        "id": item["id"],
                        "md5": item.get("payload_md5", "?"),
                        "status": "Failed",
                        "error": str(e),
                    }
                )

        return results

    def analyze_payload(self, item, force=False):
        payload_id = item["id"]
        file_path = resolve_sanitized_path(item.get("file_path"))
        file_hash = item["payload_md5"]
        file_size = item["payload_size"] or 0

        # Self-Healing: If file_path is missing or invalid, try to recover from MD5
        if not file_path or not os.path.exists(file_path):
            if file_hash:
                potential_path = os.path.join(PAYLOAD_DIR, f"dangerous_{file_hash}.txt")
                if os.path.exists(potential_path):
                    logger.warning(
                        f"[PayloadManager] Path Recovery: Found missing payload {payload_id} at {potential_path}"
                    )
                    file_path = potential_path
                    # Update DB for future
                    self.db.update_payload_file_path(
                        payload_id, file_path
                    )  # Need to implement this or just rely on runtime fix

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
                    classification = None
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

            # Determine Stage
            analysis_stage = "Analyzed"
            if result_json:
                try:
                    data = json.loads(result_json)
                    stats = data.get("stats", {})
                    if stats.get("malicious", 0) > 0:
                        analysis_stage = "hasRiskDecision"
                    elif data.get("status") == "queued":
                        analysis_stage = "QueueForAnalysis"
                except:
                    pass

            self.db.update_payload_status(
                payload_id,
                status="completed",
                analysis_stage=analysis_stage,
                vt_last_scanned=datetime.now().isoformat(),
                **({"vt_scan_id": scan_id} if scan_id else {}),
            )

            # Save to Deduped Analysis Table
            if result_json:
                # Extract risk score if we can for the DB index
                risk_score = 0
                explanation = ""
                try:
                    data = json.loads(result_json)
                    stats = data.get("stats", {})
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        risk_score = min(malicious * 10, 100)
                        explanation = f"Flagged by {malicious} engines"
                    elif "error" in data:
                        explanation = "Analysis Error"
                except:
                    pass

                self.db.update_payload_analysis(
                    payload_md5=file_hash,
                    virustotal_result=result_json,
                    risk_score=risk_score,
                    analysis_summary=explanation,
                    vt_last_scanned=datetime.now().isoformat(),
                    payload_size=file_size,
                    file_path=file_path,
                )

        except Exception as e:
            logger.error(f"[PayloadManager] Analysis Error: {e}")
            error_json = json.dumps({"error": str(e)})
            self.db.update_payload_status(payload_id, status="failed", error=str(e))
            self.db.update_payload_analysis(
                payload_md5=file_hash,
                virustotal_result=error_json,
                analysis_summary="Analysis Failed",
            )

    def _is_safe_url(self, url):
        """
        Validates URL to prevent SSRF and internal scanning.
        Blocks:
        - Basic Auth Credentials (user:pass@...)
        - Private IPs (RFC1918)
        - Loopback / Link-Local IPs
        - Non-HTTP schemes
        """
        try:
            parsed = urlparse(url)

            # 1. Scheme Check
            if parsed.scheme not in ("http", "https"):
                return False, "Invalid scheme"

            # 2. Basic Auth Check
            if parsed.username or parsed.password:
                return False, "Basic Auth detected"

            hostname = parsed.hostname
            if not hostname:
                return False, "No hostname"

            # 3. DNS Resolution & IP Check
            try:
                # Use getaddrinfo to handle IPv4/IPv6
                # This returns a list of (family, socktype, proto, canonname, sockaddr)
                addr_info = socket.getaddrinfo(hostname, None)
                found_ips = [info[4][0] for info in addr_info]
            except socket.gaierror:
                return False, "DNS resolution failed"

            for ip_str in found_ips:
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_loopback:
                        return False, f"Loopback IP detected: {ip_str}"
                    if ip.is_link_local:
                        return False, f"Link-Local IP detected: {ip_str}"
                    if ip.is_private:
                        return False, f"Private IP detected: {ip_str}"
                    # Reserved/Multicast could also be blocked, but private covers most risks
                    if ip.is_reserved:  # Covers some other ranges
                        return False, f"Reserved IP detected: {ip_str}"
                except ValueError:
                    continue  # Should not happen with getaddrinfo results

            return True, "Safe"

        except Exception as e:
            return False, f"Validation error: {e}"

    def download_file(self, url, timeout=10, max_size=10 * 1024 * 1024):
        """Helper to download with safety limits."""
        # Pre-flight SSRF Check
        is_safe, reason = self._is_safe_url(url)
        if not is_safe:
            logger.warning(f"[PayloadManager] SSRF Blocked: {url} -> {reason}")
            raise ValueError(f"SSRF Protection Blocked: {reason}")

        try:
            # We use a realistic User-Agent to avoid blocks
            headers = {"User-Agent": "curl/7.81.0"}
            r = requests.get(
                url, headers=headers, stream=True, timeout=timeout, verify=False
            )
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

    def download_and_analyze_sync(self, url, session_id, remote_ip):
        """
        Synchronously download and queue for analysis.
        Returns the content if successful.
        """
        try:
            content = self.download_file(url)
            if content:
                # Store it in the payload directory and DB immediately
                md5 = hashlib.md5(content).hexdigest()
                url_hash = hashlib.md5(url.encode()).hexdigest()

                # Double check cache
                cached = universal_cache.get("payload_download", url_hash)
                if cached:
                    return cached.get("output_bytes") or cached.get("output_text")

                filename = f"dangerous_{md5}.txt"
                file_path = os.path.join(PAYLOAD_DIR, filename)

                if not os.path.exists(file_path):
                    with open(file_path, "wb") as f:
                        f.write(content)

                # Capture snippet (first 500 chars)
                snippet = extract_snippet(content)

                # Add to DB
                self.db.add_malicious_payload(
                    url=url,
                    url_hash=url_hash,
                    session_id=session_id,
                    ip=remote_ip,
                    status="completed",
                    payload_md5=md5,
                    payload_size=len(content),
                    file_path=file_path,
                    snippet=snippet,
                )

                # Save to Universal Cache
                universal_cache.set(
                    service="payload_download",
                    key=url_hash,
                    input_text=url,
                    output_text=content,
                    is_binary=True,
                    ttl_days=30,
                )

                return content
        except Exception as e:
            logger.error(f"[PayloadManager] Sync download failed for {url}: {e}")
        return None

    def backfill_from_interactions(self):
        """
        One-time scan of interactions table to find missed URLs.
        Optimized with batch processing.
        """
        logger.info("[PayloadManager] Starting historical backfill...")
        try:
            # We fetch all commands. In a huge DB this should be paginated,
            # but for this specific "remove in 1 week" task, we'll strip it simple.
            # Only fetch meaningful commands (e.g. contain http)
            rows = self.db.get_interactions_with_http()
            if not rows:
                return

            potential_payloads = []
            seen_hashes = set()
            host_rate_limit_cache = {}
            total_potential = 0

            for row in rows:
                sid = row["session_id"]
                cmd = row["command"]
                ts = row["timestamp"]
                ip = row.get("remote_ip")

                urls = self.extract_urls(cmd)
                for u in urls:
                    total_potential += 1
                    url_hash = hashlib.md5(u.encode()).hexdigest()

                    # Avoid duplicate processing in the same loop
                    if url_hash in seen_hashes:
                        continue

                    # Host Rate Limiting check
                    parsed = urlparse(u)
                    hostname = parsed.hostname
                    if not hostname:
                        continue

                    if hostname in host_rate_limit_cache:
                        if host_rate_limit_cache[hostname]:
                            continue
                    else:
                        is_limited = self.db.is_payload_host_rate_limited(hostname)
                        host_rate_limit_cache[hostname] = is_limited
                        if is_limited:
                            continue

                    potential_payloads.append(
                        {
                            "url": u,
                            "url_hash": url_hash,
                            "session_id": sid,
                            "ip": ip,
                            "timestamp": ts,
                        }
                    )
                    seen_hashes.add(url_hash)

                    # Batch flush to DB
                    if len(potential_payloads) >= 500:
                        self.db.batch_add_malicious_payloads(potential_payloads)
                        potential_payloads = []

            # Final batch
            if potential_payloads:
                self.db.batch_add_malicious_payloads(potential_payloads)

            logger.info(
                f"[PayloadManager] Backfill complete. Scanned {len(rows)} commands, found {total_potential} URLs, queued in batches."
            )

        except Exception as e:
            logger.error(f"Backfill error: {e}")
