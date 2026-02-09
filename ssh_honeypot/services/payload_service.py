import logging
import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Union

from ssh_honeypot.core.database import get_db_backend
from ssh_honeypot.core.config import config
from ssh_honeypot.core.utils import get_data_dir

logger = logging.getLogger(__name__)

try:
    from ssh_honeypot.core.analyzers.virustotal import VirusTotalAnalyzer
except ImportError:
    VirusTotalAnalyzer = None


class PayloadService:
    """
    Service for managing malicious payloads, including retrieval,
    updates, and VirusTotal integration.
    """

    def __init__(self, db=None):
        self.db = db or get_db_backend()
        self.vt_analyzer = None
        if VirusTotalAnalyzer and config.get("virustotal", "enabled"):
            try:
                self.vt_analyzer = VirusTotalAnalyzer()
            except Exception as e:
                logger.error(f"[PayloadService] Failed to init VirusTotal: {e}")

    def get_payload_by_md5(self, md5: str) -> Optional[Dict]:
        """
        Retrieves full payload details by MD5.
        Merges data from malicious_payloads and payload_analysis tables.
        """
        try:
            # We can use the existing DB method if available, or query directly.
            # AnalyticsEngine had get_payload_details, but that includes occurrences.
            # Let's query base info first.

            # This relies on the method we moved to AnalyticsEngine, but we might want
            # a pure data retrieval here or call AnalyticsEngine?
            # User wants a "Payload Service" to be the authority.
            # So let's implement the retrieval logic here cleanly.

            conn = self.db._get_conn()
            cursor = conn.cursor()

            # Get Analysis Data
            query_analysis = f"SELECT * FROM payload_analysis WHERE payload_md5 = {self.db.placeholder}"
            cursor.execute(query_analysis, (md5,))
            analysis_row = cursor.fetchone()

            analysis_data = {}
            if analysis_row and cursor.description:
                columns = [col[0] for col in cursor.description]
                analysis_data = dict(zip(columns, analysis_row))

            # Get Base Data (Pick the first/oldest one for this MD5)
            # We need ID, URL, Status, etc.
            query_base = f"SELECT * FROM malicious_payloads WHERE payload_md5 = {self.db.placeholder} ORDER BY timestamp ASC LIMIT 1"
            cursor.execute(query_base, (md5,))
            base_row = cursor.fetchone()

            base_data = {}
            if base_row and cursor.description:
                columns = [col[0] for col in cursor.description]
                base_data = dict(zip(columns, base_row))

            if not base_data and not analysis_data:
                return None

            # Merge: Analysis data overrides base data for shared fields if any
            # (though they are mostly distinct) - BUT preserve file_path if analysis has it as None
            combined = {**base_data, **analysis_data}

            if not combined.get("file_path") and base_data.get("file_path"):
                combined["file_path"] = base_data["file_path"]

            # Parse JSON fields if string
            if isinstance(combined.get("virustotal_result"), str):
                try:
                    combined["virustotal_result"] = json.loads(
                        combined["virustotal_result"]
                    )
                except:
                    pass

            # Fetch Recent Sessions (Context)
            if base_data.get("id"):
                p_id = base_data["id"]
                query_sessions = f"""
                    SELECT s.session_id, s.start_time, s.remote_ip, s.protocol, s.username
                    FROM payload_requests pr
                    JOIN sessions s ON pr.session_id = s.session_id
                    WHERE pr.payload_id = {self.db.placeholder}
                    ORDER BY pr.timestamp DESC
                    LIMIT 5
                """
                cursor.execute(query_sessions, (p_id,))
                sessions = []
                if cursor.description:
                    sess_cols = [col[0] for col in cursor.description]
                    sessions = [dict(zip(sess_cols, row)) for row in cursor.fetchall()]
                combined["recent_sessions"] = sessions

            return combined
        except Exception as e:
            logger.error(f"[PayloadService] Error fetching payload {md5}: {e}")
            return None
        finally:
            if "conn" in locals():
                conn.close()

    def update_payload_risk_score(self, md5: str, score: int) -> bool:
        """
        Updates the risk score for a payload.
        """
        if not md5:
            return False
        try:
            # We need to ensure the entry exists in payload_analysis
            self._ensure_analysis_entry(md5)

            conn = self.db._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE payload_analysis SET risk_score = {self.db.placeholder} WHERE payload_md5 = {self.db.placeholder}",
                (score, md5),
            )
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"[PayloadService] Error updating risk score for {md5}: {e}")
            return False
        finally:
            if "conn" in locals():
                conn.close()

    def update_payload_tags(self, md5: str, tags: List[str]) -> bool:
        """
        Updates tags for a payload.
        Since we don't have a dedicated tags column, we will update the
        'virustotal_result' JSON's 'tags' field or use 'analysis_summary' if appropriate.

        Decided approach: Update 'virustotal_result' JSON 'custom_tags' or just 'tags'.
        """
        if not md5:
            return False
        try:
            current = self.get_payload_by_md5(md5)
            if not current:
                return False

            vt_result = current.get("virustotal_result") or {}

            # Ensure it's a dict (get_payload_by_md5 handles parsing)
            if not isinstance(vt_result, dict):
                vt_result = {}

            # Update tags
            vt_result["tags"] = tags

            # Save back
            return self._update_vt_result(md5, vt_result)
        except Exception as e:
            logger.error(f"[PayloadService] Error updating tags for {md5}: {e}")
            return False

    def submit_to_virustotal(self, md5: str, raw_content: bytes = None) -> Dict:
        """
        Submits a payload to VirusTotal for analysis.
        If raw_content is provided, it can handle upload (if enabled).
        Otherwise it just checks the hash.
        """
        if not self.vt_analyzer:
            return {
                "status": "error",
                "message": "VirusTotal integration disabled or unavailable",
            }

        try:
            # 1. Check Hash
            report = self.vt_analyzer.check_hash(md5)
            if report:
                # Process result similar to PayloadManager
                result_json = self._process_vt_report(report, md5)
                self._update_vt_result(md5, json.loads(result_json))
                return {"status": "found", "data": json.loads(result_json)}

            # 2. Upload if content provided and enabled
            if raw_content and config.get("virustotal", "upload_files"):
                # We need a temp file for the analyzer
                import tempfile
                import os

                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(raw_content)
                    tmp_path = tmp.name

                try:
                    analysis = self.vt_analyzer.scan_file(tmp_path)
                    if analysis:
                        return {"status": "queued", "scan_id": analysis.id}
                    else:
                        return {"status": "error", "message": "Upload failed"}
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)

            return {
                "status": "not_found",
                "message": "Hash not found in VT and upload not performed",
            }

        except Exception as e:
            logger.error(f"[PayloadService] VT Submit Error: {e}")
            return {"status": "error", "message": str(e)}

    def _ensure_analysis_entry(self, md5: str):
        """Creates a row in payload_analysis if it doesn't exist."""
        # Simple check-and-insert
        conn = self.db._get_conn()
        try:
            cursor = conn.cursor()
            query_check = f"SELECT 1 FROM payload_analysis WHERE payload_md5 = {self.db.placeholder}"
            cursor.execute(query_check, (md5,))
            if not cursor.fetchone():
                query_insert = f"INSERT INTO payload_analysis (payload_md5) VALUES ({self.db.placeholder})"
                cursor.execute(query_insert, (md5,))
                conn.commit()
        finally:
            conn.close()

    def _update_vt_result(self, md5: str, result: Dict) -> bool:
        """Helper to update the JSON result in DB."""
        self._ensure_analysis_entry(md5)
        conn = self.db._get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE payload_analysis SET virustotal_result = {self.db.placeholder} WHERE payload_md5 = {self.db.placeholder}",
                (json.dumps(result), md5),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def _process_vt_report(self, report, md5):
        """
        Extracts relevant data from VT report object.
        Reused logic from PayloadManager roughly.
        """
        try:
            stats = getattr(report, "last_analysis_stats", {})
            tags = getattr(report, "tags", [])
            summary = {
                "stats": dict(stats) if stats else {},
                "tags": list(tags) if tags else [],
                "sha256": getattr(report, "sha256", md5),
                "last_analysis_date": getattr(report, "last_analysis_date", None),
            }
            return json.dumps(summary)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def get_payload_content(self, md5: str) -> Optional[bytes]:
        """
        Retrieves the raw content of a payload file.
        """
        p = self.get_payload_by_md5(md5)
        if not p:
            return None

        file_path = p.get("file_path")
        if not file_path or not os.path.exists(file_path):
            return None

        try:
            with open(file_path, "rb") as f:
                return f.read()
        except Exception as e:
            logger.error(f"[PayloadService] Error reading payload {md5}: {e}")
            return None

    def get_payload_stats(self, hours: int = 24) -> Dict:
        """
        Generates statistics about payloads.
        """
        stats = {
            "period_hours": hours,
            "total_new": 0,
            "pending_review": 0,
            "risk_distribution": {"high": 0, "medium": 0, "low": 0, "unknown": 0},
            "service_breakdown": {},
        }

        conn = self.db._get_conn()
        try:
            cursor = conn.cursor()
            ph = self.db.placeholder

            # 1. Total New in last N hours
            # Timestamp in malicious_payloads is usually ISO string or datetime
            # We need to handle DB differences for time comparison if possible,
            # but usually python datetime param works with adapters.

            limit_dt = datetime.now() - timedelta(hours=hours)

            query_total = (
                f"SELECT count(*) FROM malicious_payloads WHERE timestamp >= {ph}"
            )
            cursor.execute(query_total, (limit_dt,))
            result = cursor.fetchone()
            stats["total_new"] = result[0] if result else 0

            # 2. Risk Distribution (Overall, not just recent? User asked "what % is marked...")
            # Let's do it for ALL payloads to give a better picture, or recent?
            # User Context: "how many payloads in last 24 hours... what % is marked..."
            # Usually stats are for the window, but risk score logic applies to the library.
            # Let's do it for ALL payloads for the Risk Distribution as that's more useful for "Library Health".
            # Or filter by recent if the user implied everything in 24h.
            # "Stats should include - how many payloads in last 24 hours ... what % is marked..."
            # It's ambiguous. Let's provide Risk Distribution for *Active* (non-failed) payloads over all time?
            # Or just satisfy the request specifically for the "dashboard" view of "Recent Activity".
            # Let's do Risk Distribution for RECENT items first (matching the 24h window).

            # Actually, "Pending to be reviewed" implies a backlog, which is global.
            # So let's do:
            # - Activity (New, Service Breakdown) -> Last 24h
            # - Health (Pending, Risk Dist) -> Global (or maybe just recent? Global is better for operational awareness)

            # Let's do Global for Pending/Risk to be safe/useful.

            # Pending Review: Status=completed AND (Risk Score is 0 OR NULL)
            # Assuming "Review" means assigning a risk score/tags.
            query_pending = "SELECT count(*) FROM malicious_payloads mp LEFT JOIN payload_analysis pa ON mp.payload_md5 = pa.payload_md5 WHERE mp.status = 'completed' AND (pa.risk_score IS NULL OR pa.risk_score = 0)"
            cursor.execute(query_pending)
            result = cursor.fetchone()
            stats["pending_review"] = result[0] if result else 0

            # Risk Distribution (Global)
            query_risk = "SELECT risk_score FROM payload_analysis WHERE risk_score > 0"
            cursor.execute(query_risk)
            scores = [r[0] for r in cursor.fetchall()]  # Tuple index 0

            for s in scores:
                if s >= 70:
                    stats["risk_distribution"]["high"] += 1
                elif s >= 30:
                    stats["risk_distribution"]["medium"] += 1
                else:
                    stats["risk_distribution"]["low"] += 1
            # Unknown is basically pending (score 0/null) which we counted above, but let's separate "scored 0" vs "null" if needed.
            # We already counted >0.

            # 3. Service Breakdown (Last 24h)
            # Join malicious_payloads -> payload_requests -> sessions
            # MP (id) <-> PR (payload_id)
            # PR (session_id) <-> S (session_id)

            query_service = f"""
                SELECT s.protocol, count(*) 
                FROM malicious_payloads mp
                JOIN payload_requests pr ON mp.id = pr.payload_id
                JOIN sessions s ON pr.session_id = s.session_id
                WHERE mp.timestamp >= {ph}
                GROUP BY s.protocol
            """
            cursor.execute(query_service, (limit_dt,))
            rows = cursor.fetchall()
            for r in rows:
                # r is (protocol, count)
                proto = r[0] or "unknown"
                count = r[1]
                stats["service_breakdown"][proto] = count

        except Exception as e:
            logger.error(f"[PayloadService] Stats Error: {e}")
            import traceback

            traceback.print_exc()
        finally:
            conn.close()

    def detect_payload_type(self, md5: str) -> str:
        """
        Determines if a payload is Binary or Text.
        Logic:
        1. Check content.
        2. Fast Check: Magic Bytes (ELF, PE, Mach-O, Shebang).
        3. Null Byte Check.
        4. Heuristic: Printable Character Ratio ("Strings" check).
           - If printable content is significantly less than total size, it's Binary.
        """
        content = self.get_payload_content(md5)
        if content is None:
            return "Unknown (No Content)"

        if not content:
            return "Empty"

        # 1. Magic Bytes (Fast Path)
        if content.startswith(b"\x7fELF"):
            return "Binary (ELF)"
        if content.startswith(b"MZ"):
            return "Binary (PE)"
        if content.startswith(b"\xfeed\xfa\xce") or content.startswith(
            b"\xfeed\xfa\xcf"
        ):
            return "Binary (Mach-O)"
        if content.startswith(b"\xca\xfe\xba\xbe"):
            return "Binary (Java/Mach-O)"

        # Shebang usually implies Text (script), but let's double check content
        if content.startswith(b"#!"):
            # Scripts are text, unless they have binary data appended
            # We can tentatively say Text, but let the ratio check confirm if it's a wrapper
            pass

        # 2. Null Bytes (Strong indicator for binary vs text)
        # However, some text files (UTF-16) might have nulls. We assume UTF-8/ASCII for "Text".
        if b"\x00" in content:
            # Check if it's UTF-16? Uncommon for malware payloads here (usually ELF/Shell script).
            # Assume Binary for now.
            return "Binary"

        # 3. Printable Ratio ("Strings" Heuristic)
        # We calculate the ratio of text characters to total characters.
        # Text chars: 32-126 (ASCII printable) + 9 (tab) + 10 (LF) + 13 (CR)
        # We also allow UTF-8 sequences if they decode validly.

        try:
            # Try decoding as UTF-8 first
            text_content = content.decode("utf-8")
        except UnicodeDecodeError:
            return "Binary (Invalid UTF-8)"

        # Count control characters in the decoded text
        # text_content is now a unicode string.
        # Python's isprintable() works well for Unicode (handles emojis as printable).
        # However, it excludes \t, \n, \r which are valid in text files.

        # We want to identify "Garbage" vs "Text".
        # Suspicious: C0 controls (0-31) except 9, 10, 13
        # C1 controls (128-159) - usually handled by isprintable() as False?

        total_chars = len(text_content)
        if total_chars == 0:
            return "Empty"

        suspicious_count = 0

        # Sample first 4096 chars for speed
        sample_text = text_content[:4096]

        for char in sample_text:
            if not char.isprintable() and char not in ("\t", "\n", "\r"):
                suspicious_count += 1

        ratio = suspicious_count / len(sample_text)

        # Threshold:
        # If > 10% suspicious characters (unprintable controls), it's likely binary
        # (even if it coincidentally decodes as valid UTF-8).
        if ratio > 0.10:
            return f"Binary (High Entropy/Controls {ratio:.0%})"

        return "Text"

    def list_payloads(self, limit: int = 50) -> List[Dict]:
        """
        Lists recent payloads with details for CLI view.
        Returns a list of dictionaries.
        """
        conn = self.db._get_conn()
        try:
            cursor = conn.cursor()

            # Base Query - Fetch recent downloads
            query = f"""
                SELECT 
                    mp.id,
                    mp.url,
                    mp.timestamp,
                    mp.status,
                    mp.payload_size,
                    mp.payload_md5,
                    mp.error_message,
                    mp.method,
                    pa.virustotal_result,
                    pa.risk_score,
                    pa.analysis_summary
                FROM malicious_payloads mp
                LEFT JOIN payload_analysis pa ON mp.payload_md5 = pa.payload_md5
                WHERE mp.status != 'failed'
                ORDER BY mp.id DESC
                LIMIT {self.db.placeholder}
            """

            cursor.execute(query, (limit,))

            if cursor.description:
                columns = [col[0] for col in cursor.description]
                rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
            else:
                rows = []

            # Enrich with IPs
            for row in rows:
                p_id = row["id"]
                # Fetch IPs associated with this download/request
                # Note: payload_requests links payload_id (pk) to IPs
                cursor.execute(
                    f"SELECT DISTINCT ip FROM payload_requests WHERE payload_id = {self.db.placeholder}",
                    (p_id,),
                )
                ips = [
                    r[0]
                    for r in cursor.fetchall()
                    if r[0] and r[0].strip().lower() != "unknown"
                ]
                row["ip_list"] = ips

            return rows

        except Exception as e:
            logger.error(f"[PayloadService] Error listing payloads: {e}")
            return []
        finally:
            conn.close()
