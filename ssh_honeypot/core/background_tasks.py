import time
import os
import json
import hashlib
from urllib.parse import urlparse
from datetime import datetime
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from ssh_honeypot.core.alert_manager import AlertManager
from ssh_honeypot.core.job_scheduler import JobScheduler

try:
    from ssh_honeypot.core.ip_enrichment import IPEnricher
except ImportError:
    IPEnricher = None

# Global Scheduler Instance
scheduler = JobScheduler()

# Recovery cursor (in-memory)
_payload_recovery_cursor = 0


def run_cleanup_job(db_instance):
    """Prunes old uploads and payloads."""
    try:
        days = config.get("upload", "cleanup_days") or 30
        db_instance.prune_uploads(days)

        # Cleanup Payloads
        from ssh_honeypot.core.payload_manager import PAYLOAD_DIR
        import time as ttime

        cutoff = ttime.time() - (days * 86400)
        if os.path.exists(PAYLOAD_DIR):
            for f in os.listdir(PAYLOAD_DIR):
                fp = os.path.join(PAYLOAD_DIR, f)
                if os.path.isfile(fp):
                    if os.path.getmtime(fp) < cutoff:
                        try:
                            os.remove(fp)
                            log.info(f"[Cleanup] Removed old payload: {f}")
                        except Exception as e:
                            log.error(f"[Cleanup] Failed to remove payload {f}: {e}")
    except Exception as e:
        log.error(f"[Cleanup] Error: {e}")


def run_analysis_batch(db_instance, llm_instance, alert_manager):
    """Analyzes a batch of commands."""
    try:
        enabled_services = config.get("analytics", "enabled_services")
        batch_size = int(config.get("analytics", "batch_size") or 10)

        commands = db_instance.get_unanalyzed_commands(
            limit=batch_size, allowed_protocols=enabled_services
        )
        if not commands:
            return

        # Batching Logic: Process if full batch OR timeout exceeded (1 hour)
        should_process = False
        if len(commands) >= batch_size:
            should_process = True
        else:
            # Check for stale commands (Timeout fallback)
            for cmd in commands:
                try:
                    ts_str = cmd.get("last_seen")
                    if ts_str:
                        # Handle potential SQLite formats
                        if "." in ts_str:
                            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
                        else:
                            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")

                        # 1 Hour Timeout
                        if (datetime.now() - ts).total_seconds() > 3600:
                            should_process = True
                            log.debug(
                                f"[Analysis] Processing partial batch (Timeout: {len(commands)} items)"
                            )
                            break
                except Exception:
                    # If parsing fails, default to processing to avoid getting stuck
                    should_process = True
                    break

        if not should_process:
            return

        log.info(f"[Analysis] processing batch of {len(commands)} commands")

        results = llm_instance.analyze_batch(
            [(c["request_md5"], c["command"]) for c in commands]
        )

        if not results:
            log.warning(
                "[Analysis] Batch analysis returned no results. Skipping this batch to allow retry."
            )
            return

        for cmd_row in commands:
            cmd_hash = cmd_row["request_md5"]
            cmd_text = cmd_row["command"]
            session_id = cmd_row["session_id"]
            ip = cmd_row["remote_ip"]

            analysis = results.get(cmd_hash)
            if analysis:
                db_instance.save_command_analysis(
                    cmd_hash,
                    cmd_text,
                    analysis.get("activity_type", "unknown"),
                    analysis.get("stage", "unknown"),
                    int(analysis.get("risk", 0)),
                    analysis.get("explanation", ""),
                )
                # Helper for alerts
                try:
                    score = analysis.get("risk", 0)
                    explanation = analysis.get("explanation", "")
                    alert_manager.check_risk_score(session_id, ip, score, explanation)
                except Exception:
                    pass

    except Exception as e:
        log.error(f"[Analysis] Error: {e}")


def run_session_analysis_batch(db_instance, llm_instance):
    """Summarizes missed sessions."""
    try:
        from ssh_honeypot.core.session_analyzer import analyze_session

        sessions = db_instance.get_unanalyzed_sessions(limit=20)
        if not sessions:
            return

        for session_id in sessions:
            analyze_session(session_id, db=db_instance, llm=llm_instance)
    except Exception as e:
        log.error(f"[SessionAnalysis] Error: {e}")


def run_stats_generation_job(db_instance):
    """Generates composite infographic data across multiple windows and resolutions."""
    try:
        if not config.get("http", "showstats"):
            return

        from ssh_honeypot.core.utils import get_ignored_ips

        ignore_ips = get_ignored_ips()

        # Fetch full stats for 1H, 1D, 1W
        stats_1h = db_instance.get_infographic_stats(hours=1, ignore_ips=ignore_ips)
        stats_1d = db_instance.get_infographic_stats(hours=24, ignore_ips=ignore_ips)
        stats_1w = db_instance.get_infographic_stats(hours=168, ignore_ips=ignore_ips)

        # DEBUG: Check Protocols in DB (Remote Debugging)
        try:
            conn = db_instance._get_conn()
            c = conn.cursor()
            c.execute("SELECT DISTINCT protocol FROM sessions")
            protos = [r[0] for r in c.fetchall()]
            log.info(f"[StatsJob] Distinct Protocols in Sessions: {protos}")

            # Check interaction counts per protocol
            c.execute(
                "SELECT s.protocol, COUNT(i.id) FROM interactions i JOIN sessions s ON i.session_id = s.session_id GROUP BY s.protocol"
            )
            counts = c.fetchall()
            log.info(f"[StatsJob] Interaction Counts: {counts}")
            conn.close()
        except Exception as e:
            log.error(f"[StatsJob] Debug Error: {e}")

        composite = {
            "windows": {"1H": stats_1h, "1D": stats_1d, "1W": stats_1w},
            "graphs": {
                "hourly_24h": db_instance.get_hourly_session_counts(hours=24),
                "daily_7d": db_instance.get_daily_session_counts(days=7),
                "daily_21d": db_instance.get_daily_session_counts(days=21),
            },
            "top_mysql_risk": db_instance.get_recent_top_commands_by_risk(
                "mysql", limit=15
            ),
            "top_telnet_risk": db_instance.get_recent_top_commands_by_risk(
                "telnet", limit=15
            ),
            "top_llm_risk": db_instance.get_recent_top_commands_by_risk(
                "llm-api", limit=15
            ),
            "recent_high_risk": db_instance.get_recent_high_risk_events(limit=15),
            "recent_payloads": db_instance.get_recent_payloads(limit=15),
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        from ssh_honeypot.core.utils import PROJECT_ROOT

        data_path = os.path.join(PROJECT_ROOT, "data", "status_data.json")
        os.makedirs(os.path.dirname(data_path), exist_ok=True)

        with open(data_path, "w") as f:
            json.dump(composite, f, indent=2)

        log.info(f"[StatsJob] Generated multi-window stats in {data_path}")
    except Exception as e:
        log.error(f"[StatsJob] Error: {e}")


def run_ip_enrichment_batch(db_instance):
    """Enriches one IP at a time (rate limited)."""
    if not IPEnricher:
        return

    try:
        candidates = db_instance.get_unenriched_ips(limit=1)
        if candidates:
            ip = candidates[0]
            enricher = IPEnricher()
            result = enricher.enrich_ip(ip)
            if result:
                db_instance.save_ip_intelligence(ip, result)
                log.info(f"[Enrichment] Enriched {ip} ({result.get('network_type')})")
    except Exception as e:
        log.error(f"[Enrichment] Error: {e}")


def run_payload_download_batch(db_instance):
    """Process pending downloads."""
    try:
        from ssh_honeypot.core.payload_manager import PayloadManager

        manager = PayloadManager(db_instance)
        manager.process_queue()
    except Exception as e:
        log.error(f"[PayloadWorker] Error: {e}")


def run_payload_analysis_batch(db_instance):
    """Process VT analysis."""
    try:
        from ssh_honeypot.core.payload_manager import PayloadManager

        manager = PayloadManager(db_instance)
        manager.process_analysis_queue()
    except Exception as e:
        log.error(f"[VTWorker] Error: {e}")


def run_payload_recovery_job(db_instance):
    """
    Incremental Backfill: Checks for missed payloads in recent interactions.
    This acts as a safety net if the realtime hook fails or DB commits race.
    """
    global _payload_recovery_cursor
    try:
        from ssh_honeypot.core.payload_manager import PayloadManager

        pm = PayloadManager(db_instance)

        # Batch size for recovery (Optimized for faster backfill)
        limit = 500

        # optimized cursor init
        if _payload_recovery_cursor == 0:
            try:
                # auto-catchup: start from 10k items ago to verify recent history first
                # This prevents "starting from 0" on every restart which implies scanning years of history
                max_id = (
                    db_instance.get_max_interaction_id()
                )  # We need this method or raw query
                if not max_id:
                    # Raw query fallback if method missing
                    conn = db_instance._get_conn()
                    c = conn.cursor()
                    c.execute("SELECT MAX(id) FROM interactions")
                    row = c.fetchone()
                    max_id = row[0] if row and row[0] else 0
                    conn.close()

                if max_id > 10000:
                    _payload_recovery_cursor = max_id - 10000
                    log.info(
                        f"[Recovery] Smart-Start: Jumping cursor to {_payload_recovery_cursor} (Max: {max_id}) to catch recent data."
                    )
            except Exception as e:
                log.warning(f"[Recovery] Failed to determine max ID: {e}")

        rows = db_instance.get_interactions_since_id(
            _payload_recovery_cursor, limit=limit
        )

        if rows:
            potential_payloads = []
            seen_hashes = set()
            host_rate_limit_cache = {}

            for row in rows:
                cmd_id = row["id"]
                cmd_text = row["command"]
                sid = row["session_id"]
                ip = row["remote_ip"]

                # Skip HTTP CONNECT/GET for payload analysis
                if cmd_text.startswith("CONNECT ") or cmd_text.startswith("GET "):
                    continue

                # Update cursor
                if cmd_id > _payload_recovery_cursor:
                    _payload_recovery_cursor = cmd_id

                urls = pm.extract_urls(cmd_text)
                for url in urls:
                    url_hash = hashlib.md5(url.encode()).hexdigest()

                    if url_hash in seen_hashes:
                        continue

                    # Host Rate Limiting check
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if not hostname:
                        continue

                    if hostname in host_rate_limit_cache:
                        if host_rate_limit_cache[hostname]:
                            continue
                    else:
                        is_limited = db_instance.is_payload_host_rate_limited(hostname)
                        host_rate_limit_cache[hostname] = is_limited
                        if is_limited:
                            continue

                    potential_payloads.append(
                        {
                            "url": url,
                            "url_hash": url_hash,
                            "session_id": sid,
                            "ip": ip,
                            "timestamp": row.get("timestamp") or datetime.now(),
                        }
                    )
                    seen_hashes.add(url_hash)

            if potential_payloads:
                db_instance.batch_add_malicious_payloads(potential_payloads)

            # Log progress so user sees activity
            log.debug(
                f"[Recovery] Scanned {len(rows)} interactions (Cursor: {_payload_recovery_cursor}). Batch queued: {len(potential_payloads)}"
            )

    except Exception as e:
        log.error(f"[Recovery] Error: {e}")


def run_status_report_job(db_instance):
    """
    Logs the current system backlog status to help admins monitor progress.
    """
    try:
        # 1. Analysis Backlog
        # We don't have a direct count method, but we can verify via unanalyzed_commands check
        # Or better, just count unanalyzed commands if possible.
        # Since we lack a count API, we can infer from batch size or add one.
        # For now, let's just log that the job is alive.
        # Actually, let's try to get a count from `malicious_payloads`

        # Payloads Stats
        pending_dl = 0
        failed_dl = 0
        try:
            # This assumes SQL backend structure or similar cursor access
            conn = db_instance._get_conn()
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM malicious_payloads WHERE status='queued'")
            pending_dl = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM malicious_payloads WHERE status='failed'")
            failed_dl = c.fetchone()[0]
            conn.close()
        except:
            pass

        log.debug(
            f"[System Status] Payloads Queued: {pending_dl} | Payloads Failed: {failed_dl} | Recovery Cursor: {_payload_recovery_cursor}"
        )

    except Exception as e:
        log.error(f"[Status] Error: {e}")


def start_background_tasks(db_instance, llm_instance):
    """
    Initializes and starts the Job Scheduler with all async tasks.
    """
    try:
        log.info("[System] Starting Async Job Scheduler...")

        alert_manager = AlertManager()

        # 1. Cleanup (Every 1 hour)
        scheduler.register_job(
            "cleanup", lambda: run_cleanup_job(db_instance), interval_seconds=3600
        )

        scheduler.register_job(
            "llm_analysis",
            lambda: run_analysis_batch(db_instance, llm_instance, alert_manager),
            interval_seconds=30,
        )

        # 2.5. Session Analysis (Every 30 seconds)
        scheduler.register_job(
            "session_analysis",
            lambda: run_session_analysis_batch(db_instance, llm_instance),
            interval_seconds=30,
        )

        # 3. IP Enrichment (Every 10 seconds - controlled rate)
        if IPEnricher:
            scheduler.register_job(
                "ip_enrichment",
                lambda: run_ip_enrichment_batch(db_instance),
                interval_seconds=10,
            )

        # 4. Payload Downloads (Every 10 seconds)
        scheduler.register_job(
            "payload_download",
            lambda: run_payload_download_batch(db_instance),
            interval_seconds=10,
        )

        # 5. Payload VT Analysis (Every 15 seconds)
        scheduler.register_job(
            "payload_vt",
            lambda: run_payload_analysis_batch(db_instance),
            interval_seconds=15,
        )

        # 6. Infographic Stats (Every 1 hour)
        scheduler.register_job(
            "infographic_stats",
            lambda: run_stats_generation_job(db_instance),
            interval_seconds=3600,
        )

        # 6. Payload Recovery / Backfill Safety Net (Every 30 seconds - Turbo Mode)
        # Checks for anything missed by realtime hooks
        scheduler.register_job(
            "payload_recovery",
            lambda: run_payload_recovery_job(db_instance),
            interval_seconds=30,
        )

        # 7. Status Report (Every 60 seconds)
        scheduler.register_job(
            "status_report",
            lambda: run_status_report_job(db_instance),
            interval_seconds=60,
        )

        scheduler.start()

    except Exception as e:
        log.error(f"[System] Failed to start background tasks: {e}")


# Backward compatibility stubs for direct looping callers (deprecated usage)
def cleanup_loop(db):
    scheduler.register_job("cleanup", lambda: run_cleanup_job(db), 3600)


def analysis_loop(db, llm, alert_manager=None, run_once=False):
    if run_once:
        if not alert_manager:
            alert_manager = AlertManager()
        run_analysis_batch(db, llm, alert_manager)
    else:
        scheduler.register_job(
            "llm_analysis", lambda: run_analysis_batch(db, llm, AlertManager()), 30
        )


def ip_enrichment_loop(db, run_once=False):
    if run_once:
        run_ip_enrichment_batch(db)
    else:
        scheduler.register_job("ip_enrichment", lambda: run_ip_enrichment_batch(db), 10)


def payload_download_loop(db):
    scheduler.register_job(
        "payload_download", lambda: run_payload_download_batch(db), 10
    )


def payload_analysis_loop(db):
    scheduler.register_job("payload_vt", lambda: run_payload_analysis_batch(db), 15)
