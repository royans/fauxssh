import time
import threading
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from ssh_honeypot.core.config import config
from ssh_honeypot.core.alert_manager import AlertManager

try:
    from ssh_honeypot.core.ip_enrichment import IPEnricher
except ImportError:
    IPEnricher = None

def cleanup_loop(db_instance):
    """Background thread to clean up old uploads"""
    while True:
        try:
            # Configurable retention
            days = config.get('upload', 'cleanup_days') or 30
            log.info(f"[Cleanup] Running prune job (retention: {days} days)...")
            
            deleted_items = db_instance.prune_uploads(days)
            if deleted_items:
                log.info(f"[Cleanup] Removed {len(deleted_items)} old upload records from DB.")
                
            # Cleanup Payloads (Jan 10)
            from ssh_honeypot.core.payload_manager import PAYLOAD_DIR
            import os
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
            
        time.sleep(3600) # Run every hour

def analysis_loop(db_instance, llm_instance, alert_manager_instance=None, run_once=False):
    """Background thread to analyze commands with LLM"""
    if alert_manager_instance is None:
        alert_manager_instance = AlertManager()
        
    log.info("[Analysis] Starting Threat Analysis Loop...")
    while True:
        try:
            # Poll for unanalyzed commands
            commands = db_instance.get_unanalyzed_commands(limit=10)
            
            if not commands:
                if run_once:
                    log.info("[Analysis] No commands to analyze. Exiting test mode.")
                    break
                time.sleep(10) # Wait if nothing to do
                continue
                
            # Batch Analysis
            log.info(f"[Analysis] Batch processing {len(commands)} commands...")
            
            # commands is now a list of dicts: {'request_md5':..., 'command':..., 'session_id':..., 'remote_ip':...}
            results = llm_instance.analyze_batch([(c['request_md5'], c['command']) for c in commands])
            
            for cmd_row in commands:
                cmd_hash = cmd_row['request_md5']
                cmd_text = cmd_row['command']
                session_id = cmd_row['session_id']
                ip = cmd_row['remote_ip']
                
                analysis = results.get(cmd_hash)
                
                if analysis:
                     log.info(f"[Analysis] Processed: {cmd_text[:30]}... -> {analysis.get('explanation')}")
                     db_instance.save_analysis(cmd_hash, cmd_text, analysis)
                     
                     # Check Risk for Alerting
                     try:
                         score = analysis.get('risk', 0)
                         explanation = analysis.get('explanation', '')
                         alert_manager_instance.check_risk_score(session_id, ip, score, explanation)
                     except Exception as e:
                         log.error(f"[Analysis] Alert Error: {e}")
                else:
                    log.warning(f"[Analysis] Batch Miss for: {cmd_text[:30]}...")
                    failure_analysis = {
                        'type': 'Unknown', 
                        'stage': 'Unknown', 
                        'risk': 0, 
                        'explanation': 'Analysis Failed: Batch Miss'
                    }
                    db_instance.save_analysis(cmd_hash, cmd_text, failure_analysis)
                     
            if run_once:
                log.info("[Analysis] Test run complete.")
                break

            # Rate limit protection (5 requests per minute = 12s delay)
            time.sleep(12)
                
        except KeyboardInterrupt:
            break
        except Exception as e:
             log.error(f"[Analysis] Error: {e}")
             if run_once: break
             time.sleep(30)
             
             if run_once: break
             time.sleep(30)
             
        time.sleep(5) # Poll interval

def ip_enrichment_loop(db_instance, run_once=False):
    """
    Background thread to enrich IP data (GeoIP, etc).
    Rate Limit: 10 requests per minute (~6 seconds delay).
    """
    if IPEnricher is None:
        log.warning("[Enrichment] IPEnricher module missing (deps?). Worker disabled.")
        return

    enricher = IPEnricher()
    log.info("[Enrichment] Starting IP Intelligence Worker (Limit: 10/min)...")
    
    while True:
        try:
            # 1. Fetch Candidate (Limit 1 to control rate)
            # Prioritized by LAST SEEN (recent activity first)
            candidates = db_instance.get_unenriched_ips(limit=1)
            
            if not candidates:
                if run_once: break
                time.sleep(30) # Sleep longer if queue is empty
                continue
                
            ip = candidates[0]
            
            # 2. Enrich
            result = enricher.enrich_ip(ip)
            
            # 3. Save
            if result:
                db_instance.save_ip_intelligence(ip, result)
                log.info(f"[Enrichment] Enriched {ip} ({result.get('network_type')})")
            
            if run_once: break

            # 4. Rate Limit Delay
            # 10 req/min = 60s / 10 = 6s delay
            # We enforce strictly 6s gap between API calls
            time.sleep(6)
            
        except Exception as e:
            log.error(f"[Enrichment] Worker Error: {e}")
            time.sleep(30)


def payload_download_loop(db_instance):
    """
    Background thread to download malicious payloads.
    Polls the 'pending' queue in malicious_payloads table.
    """
    try:
        from ssh_honeypot.core.payload_manager import PayloadManager
    except ImportError:
        log.error("[PayloadWorker] Failed to import PayloadManager.")
        return

    manager = PayloadManager(db_instance)
    log.info("[PayloadWorker] Starting Payload Download Loop...")
    
    while True:
        try:
            # Main processing logic inside PayloadManager
            # We poll frequently (10s) as these are high value
            manager.process_queue()
            
            time.sleep(10)
            
        except Exception as e:
            log.error(f"[PayloadWorker] Error: {e}")
            time.sleep(60)
