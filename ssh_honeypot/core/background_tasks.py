import time
import threading
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from ssh_honeypot.core.alert_manager import AlertManager

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
             
        time.sleep(5) # Poll interval
