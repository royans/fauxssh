import hashlib
import json
from .logging_setup import log

try:
    from .database import HoneyDB
    from .llm import LLMInterface
    from .config import config
except ImportError:
    # Fallback for direct testing
    from ssh_honeypot.core.database import HoneyDB
    from ssh_honeypot.core.llm import LLMInterface
    from ssh_honeypot.core.config import config

def analyze_session(session_id, db=None, llm=None):
    """
    Analyzes a session to generate a narrative summary and risk score.
    Uses caching based on command chain hash.
    Returns: status_string
    """
    if not db:
        db = HoneyDB()
    
    # 1. Fetch Interactions
    commands = db.get_session_interactions(session_id)
    if not commands or len(commands) <= 1:
        return "Skipped (Short Session)"
        
    # 2. Compute Chain Hash
    # Normalize: join by pipe, maybe strip whitespace
    chain_str = "|".join([c.strip() for c in commands])
    chain_hash = hashlib.md5(chain_str.encode()).hexdigest()
    
    # 3. Check Cache
    cached = db.get_cached_session_summary(chain_hash)
    if cached:
        summary, risk_score = cached
        db.update_session_summary(session_id, summary, risk_score)
        log.info(f"[SessionAnalyzer] Cache Hit for session {session_id} (Hash: {chain_hash[:8]})")
        return "Analyzed (Cache Hit)"
        
    # 4. LLM Analysis
    if not llm:
        llm = LLMInterface()
        
    log.info(f"[SessionAnalyzer] Analyzing session {session_id} (len={len(commands)})...")
    result = llm.generate_session_summary(commands)
    
    if result and isinstance(result, dict):
        summary = result.get('summary', 'No summary provided')
        risk_score = result.get('risk_score', 0)
        mitre = result.get('mitre_codes', [])
        
        # Append MITRE codes to summary if present
        if mitre:
             summary += f" [MITRE: {', '.join(mitre)}]"
        
        # Save to Cache
        db.save_session_summary_cache(chain_hash, summary, risk_score)
        
        # Update Session
        db.update_session_summary(session_id, summary, risk_score)
        return "Analyzed (LLM)"
        
    return "Failed (LLM Error)"
