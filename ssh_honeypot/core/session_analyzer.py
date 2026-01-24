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

    # Use consistent string for hashing empty/single sessions
    if not commands:
        chain_str = "__EMPTY_SESSION__"
    else:
        # Truncate for LLM if it's a massive automated dump to save tokens
        if len(commands) > 50:
            commands_to_hash = commands[:50]
        else:
            commands_to_hash = commands
        chain_str = "|".join([c.strip() for c in commands_to_hash])

    # 2. Compute Chain Hash
    chain_hash = hashlib.md5(chain_str.encode()).hexdigest()

    # 3. Check Cache
    cached = db.get_cached_session_summary(chain_hash)
    if cached:
        summary, risk_score = cached
        db.update_session_summary(session_id, summary, risk_score)
        log.info(
            f"[SessionAnalyzer] Cache Hit for session {session_id} (Hash: {chain_hash[:8]})"
        )
        return "Analyzed (Cache Hit)"

    # Handle Empty Session specifically (cached above after first run)
    if not commands:
        summary = "Session terminated after authentication (no commands)."
        risk_score = 0
        db.save_session_summary_cache(chain_hash, summary, risk_score)
        db.update_session_summary(session_id, summary, risk_score)
        return "Analyzed (Empty)"

    # 4. Command-Level Fallback for 1-Command Sessions
    if len(commands) == 1:
        cmd_text = commands[0]
        cmd_hash = hashlib.md5(cmd_text.encode()).hexdigest()
        analysis = db.get_analysis(cmd_hash)
        if analysis:
            summary = (
                f"Single command session: {cmd_text}. {analysis.get('explanation', '')}"
            )
            risk_score = analysis.get("risk_score", 0)
            db.save_session_summary_cache(chain_hash, summary, risk_score)
            db.update_session_summary(session_id, summary, risk_score)
            log.info(
                f"[SessionAnalyzer] Reusing command analysis for session {session_id}"
            )
            return "Analyzed (Command Reuse)"

    # 4. LLM Analysis
    if not llm:
        llm = LLMInterface()

    log.info(
        f"[SessionAnalyzer] Analyzing session {session_id} (len={len(commands)})..."
    )
    result = llm.generate_session_summary(commands)

    if result and isinstance(result, dict):
        summary = result.get("summary", "No summary provided")
        risk_score = result.get("risk_score", 0)
        mitre = result.get("mitre_codes", [])

        # Append MITRE codes to summary if present
        if mitre:
            summary += f" [MITRE: {', '.join(mitre)}]"

        # Save to Cache
        db.save_session_summary_cache(chain_hash, summary, risk_score)

        # Update Session
        db.update_session_summary(session_id, summary, risk_score)

        # Trigger Alert Check
        try:
            from .alert_manager import AlertManager

            # Fetch IP (We need to re-fetch or pass it in. Pass it in is better but requires sig change.
            # db.get_session_info(session_id)?
            # Let's just fetch it from DB for reliability
            session_info = db.get_session(session_id)
            if session_info:
                remote_ip = session_info.get("remote_ip", "unknown")
                protocol = session_info.get("protocol", "ssh")

                mgr = AlertManager()
                mgr.check_risk_score(
                    session_id,
                    remote_ip,
                    risk_score,
                    explanation=f"Session Summary: {summary}",
                    protocol=protocol,
                )
        except Exception as e:
            log.error(f"[SessionAnalyzer] Alert Trigger Error: {e}")

        return "Analyzed (LLM)"

    return "Failed (LLM Error)"
