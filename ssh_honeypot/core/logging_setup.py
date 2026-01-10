import logging
import sys

def setup_logger(name="ssh_honeypot"):
    """
    Sets up a centralized logger with valid formatting:
    Date/Time - File - Function - Line - Message
    """
    logger = logging.getLogger(name)
    
    # Prevent adding multiple handlers if setup is called multiple times
    if logger.hasHandlers():
        return logger
        
    logger.setLevel(logging.DEBUG)

    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)

    # Format: 2026-01-01 19:42:59   server.py   handle_connection   555   Message
    # Using 3 spaces as distinct separator
    formatter = logging.Formatter(
        '%(asctime)s   %(filename)s   %(funcName)s   %(lineno)d   %(message)s', 
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    ch.setFormatter(formatter)

    logger.addHandler(ch)

    return logger

def configure_paramiko_noise():
    """
    Suppresses specific Paramiko errors that are spammy (e.g. scanners).
    """
    # Filter for Transport logger
    p_log = logging.getLogger("paramiko.transport")
    
    class IncompatiblePeerFilter(logging.Filter):
        def filter(self, record):
            msg = record.getMessage()
            if "Incompatible ssh peer" in msg or "no acceptable host key" in msg:
                return False
            # Also suppress "EOFError" which happens on disconn often
            if "EOFError" in msg:
                return False
            return True
            
    p_log.addFilter(IncompatiblePeerFilter())
    
    # Ensure level is at least WARNING (suppress INFO/DEBUG if active)
    logging.getLogger("paramiko").setLevel(logging.WARNING)

# Global configuration
configure_paramiko_noise()

# Global instance for easy import
log = setup_logger()
