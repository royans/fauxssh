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

# Global instance for easy import
log = setup_logger()
