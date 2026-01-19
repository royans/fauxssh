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
        "%(asctime)s   %(filename)s   %(funcName)s   %(lineno)d   %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    ch.setFormatter(formatter)

    logger.addHandler(ch)

    # File Handler (Rotating)
    try:
        from logging.handlers import TimedRotatingFileHandler
        import os

        # Avoid circular import with config by using utils directly if possible, or try import
        # ssh_honeypot.core.utils should be safe
        from ssh_honeypot.core.utils import get_data_dir

        log_dir = get_data_dir()
        if log_dir and os.path.exists(log_dir):
            log_file = os.path.join(log_dir, "server.log")

            # Rotate at midnight, keep 7 days
            fh = TimedRotatingFileHandler(
                log_file, when="midnight", interval=1, backupCount=7
            )
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(formatter)
            logger.addHandler(fh)

            # SUCCESS: Disable Console Handler to prevent duplication in server_startup.log
            # UNLESS we are in test mode, where we want to see logs in stdout
            if os.getenv("FAUXSSH_TEST_MODE") != "1":
                logger.removeHandler(ch)

    except Exception as e:
        # Fallback to console only if file setup fails
        print(f"[!] Logging File Setup Failed: {e}")

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

    class IncompatiblePeerFilter(logging.Filter):
        def filter(self, record):
            msg = record.getMessage()
            if "Incompatible ssh peer" in msg or "no acceptable host key" in msg:
                return False
            # Suppress EOFError (Disconnects)
            if "EOFError" in msg:
                return False
            # Suppress Banner Check Timouts/Errors (Scanner Noise)
            if "_check_banner" in str(record.funcName) or "check_banner" in msg:
                return False
            if record.exc_info:
                exc_type, exc_value, _ = record.exc_info
                if (
                    "SSHException" in str(exc_type)
                    or "timeout" in str(exc_type)
                    or "TimeoutError" in str(exc_type)
                ):
                    if "_check_banner" in str(record.funcName):
                        return False

            return True

    p_log.addFilter(IncompatiblePeerFilter())

    # Ensure level is at least WARNING (suppress INFO/DEBUG if active)
    logging.getLogger("paramiko").setLevel(logging.WARNING)


# Global configuration
configure_paramiko_noise()

# Global instance for easy import
log = setup_logger()
