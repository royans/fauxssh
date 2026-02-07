import logging
import sys


def setup_logger(name="ssh_honeypot"):
    """
    Sets up a centralized logger with valid formatting:
    Date/Time - Level - Target - File:Line - Message
    Configures the ROOT logger to ensure library logs are also formatted correctly
    and prevents double logging.
    """
    # 1. Get the Root Logger
    root_logger = logging.getLogger()

    # If root already has handlers, we've already initialized
    if root_logger.hasHandlers():
        return logging.getLogger(name)

    # Initial Global Level
    root_logger.setLevel(logging.INFO)

    # 2. Console Handler (for startup/test)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)

    # Structured Format
    # 2026-01-01 19:42:59   INFO   ssh_honeypot   server.py:123   Message
    formatter = logging.Formatter(
        "%(asctime)s   %(levelname)-8s   %(name)-15s   %(filename)s:%(lineno)d   %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    ch.setFormatter(formatter)
    root_logger.addHandler(ch)

    # 3. File Handler
    try:
        from logging.handlers import TimedRotatingFileHandler
        import os
        from ssh_honeypot.core.utils import get_data_dir

        log_dir = get_data_dir()
        if log_dir:
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            log_file = os.path.join(log_dir, "fauxssh.log")

            # Rotate at midnight, keep 7 days
            fh = TimedRotatingFileHandler(
                log_file, when="midnight", interval=1, backupCount=7
            )
            fh.setLevel(logging.INFO)
            fh.setFormatter(formatter)
            root_logger.addHandler(fh)

            # Disable Console Handler in production to keep stdout clean for start.sh
            if os.getenv("FAUXSSH_TEST_MODE") != "1":
                root_logger.removeHandler(ch)

    except Exception as e:
        print(f"[!] Logging File Setup Failed: {e}")

    # 4. Suppress Noisy Libraries by default
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("mysql_mimic").setLevel(logging.WARNING)
    logging.getLogger("passlib").setLevel(logging.ERROR)

    return logging.getLogger(name)


def apply_config_to_logging(config):
    """
    Applies the configuration values to the logging system.
    Called after config.yaml is loaded.
    """
    log_cfg = config.get("logging") or {}
    global_level_name = log_cfg.get("level", "INFO").upper()
    global_level = getattr(logging, global_level_name, logging.INFO)

    # 1. Update Global ROOT Logger Level
    root_logger = logging.getLogger()
    root_logger.setLevel(global_level)
    for handler in root_logger.handlers:
        handler.setLevel(global_level)

    # 2. Apply Module-Specific Levels
    modules = log_cfg.get("modules") or {}
    for mod_name, level_name in modules.items():
        try:
            level = getattr(logging, level_name.upper(), logging.INFO)
            logging.getLogger(mod_name).setLevel(level)
            logging.getLogger("ssh_honeypot").info(
                f"[Logging] Set module '{mod_name}' to {level_name.upper()}"
            )
        except Exception as e:
            logging.getLogger("ssh_honeypot").warning(
                f"[Logging] Failed to set module '{mod_name}' level: {e}"
            )

    logging.getLogger("ssh_honeypot").info(
        f"[Logging] Applied config-based levels (Global: {global_level_name})"
    )


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

            # Suppress empty messages (Source: transport.py:1907)
            if not msg.strip():
                return False

            # Suppress Broken Pipe / Connection Reset in Transport
            if "Broken pipe" in msg or "Connection reset" in msg:
                return False

            if record.exc_info:
                exc_type, exc_value, _ = record.exc_info
                exc_str = str(exc_type)
                val_str = str(exc_value)

                if (
                    "SSHException" in exc_str
                    or "timeout" in exc_str
                    or "TimeoutError" in exc_str
                    or "BrokenPipeError" in exc_str
                    or "ConnectionResetError" in exc_str
                    or "Broken pipe" in val_str
                    or "Connection reset" in val_str
                ):
                    return False

            return True

    p_log.addFilter(IncompatiblePeerFilter())

    # Ensure level is at least WARNING (suppress INFO/DEBUG if active)
    logging.getLogger("paramiko").setLevel(logging.WARNING)


# Global configuration
configure_paramiko_noise()

# Global instance for easy import
log = setup_logger()
