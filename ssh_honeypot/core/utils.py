import os
import subprocess

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))

# Robust .env loading
try:
    from dotenv import load_dotenv

    # 1. Search specific paths relevant to deployment structure
    candidate_paths = [
        # Explicit locations (Local then Parent)
        os.path.join(PROJECT_ROOT, ".env"),  # ./sshpot/.env (Local)
        os.path.join(os.path.dirname(PROJECT_ROOT), ".env"),  # ../.env (Parent)
    ]

    # 2. Try implicit search
    try:
        from dotenv import find_dotenv

        found = find_dotenv(usecwd=True)
        if found:
            candidate_paths.append(found)
    except ImportError:
        pass

    env_loaded = False
    for p in candidate_paths:
        if os.path.exists(p):
            load_dotenv(p)
            env_loaded = True

except ImportError:
    pass


def get_data_dir():
    """
    Returns the absolute path to the data directory.
    """
    env_path = os.getenv("FAUXSSH_DATA_DIR")
    if env_path:
        # Resolve path (handles relative paths from CWD)
        data_dir = os.path.abspath(env_path)
    else:
        # Auto-detect sibling data directory (common deployment pattern, e.g. ~/c/data next to ~/c/sshpot)
        sibling_data = os.path.abspath(os.path.join(PROJECT_ROOT, "..", "data"))
        if os.path.exists(sibling_data) and os.path.isdir(sibling_data):
            data_dir = sibling_data
        else:
            data_dir = os.path.join(PROJECT_ROOT, "data")

    # Auto-create if missing
    if not os.path.exists(data_dir):
        try:
            os.makedirs(data_dir, exist_ok=True)
        except Exception as e:
            print(f"[!] Critical: Could not create data directory at {data_dir}: {e}")

    return data_dir


def get_version():
    """Reads version from pyproject.toml to avoid hardcoding drift."""
    try:
        import tomllib

        # Assuming run from root or finding root relative to this file
        base_dir = PROJECT_ROOT
        with open(os.path.join(base_dir, "pyproject.toml"), "rb") as f:
            data = tomllib.load(f)
            return data["project"]["version"]
    except Exception as e:
        # Fallback or log error
        return "0.0.0-unknown"


def get_ignored_ips():
    """
    Returns a list of IPs to ignore in analytics, parsed from ANALYTICS_IGNORE_IPS.
    """
    raw = os.getenv("ANALYTICS_IGNORE_IPS", "")
    ips = [ip.strip() for ip in raw.split(",") if ip.strip()]

    from ssh_honeypot.core.logging_setup import log

    log.info(f"[UtilsDebug] get_ignored_ips() raw='{raw}' -> found {len(ips)} base IPs")

    if not raw:
        return []

    expanded_ips = []
    for ip in ips:
        expanded_ips.append(ip)
        # If it looks like an IPv4 address, also ignore the IPv6-mapped version
        if "." in ip and ":" not in ip:
            expanded_ips.append(f"::ffff:{ip}")

    return expanded_ips


def obfuscate_ip(ip):
    """
    Obfuscates the last octet of an IP address (e.g., 1.2.3.4 -> 1.2.3.X).
    """
    if not ip or not isinstance(ip, str):
        return ip
    if "." in ip:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.X"
    if ":" in ip:
        parts = ip.split(":")
        if len(parts) > 1:
            return ":".join(parts[:-1]) + ":XXXX"
    return ip


def random_response_delay(min_seconds=0.1, max_seconds=0.5):
    """
    Introduces a random delay to simulate network latency or processing time.
    """
    import time
    import random
    import os

    if os.getenv("SSHPOT_TEST_MODE"):
        return

    time.sleep(random.uniform(min_seconds, max_seconds))


def sanitize_path(text):
    """
    Masks absolute paths containing the data directory or project root
    with placeholders to prevent internal structure leakage.
    Works dynamically regardless of where the app is deployed.
    """
    if not text or not isinstance(text, str):
        return text

    data_dir = get_data_dir()
    # Mask Data Dir (Priority, as it's most sensitive)
    if data_dir in text:
        text = text.replace(data_dir, "<DATA_DIR>")

    # Mask Project Root
    if PROJECT_ROOT in text:
        text = text.replace(PROJECT_ROOT, "<ROOT>")

    # Optional: Mask home directoy if still present (e.g. /home/royans)
    home_dir = os.path.expanduser("~")
    if home_dir and len(home_dir) > 5 and home_dir in text:
        text = text.replace(home_dir, "<HOME>")

    return text


def resolve_sanitized_path(text):
    """
    Inverses sanitize_path by replacing placeholders with real absolute paths.
    """
    if not text or not isinstance(text, str):
        return text

    data_dir = get_data_dir()
    home_dir = os.path.expanduser("~")

    if "<DATA_DIR>" in text:
        text = text.replace("<DATA_DIR>", data_dir)
    if "<ROOT>" in text:
        text = text.replace("<ROOT>", PROJECT_ROOT)
    if "<HOME>" in text:
        text = text.replace("<HOME>", home_dir)

    return text


def sanitize_obj(obj):
    """
    Recursively scans a dict or list and sanitizes all string values
    using sanitize_path.
    """
    if isinstance(obj, str):
        return sanitize_path(obj)
    if isinstance(obj, list):
        return [sanitize_obj(i) for i in obj]
    if isinstance(obj, dict):
        return {k: sanitize_obj(v) for k, v in obj.items()}
    return obj


def create_dual_stack_socket(bind_ip, port, backlog=64):
    """
    Creates and binds a socket that supports dual-stack (IPv4+IPv6) if bind_ip is '::'.
    """
    import socket

    addr_family = socket.AF_INET
    if ":" in bind_ip or bind_ip == "::":
        addr_family = socket.AF_INET6

    sock = socket.socket(addr_family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if addr_family == socket.AF_INET6:
        try:
            # Enable Dual Stack (IPv4 fallback on IPv6 socket) if binding ::
            IPPROTO_IPV6 = getattr(socket, "IPPROTO_IPV6", 41)
            IPV6_V6ONLY = getattr(socket, "IPV6_V6ONLY", 26)
            sock.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
        except Exception as e:
            from ssh_honeypot.core.logging_setup import log
            import sys

            log.warning(f"[Socket] Could not set IPV6_V6ONLY=0: {e}")

    sock.bind((bind_ip, port))
    sock.listen(backlog)
    return sock


def find_available_port(start=20000, end=30000):
    """
    Finds a random available port in the given range.
    """
    import socket
    import random

    while True:
        port = random.randint(start, end)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", port))
            sock.close()
            return port
        except OSError:
            continue


def extract_snippet(content, max_len=500):
    """
    Extracts a text snippet from content (bytes or str).
    If binary, extracts printable strings of length >= 10.
    """
    if not content:
        return ""

    # Ensure bytes
    if isinstance(content, str):
        content_bytes = content.encode("utf-8", errors="ignore")
    else:
        content_bytes = content

    # 1. Try UTF-8 first (fast path for text files)
    try:
        text = content_bytes.decode("utf-8")
        # Check for null bytes to detect binary masquerading as text
        if "\x00" in text:
            raise UnicodeDecodeError("null bytes", b"", 0, 1, "null bytes")
        return text[:max_len]
    except UnicodeDecodeError:
        pass

    # 2. Binary: Extract Strings
    import re

    # Min length 10 as requested
    pattern = re.compile(b"[ -~\\t\\r\\n]{10,}")

    found = pattern.findall(content_bytes)
    if not found:
        return "<Binary Data - No Strings Found>"

    # Join found strings
    text = b"\n".join(found).decode("utf-8", errors="ignore")
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def get_storable_content(content, max_len=1024 * 1024):
    """
    Prepares payload content for DB storage (up to 1MB).
    If text, returns text. If binary, returns extracted strings.
    Returns (content_str, is_binary)
    """
    if not content:
        return "", False

    if isinstance(content, str):
        content_bytes = content.encode("utf-8", errors="ignore")
    else:
        content_bytes = content

    # 1. Try Text
    try:
        text = content_bytes.decode("utf-8")
        if "\x00" not in text:
            return text[:max_len], False
    except UnicodeDecodeError:
        pass

    # 2. Binary -> Strings
    import re

    pattern = re.compile(b"[ -~\\t\\r\\n]{10,}")
    found = pattern.findall(content_bytes)

    if not found:
        return "<Binary Data - No Strings Found>", True

    text = b"\n".join(found).decode("utf-8", errors="ignore")
    return text[:max_len], True


def ensure_ssl_keys(cert_path, key_path):
    """
    Checks if SSL cert/key exist at the given paths.
    If not, generates a self-signed certificate using openssl.
    """
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return True

    # Ensure directory exists
    cert_dir = os.path.dirname(cert_path)
    if not os.path.exists(cert_dir):
        try:
            os.makedirs(cert_dir, exist_ok=True)
        except Exception as e:
            print(f"[!] Critical: Could not create SSL directory at {cert_dir}: {e}")
            return False

    print(f"[*] Generating self-signed SSL certificate: {cert_path}")

    # OpenSSL Command
    cmd = [
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-days",
        "365",
        "-nodes",
        "-x509",
        "-keyout",
        key_path,
        "-out",
        cert_path,
        "-subj",
        "/C=US/ST=Denial/L=Springfield/O=Dis/CN=mail.localhost",
    ]

    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(cert_path) and os.path.exists(key_path):
            print(f"[*] SSL Certificate generated successfully.")
            return True
    except FileNotFoundError:
        print(
            "[!] Error: 'openssl' command not found. Cannot generate SSL certificates."
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] Error generating SSL certificate: {e}")
    except Exception as e:
        print(f"[!] Unexpected error generating SSL certificate: {e}")

    return False
