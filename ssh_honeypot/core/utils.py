import os

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))

# Robust .env loading
try:
    from dotenv import load_dotenv

    # 1. Search specific paths relevant to deployment structure
    candidate_paths = [
        # Explicit locations
        os.path.join(PROJECT_ROOT, ".env"),  # ./sshpot/.env (Clone root)
        os.path.join(
            os.path.dirname(PROJECT_ROOT), ".env"
        ),  # ../.env (User deploy root, e.g. ~/c/.env)
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
    if not raw:
        return []

    ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
    expanded_ips = []

    for ip in ips:
        expanded_ips.append(ip)
        # If it looks like an IPv4 address, also ignore the IPv6-mapped version
        if "." in ip and ":" not in ip:
            expanded_ips.append(f"::ffff:{ip}")

    return expanded_ips


def random_response_delay(min_seconds=0.1, max_seconds=0.5):
    """
    Introduces a random delay to simulate network latency or processing time.
    """
    import time
    import random

    time.sleep(random.uniform(min_seconds, max_seconds))
