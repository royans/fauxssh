import os
import re
import pytest

# Define forbidden patterns that indicate potential security risks
# We use regex to match function calls
FORBIDDEN_PATTERNS = [
    (r"exec\s*\(", "exec() function"),
    (r"eval\s*\(", "eval() function"),
    (r"os\.system\s*\(", "os.system() call"),
    (r"os\.popen\s*\(", "os.popen() call"),
    (r"subprocess\.run\s*\(", "subprocess.run() call"),
    (r"subprocess\.call\s*\(", "subprocess.call() call"),
    (r"subprocess\.Popen\s*\(", "subprocess.Popen() call"),
    (r"subprocess\.check_output\s*\(", "subprocess.check_output() call"),
]


def test_no_dangerous_functions():
    """
    Scans the source code in 'ssh_honeypot' for forbidden dangerous function calls
    to ensure sandbox integrity.
    """
    base_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "ssh_honeypot")
    )

    violations = []

    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        lines = f.readlines()

                    for i, line in enumerate(lines):
                        # Skip comments (naive check)
                        if line.strip().startswith("#"):
                            continue

                        for pattern, name in FORBIDDEN_PATTERNS:
                            if re.search(pattern, line):
                                violations.append(
                                    f"{name} found in {file}:{i+1} -> {line.strip()}"
                                )
                except Exception as e:
                    print(f"Could not read {filepath}: {e}")

    # Assert that no violations were found
    if violations:
        pytest.fail("\n".join(["Security Violation detected:"] + violations))


def test_no_hardcoded_secrets():
    """
    Scans the codebase for hardcoded API keys and secrets.
    """
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    # Secret Patterns
    SECRET_PATTERNS = [
        (r"AIza" + r"[0-9A-Za-z-_]{35}", "Google API Key"),
        (r"sk-" + r"[a-zA-Z0-9]{20,}", "OpenAI API Key"),
        (r"AKIA" + r"[0-9A-Z]{16}", "AWS Access Key"),
        (r"ghp_" + r"[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
        (
            r'GOOGLE_API_KEY\s*=\s*["\'][^<]',
            "Hardcoded GOOGLE_API_KEY assignment",
        ),  # Ignore template values
    ]

    # Whitelisted files/directories
    EXCLUDE_DIRS = {
        ".git",
        "__pycache__",
        "venv",
        "env",
        "data",
        "egg-info",
        ".pytest_cache",
    }
    EXCLUDE_FILES = {
        "aws_keys.txt",
        ".env.example",
        "credentials",
        "test_codebase_security.py",
        "publish_fauxssh.sh",
    }

    violations = []

    for root, dirs, files in os.walk(base_dir):
        # Prune excluded dirs
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file in files:
            if file in EXCLUDE_FILES or file.endswith(".pyc") or file.endswith(".log"):
                continue

            # Scan only text-ish files
            if not file.endswith((".py", ".sh", ".md", ".yaml", ".json", ".txt")):
                continue

            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern, name in SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        # Common false positives
                        if (
                            "your_key_here" in match
                            or "fake_key" in match
                            or "AIzaSy_FAKE" in match
                        ):
                            continue
                        violations.append(f"{name} found in {file}: {match[:10]}...")
            except Exception as e:
                # Binary file or other error
                pass

    if violations:
        pytest.fail("\n".join(["Secret Leak detected:"] + violations))
