import os
import re
import pytest

# Define forbidden patterns that indicate potential security risks
# We use regex to match function calls
FORBIDDEN_PATTERNS = [
    (r'exec\s*\(', "exec() function"),
    (r'eval\s*\(', "eval() function"),
    (r'os\.system\s*\(', "os.system() call"),
    (r'os\.popen\s*\(', "os.popen() call"),
    (r'subprocess\.run\s*\(', "subprocess.run() call"),
    (r'subprocess\.call\s*\(', "subprocess.call() call"),
    (r'subprocess\.Popen\s*\(', "subprocess.Popen() call"),
    (r'subprocess\.check_output\s*\(', "subprocess.check_output() call"),
]

def test_no_dangerous_functions():
    """
    Scans the source code in 'ssh_honeypot' for forbidden dangerous function calls
    to ensure sandbox integrity.
    """
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'ssh_honeypot'))
    
    violations = []

    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        
                    for i, line in enumerate(lines):
                        # Skip comments (naive check)
                        if line.strip().startswith('#'):
                            continue
                            
                        for pattern, name in FORBIDDEN_PATTERNS:
                            if re.search(pattern, line):
                                violations.append(f"{name} found in {file}:{i+1} -> {line.strip()}")
                except Exception as e:
                    print(f"Could not read {filepath}: {e}")

    # Assert that no violations were found
    if violations:
        pytest.fail("\n".join(["Security Violation detected:"] + violations))
