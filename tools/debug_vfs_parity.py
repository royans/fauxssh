
import os
import sys

# Add project root
sys.path.append(os.getcwd())

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.config import config

def test_parity():
    # Load config/persona
    config.load_persona("Debian12_GPU_8GB")
    
    # Init DB
    db = HoneyDB("data/test_parity.db") # Use separate DB
    
    # Mock IP/User
    ip = "127.0.0.1"
    user = "royans"
    cwd = "/home/royans"
    
    # Force skeleton load (normally done in server init, but HoneyDB init does it too)
    print(f"Skeleton Cache Size: {len(db.skeleton_cache)}")
    
    print("\n--- Testing inspect_dir ---")
    report = db.inspect_dir(ip, user, cwd)
    print(report)
    
    print("\n--- Testing list_user_dir ---")
    items = db.list_user_dir(ip, user, cwd)
    filenames = [os.path.basename(i['path']) for i in items]
    print(f"Found {len(items)} items:")
    for f in sorted(filenames):
        print(f" - {f}")

    # Validation
    if ".bash_history" in filenames:
        print("\n[PASS] .bash_history found in list_user_dir")
    else:
        print("\n[FAIL] .bash_history MISSING from list_user_dir!")
        
    os.remove("data/test_parity.db")

if __name__ == "__main__":
    test_parity()
