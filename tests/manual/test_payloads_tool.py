
import sys
import os
import time

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.payload_manager import PayloadManager

def test_payload_manager():
    print("Initializing DB...")
    db = HoneyDB()
    pm = PayloadManager(db)
    
    test_url = "https://www.google.com/robots.txt" # Safe test URL
    session_id = "test-session-123"
    ip = "127.0.0.1"
    
    print(f"Queuing payload: {test_url}")
    pm.queue_payload(test_url, session_id, ip)
    
    print("Checking if Queued...")
    pending = db.get_pending_payloads()
    found = False
    for p in pending:
        if p['url'] == test_url:
            print("SUCCESS: Payload found in pending queue.")
            found = True
            break
            
    if not found:
        print("FAILURE: Payload not found in queue (maybe rate limited or deduped?)")
        # Check payload table count
        return

    print("Processing Queue (Download)...")
    pm.process_queue()
    
    print("Verifying Download...")
    import hashlib
    url_hash = hashlib.md5(test_url.encode()).hexdigest()
    record = db.get_payload_by_hash(url_hash)
    
    if record and record['status'] == 'completed':
        print(f"SUCCESS: Status is 'completed'")
        print(f"Path: {record['file_path']}")
        print(f"Size: {record['payload_size']}")
        
        if os.path.exists(record['file_path']):
            print("SUCCESS: File exists on disk.")
        else:
            print("FAILURE: File missing from disk.")
            
        # Test Dedupe Logic
        print("Testing Deduplication (Second Queue Attempt)...")
        pm.queue_payload(test_url, session_id, ip) # Should be skipped
    else:
        print(f"FAILURE: Status is {record['status'] if record else 'None'}")
        if record and record['error_message']:
            print(f"Error: {record['error_message']}")

if __name__ == "__main__":
    test_payload_manager()
