import os
import json
import logging

try:
    from .honey_db import HoneyDB
except ImportError:
    from honey_db import HoneyDB

def seed_filesystem(db, json_path=None):
    """
    Seeds the database with static filesystem entries from a JSON file.
    Args:
        db: HoneyDB instance
        json_path: Path to the JSON seed file. If None, defaults to static_fs_seed.json in the same dir.
    """
    if not json_path:
        json_path = os.path.join(os.path.dirname(__file__), 'static_fs_seed.json')

    if not os.path.exists(json_path):
        logging.warning(f"FS Seeder: JSON file not found at {json_path}")
        return

    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        logging.error(f"FS Seeder: Failed to load JSON: {e}")
        return

    count = 0
    
    # OPTIMIZATION: Use a single transaction to avoid spamming connection/locks
    # for 900+ items.
    
    try:
        conn = db._get_conn()
        cursor = conn.cursor()
        
        for item in data:
            path = item.get('path')
            parent = item.get('parent_path')
            ftype = item.get('type')
            meta = item.get('metadata')
            content = item.get('content', '')

            if not path or not parent:
                continue
            
            # Use INSERT OR IGNORE to respect existing data without a read query
            cursor.execute("""
                INSERT OR IGNORE INTO global_filesystem (path, parent_path, type, metadata, content)
                VALUES (?, ?, ?, ?, ?)
            """, (path, parent, ftype, json.dumps(meta) if isinstance(meta, dict) else meta, content))
            
            if cursor.rowcount > 0:
                count += 1
                
        conn.commit()
        conn.close()
        
    except Exception as e:
        logging.error(f"FS Seeder DB Error: {e}")
        # Try to clean up if needed, though conn variable scope is safe enough here.
    
    if count > 0:
        print(f"[*] Seeded {count} static filesystem items.")
    else:
        # print("[*] Filesystem already seeded.")
        pass
