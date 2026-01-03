import os
import json
import logging

try:
    from .honey_db import HoneyDB
except ImportError:
    from honey_db import HoneyDB


def get_skeleton_data(json_path=None):
    """
    Returns a list of file nodes for the Skeleton layer.
    Combines static_fs_seed.json and dynamic defaults.
    """
    if not json_path:
        json_path = os.path.join(os.path.dirname(__file__), 'static_fs_seed.json')

    nodes = []
    
    # 1. Load Static Seed
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                nodes = json.load(f)
        except Exception as e:
            logging.error(f"FS Seeder: Failed to load JSON: {e}")
            
    # 2. Append Dynamic User Defaults (Formerly in utils.py)
    # We use a placeholder path prefix ~ for home dir relative paths
    
    home_defaults = [
        {"path": "~/.bash_history", "type": "file", "content": "ls\ncd /var/www\ncat config.php\nexit", "metadata": {"permissions": "-rw-r--r--"}},
        {"path": "~/.profile", "type": "file", "content": "# ~/.profile: executed by the command interpreter for login shells.\n", "metadata": {"permissions": "-rw-r--r--"}},
        {"path": "~/blogofy_db_dump_2021.sql", "type": "file", "content": "CREATE TABLE users (id INT, username VARCHAR(255));\nINSERT INTO users VALUES (1, 'admin');", "metadata": {"permissions": "-rw-r--r--"}},
        {"path": "~/access_log.old.gz", "type": "file", "content": "binary_content_simulation", "metadata": {"permissions": "-rw-r--r--", "size": 1048576}}, 
        {"path": "~/migration_notes.txt", "type": "file", "content": "Todo: migrate to v4. Check heavy queries on auth table.", "metadata": {"permissions": "-rw-r--r--"}},
        {"path": "~/deploy_v3.sh", "type": "file", "content": "#!/bin/bash\necho 'Deploying v3...'\ncp -r /src /var/www/html", "metadata": {"permissions": "-rwxr-xr-x"}},
        {"path": "~/docker-compose.yml.bak", "type": "file", "content": "version: '3'\nservices:\n  web:\n    image: nginx", "metadata": {"permissions": "-rw-r--r--"}},
        {"path": "~/aws_keys.txt", "type": "file", "content": "AKIAABCDEFGHIJKLMNOP\nSECRET_KEY=...", "metadata": {"permissions": "-rw-------"}},
        {"path": "~/id_rsa_backup", "type": "file", "content": "-----BEGIN OPENSSH PRIVATE KEY-----\n...", "metadata": {"permissions": "-rw-------"}},
        {"path": "~/wallet.dat", "type": "file", "content": "binary_wallet_data", "metadata": {"permissions": "-rw-------"}}
    ]
    
    nodes.extend(home_defaults)
    
    return nodes
    
def seed_filesystem(db, json_path=None):
    """Deprecated: Skeleton Layer now handles this dynamically."""
    pass

