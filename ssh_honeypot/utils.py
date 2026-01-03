
import time
import random

def random_response_delay(min_delay=0.5, max_delay=1.5):
    """
    Introduces a random delay to simulate network latency or LLM processing time.
    This helps mitigate timing side-channel attacks where an attacker can 
    distinguish between internal commands (fast) and LLM commands (slow).
    
    Args:
        min_delay (float): Minimum delay in seconds.
        max_delay (float): Maximum delay in seconds.
    """
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)

def ensure_user_home(db, ip, user):
    """
    Ensures that the user's home directory has initial files seeded in the User DB.
    This prevents 'empty directory' issues on initial login even if VFS isn't initialized yet.
    """
    import datetime
    import os
    
    if user == 'root':
        home_dir = '/root'
    else:
        home_dir = f"/home/{user}"
        
    # Check if we already have files
    existing = db.list_user_dir(ip, user, home_dir)
    if existing:
        return # Already seeded
        
    # Seed Defaults
    # Persona: Blogofy
    files = {
        "blogofy_db_dump_2021.sql": "CREATE TABLE users (id INT, username VARCHAR(255));\nINSERT INTO users VALUES (1, 'admin');",
        "access_log.old.gz": "binary_content_simulation",
        "migration_notes.txt": "Todo: migrate to v4. Check heavy queries on auth table.",
        "deploy_v3.sh": "#!/bin/bash\necho 'Deploying v3...'\ncp -r /src /var/www/html",
        "docker-compose.yml.bak": "version: '3'\nservices:\n  web:\n    image: nginx",
        "aws_keys.txt": "AKIAABCDEFGHIJKLMNOP\nSECRET_KEY=...",
        "id_rsa_backup": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
        "wallet.dat": "binary_wallet_data"
    }
    
    # Also standard dotfiles
    files[".bash_history"] = "ls\ncd /var/www\ncat config.php\nexit"
    files[".profile"] = "# ~/.profile: executed by the command interpreter for login shells.\n"
    
    for filename, content in files.items():
        abs_path = os.path.join(home_dir, filename)
        size = len(content)
        # Randomize size for realism if 'binary'
        if content == "binary_content_simulation": size = 1048576 
        
        db.update_user_file(ip, user, abs_path, home_dir, 'file',
            {'size': size, 'permissions': '-rw-r--r--', 'owner': user, 'group': user, 'created': datetime.datetime.now().isoformat()},
            content
        )
