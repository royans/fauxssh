import os
import sys
import json

# Setup paths
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'ssh_honeypot')))

# Mock Config
from unittest.mock import MagicMock
from ssh_honeypot.config_manager import config

# Point to ACTUAL persona path
persona_path = "/home/royans/c/sshpot/personas/Debian12_GPU_8GB/fs"
config.get = MagicMock()
def config_get_side_effect(section, key=None):
    if section == 'persona' and key == '_fs_path':
        return persona_path
    if section == 'persona' and key == 'filesystem':
        return {'user_home_mapping': True, 'default_home_owner': True}
    return {}
config.get.side_effect = config_get_side_effect

from ssh_honeypot.honey_db import HoneyDB

# Init DB (In memory or usage of existing?)
# We should use a fresh DB to test logic, or the real DB to test state?
# The user's issue persists across restarts likely, so it's logic + skeleton.
# Let's use memory DB but with real skeleton.
db_path = ":memory:"
db = HoneyDB(db_path)

# Verify Skeleton Load
print(f"Skeleton Items: {len(db.skeleton_cache)}")
# print([i['path'] for i in db.skeleton_cache if 'bashrc' in i['path']])

# 3. List /home/royans
print("\n--- Listing /home/royans ---")
ip = "1.2.3.4"
user = "royans"
path = "/home/royans"

items = db.list_user_dir(ip, user, path)

print(f"Items found: {len(items)}")
for i in items:
    print(f" - {i['path']}")

# 4. Check specific skeleton item mapping
print("\n--- Debug Trace ---")
found_bashrc = False
for item in db.skeleton_cache:
    if '.bashrc' in item['path']:
        skel_path = item['path']
        if skel_path.startswith('~'):
             resolved = skel_path.replace('~', f'/home/{user}', 1)
        else:
             resolved = skel_path
        
        parent = os.path.dirname(resolved)
        print(f"Skel: {skel_path} -> {resolved} | Parent: '{parent}' vs '{path}' | Match: {parent == path}")
        found_bashrc = True

if not found_bashrc:
    print("WARNING: .bashrc not found in skeleton!")
