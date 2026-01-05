
import os
import sys

# Add project root
sys.path.append(os.getcwd())

from ssh_honeypot.config_manager import config
from ssh_honeypot.fs_seeder import get_skeleton_data

def debug_seeder():
    print("--- Debugging Config ---")
    # Force load persona
    config.load_persona("Debian12_GPU_8GB")
    
    mapping = config.get('persona', 'filesystem', 'user_home_mapping')
    print(f"Config user_home_mapping: {mapping} (Type: {type(mapping)})")
    
    fs_path = config.get('persona', '_fs_path')
    print(f"FS Path: {fs_path}")
    
    print("\n--- Running Seeder ---")
    data = get_skeleton_data()
    
    print(f"Total Items: {len(data)}")
    
    print("\n--- Checking Home Directory Items ---")
    home_items = [i for i in data if 'home' in i['path'] or i['path'].startswith('~')]
    
    for i in home_items:
        print(f"Path: {i['path']}")
        
if __name__ == "__main__":
    debug_seeder()
