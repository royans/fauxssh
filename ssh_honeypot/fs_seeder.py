import os
import json
import logging

try:
    from .config_manager import config
except ImportError:
    from config_manager import config

def get_skeleton_data(json_path=None):
    """
    Returns a list of file nodes for the Skeleton layer.
    Combines static_fs_seed.json and dynamic defaults.
    """
    if not json_path:
        # Default: ProjectRoot/data/personas/base_fs.json
        # Resolving relative to this file: ../../data/personas/base_fs.json
        # But this file is in ssh_honeypot/
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        json_path = os.path.join(base_dir, 'data', 'personas', 'base_fs.json')

    nodes = []
    
    # 1. Load Static Seed
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                nodes = json.load(f)
        except Exception as e:
            logging.error(f"FS Seeder: Failed to load JSON: {e}")
            
    # 2. Append Dynamic User Defaults
    # Note: These are now handled by the persona overlay in fs/home/USER/
    home_defaults = []
    nodes.extend(home_defaults)

    # 3. Load Filesystem Overlay from Persona
    fs_path = config.get('persona', '_fs_path')
    if fs_path and os.path.exists(fs_path):
        # logging.info(f"Loading filesytem overlay from {fs_path}")
        overlay_nodes = load_overlay_nodes(fs_path)
        
        # Merge Strategy: Overwrite existing paths with new nodes
        # Create map for quick lookup
        node_map = {n['path']: i for i, n in enumerate(nodes)}
        
        for new_node in overlay_nodes:
            path = new_node['path']
            if path in node_map:
                # Update existing
                nodes[node_map[path]] = new_node
            else:
                nodes.append(new_node)
                node_map[path] = len(nodes) - 1

    return nodes

def load_overlay_nodes(fs_root):
    """
    Recursively walks fs_root and produces a list of HoneyDB-compatible nodes.
    Handles 'USER' directory remapping to '~'.
    """
    overlay = []
    
    fs_config = config.get('persona', 'filesystem') or {}
    meta_overrides = fs_config.get('metadata_overrides', {})
    default_home_owner = fs_config.get('default_home_owner', False)
    user_home_mapping = fs_config.get('user_home_mapping', False)

    for root, dirs, files in os.walk(fs_root):
        # Determine relative path from fs_root
        rel_root = os.path.relpath(root, fs_root)
        if rel_root == ".": rel_root = ""
        
        # Calculate virtual absolute path
        # e.g. fs/etc/issue -> /etc/issue
        
        # Handle Directory Nodes
        for d in dirs:
            real_path = os.path.join(root, d)
            v_rel_path = os.path.join(rel_root, d)
            v_abs_path = "/" + v_rel_path.lstrip("/")
            
            # Dynamic mapping: /home/USER -> ~
            # Note: We use '~' which HoneyDB expands to /home/<actual_user>
            remapped_path = v_abs_path
            is_user_home = False
            
            if user_home_mapping and (v_abs_path == "/home/USER" or v_abs_path.startswith("/home/USER/")):
                 remapped_path = v_abs_path.replace("/home/USER", "~", 1)
                 is_user_home = True

            # Metadata defaults
            owner = "root"
            group = "root"
            perm = "drwxr-xr-x"
            
            if is_user_home and default_home_owner and remapped_path.startswith("~"):
                # Use special marker that HoneyDB or FS seeder might interpret?
                # HoneyDB's seed_fs resolves '~' but doesn't auto-set owner unless we tell it.
                # Actually, HoneyDB usually sets owner to the session user for newly created files.
                # But for seeded files, we need to be explicit.
                # We can use a placeholder "LE_USER" and let HoneyDB resolve it?
                # Or just keep it as generic and let HoneyDB handle permissions?
                # For now, let's assume 'root' unless specific override.
                # Actually, the requirement is "owned by $USER".
                # Since we don't know $USER at seed time (global seed), we have a problem.
                # The skeleton data is loaded ONCE globally? No, `HoneyDB` is initialized per session?
                # No, HoneyDB is global singleton in server.py (lines 71).
                # Wait, `get_skeleton_data` is called by... `HoneyDB.__init__`?
                # If HoneyDB is global, we can't burn "alabaster" into the seed unless we want everyone to see it.
                # HoneyDB uses `cow_layers` per session.
                # The BASE layer is shared.
                # If we put `~` in path, `HoneyDB.get_node` resolves `~` to `/home/<current_user>`.
                owner = "root" # Default for shared layer.
            
            # Applying overrides
            if v_abs_path in meta_overrides:
                 ov = meta_overrides[v_abs_path]
                 owner = ov.get('owner', owner)
                 perm = ov.get('mode', perm) # mode vs permissions field name mismatch?
                 # Seed uses 'permissions'. Config uses 'mode'. Let's normalize.
                 perm = ov.get('permissions', perm)

            overlay.append({
                "path": remapped_path,
                "parent_path": os.path.dirname(remapped_path), # Approximation
                "type": "directory",
                "metadata": {
                    "permissions": perm,
                    "owner": owner,
                    "group": group
                }
            })

        # Handle File Nodes
        for f in files:
            real_path = os.path.join(root, f)
            v_rel_path = os.path.join(rel_root, f)
            v_abs_path = "/" + v_rel_path.lstrip("/")
            
            remapped_path = v_abs_path
            if user_home_mapping and (v_abs_path.startswith("/home/USER/")):
                 remapped_path = v_abs_path.replace("/home/USER", "~", 1)

            # Read Content
            content = ""
            try:
                if os.path.getsize(real_path) > 1024 * 50: # 50KB Limit
                    content = "binary_large_file"
                else:
                    with open(real_path, 'r', encoding='utf-8') as fh:
                        content = fh.read()
            except UnicodeDecodeError:
                content = "binary_data"
            except Exception:
                content = ""

            # Metadata defaults
            owner = "root"
            group = "root"
            perm = "-rw-r--r--"
            
            # Dynamic Ownership for Home Directory
            # If we are in ~, and the config says default_home_owner=True,
            # we purposely leaving 'owner' unset (None) so HoneyDB's list_user_dir
            # will dynamically fill it with the current session username.
            if default_home_owner and remapped_path.startswith("~"):
                 owner = None
                 group = None

            # Applying overrides
            # Check both absolute path (/home/USER/file) and remapped path (~/file)
            target_override = None
            if v_abs_path in meta_overrides:
                target_override = meta_overrides[v_abs_path]
            elif remapped_path in meta_overrides:
                target_override = meta_overrides[remapped_path]
                
            if target_override:
                 if 'owner' in target_override: owner = target_override['owner']
                 perm = target_override.get('permissions', target_override.get('mode', perm))

            meta = {
                "permissions": perm,
                "size": len(content)
            }
            if owner: meta["owner"] = owner
            if group: meta["group"] = group
            
            overlay.append({
                "path": remapped_path,
                "parent_path": os.path.dirname(remapped_path),
                "type": "file",
                "content": content,
                "metadata": meta
            })
            
    return overlay
    
def seed_filesystem(db, json_path=None):
    """Deprecated: Skeleton Layer now handles this dynamically."""
    pass

