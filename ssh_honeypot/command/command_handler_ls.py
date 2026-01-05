import os
import json
import datetime
import shlex
from ssh_honeypot.filesystem_utils import resolve_path, expand_wildcards

class LSCommand:
    def __init__(self, db):
        self.db = db

    def handle(self, cmd, context):
        """
        Hybrid 'ls' handler.
        - Managed Directory (User/Skeleton): Returns deterministic output from DB.
        - System/Unknown Directory: Falls back to LLM (returns None).
        """
        args = []
        try:
            args = shlex.split(cmd)
        except:
            args = cmd.split()
            
        flags = set()
        raw_paths = []
        
        for arg in args[1:]:
            if arg.startswith('-'):
                # Handle combined flags like -lrt
                for char in arg:
                    if char != '-': flags.add(char)
            else:
                raw_paths.append(arg)
                
        # Wildcard Expansion and Path Collection
        targets = []
        if not raw_paths:
            targets.append('.')
        else:
            for p in raw_paths:
                if any(x in p for x in ['*', '?', '[']):
                    expanded = expand_wildcards(self.db, p, context)
                    if expanded:
                        targets.extend(expanded)
                    else:
                        targets.append(p) # Keep literal if no match
                else:
                    targets.append(p)

        cwd = context.get('cwd', '/')
        ip = context.get('client_ip')
        user = context.get('user', 'root')
        
        all_items = []
        
        # Process all targets
        for target in targets:
            target_path = resolve_path(cwd, target)
            
            is_dir_check = self.db.is_managed_directory(ip, user, target_path)
            node = self.db.get_user_node(ip, user, target_path)
            
            if node:
                if node['type'] == 'directory':
           # Get items
                    items = self.db.list_user_dir(ip, user, target_path)
                    print(f"DEBUG LS: Path={target_path} Items found={len(items)}")
                    all_items.extend(items)
                else:
                     all_items.append(node)
            elif is_dir_check:
                items = self.db.list_user_dir(ip, user, target_path)
                if items:
                    all_items.extend(items)
            else:
                 # If we have a single unmanaged target, fallback to LLM
                 if len(targets) == 1:
                     return None
                 continue

        # Filter hidden (unless -a)
        show_hidden = 'a' in flags
        visible_items = []
        for item in all_items:
            fname = os.path.basename(item['path'])
            if not show_hidden and fname.startswith('.'):
                 continue
            visible_items.append(item)
            
        # Add . and .. simulation for long listing if single dir target
        # Simplified: checking if we are listing a directory content
        # If all_items contains the dir itself (single node), we don't add . ..
        # But our logic above adds CHILDREN if it's a dir.
        # So check if targets==1 and target resolved to a dir?
        # Re-verify target logic:
        # If target was dir, we fetched children.
        # If target was file, we fetched node.
        # Ideally we know if we are listing a dir.
        
        listing_dir = False
        if len(targets) == 1 and not raw_paths: listing_dir = True # ls (implied .)
        elif len(targets) == 1:
             # Check if that target was a directory
             t_path = resolve_path(cwd, targets[0])
             if self.db.is_managed_directory(ip, user, t_path):
                 listing_dir = True
            
        # Sort
        sort_key = lambda x: os.path.basename(x['path'])
        reverse = False
        
        if 't' in flags:
            sort_key = lambda x: x.get('created_at', '') 
            reverse = True 
        
        if 'r' in flags:
            reverse = not reverse 
            
        visible_items.sort(key=sort_key, reverse=reverse)
        
        # Format Output
        output_lines = []
        
        if 'l' in flags:
            # Long format
            if show_hidden and listing_dir:
                 now_str = datetime.datetime.now().strftime("%b %d %H:%M")
                 output_lines.append(f"drwxr-xr-x 2 {user} {user} 4096 {now_str} .")
                 output_lines.append(f"drwxr-xr-x 2 {user} {user} 4096 {now_str} ..")
            
            for item in visible_items:
                meta = {}
                try:
                    meta = json.loads(item.get('metadata', '{}'))
                except: pass
                
                perms = meta.get('permissions', '-rw-r--r--')
                if item.get('type') == 'directory' and not perms.startswith('d'):
                    perms = 'd' + perms[1:]
                
                # Mock links
                links = 1
                if item.get('type') == 'directory': links = 2
                
                owner = meta.get('owner', user)
                group = meta.get('group', user)
                size = meta.get('size', 4096 if item['type']=='directory' else 0)
                
                ts_str = item.get('created_at', '')
                try:
                    ts = datetime.datetime.fromisoformat(ts_str)
                    date_str = ts.strftime("%b %d %H:%M")
                except:
                    date_str = datetime.datetime.now().strftime("%b %d %H:%M") 
                
                fname = os.path.basename(item['path'])
                
                color_start = ""
                color_end = "\033[0m"
                if item['type'] == 'directory':
                    color_start = "\033[01;34m"
                elif 'x' in perms:
                    color_start = "\033[01;32m"
                else:
                    color_end = "" 
                    
                line = f"{perms} {links:>2} {owner} {group} {size:>4} {date_str} {color_start}{fname}{color_end}"
                output_lines.append(line)
                
            output = f"total {len(visible_items)}\n" + "\n".join(output_lines) + "\n"
        
        else:
             # Short format
             names = []
             if show_hidden and listing_dir:
                 names.append(".")
                 names.append("..")
             
             for item in visible_items:
                 fname = os.path.basename(item['path'])
                 
                 meta = {}
                 try: meta = json.loads(item.get('metadata', '{}'))
                 except: pass
                 perms = meta.get('permissions', '')
                 
                 color_start = ""
                 color_end = "\033[0m"
                 if item['type'] == 'directory':
                    color_start = "\033[01;34m"
                 elif 'x' in perms or item.get('type') == 'file': 
                    if 'x' in perms: color_start = "\033[01;32m"
                    else: color_end = ""
                 else:
                    color_end = ""
                 
                 names.append(f"{color_start}{fname}{color_end}")
                 
             output = "  ".join(names) + "\n"
        
        return output, {}, {'source': 'local', 'cached': False}
