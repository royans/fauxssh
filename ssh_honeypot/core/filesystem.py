import os
import glob
import shlex


def resolve_path(cwd, path):
    """
    Resolves a path relative to the current working directory.
    Handles ~, ., ..
    """
    if path.startswith("~"):
        # In a real shell ~ expands to home.
        # But here we might check context['user']?
        # For simple resolving we assume ~ is usually /root or /home/user depending on user.
        # But this function doesn't know user.
        # Typically the CALLER handles ~ expansion or we pass user home.
        # command_handler.py's _resolve_path assumed path was already partially handled or just used abspath logic?
        # Let's check original implementation logic logic.
        # Original:
        # if path == '~': return context.get('home', '/root') ...
        # Wait, the original _resolve_path was:
        # def _resolve_path(self, cwd, path):
        #    if path.startswith('/'): return os.path.normpath(path)
        #    return os.path.normpath(os.path.join(cwd, path))

        # It did NOT handle ~. Command handler handle_cd usually handled ~.
        pass

    if path.startswith("/"):
        return os.path.normpath(path)

    # Handle . and .. via normpath
    joined = os.path.join(cwd, path)
    return os.path.normpath(joined)


def expand_wildcards(db, path_pattern, context):
    """
    Expands wildcards (*, ?, []) in a path pattern using the VFS (HoneyDB).
    Returns a list of resolved absolute paths.
    """
    cwd = context.get("cwd", "/")
    ip = context.get("client_ip")
    user = context.get("user", "root")

    # 1. Resolve to absolute generic pattern
    abs_pattern = resolve_path(cwd, path_pattern)

    # 2. Get parent directory to list
    parent_dir = os.path.dirname(abs_pattern)
    filename_pattern = os.path.basename(abs_pattern)

    # 3. List entries in parent
    # We only assume managed directories can allow wildcard expansion.
    if not db.is_managed_directory(ip, user, parent_dir):
        # If the directory itself isn't managed, we can't really expand wildcards inside it effectively
        # unless we fallback to some mock logic. For now return empty or literal.
        return []

    items = db.list_user_dir(ip, user, parent_dir)
    # items list of dicts: {'path': '...', ...}

    # 4. Filter matches
    import fnmatch

    matches = []
    for item in items:
        # Check matching
        # item['path'] is absolute.
        fname = os.path.basename(item["path"])

        if fnmatch.fnmatch(fname, filename_pattern):
            matches.append(item["path"])

    return sorted(matches)
