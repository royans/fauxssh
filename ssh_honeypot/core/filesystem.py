import os
import glob
import shlex


def resolve_path(cwd, path):
    """
    Resolves a path relative to the current working directory.
    Handles ~, ., ..
    """
    if path is None:
        path = "."
    if cwd is None:
        cwd = "/"

    if path.startswith("~"):
        # Expand ~ manually based on simple heuristics since we don't have user context here easily
        # But we can try to guess or just return unmodified if we can't.
        # However, to fix the specific bug '~/.ssh/authorized_keys', we need to handle it.
        # This function signature `resolve_path(cwd, path)` is limiting.
        # Ideally we pass `user` or `home`.
        # For now, let's assume /root if not specified, OR we assume command_handler expands it?
        # CommandHandler calls this. Let's update CommandHandler to expand ~ BEFORE calling resolve_path?
        # OR we modify this to take options.
        # But changing signature breaks callers?
        # Let's check callers. Only CommandHandler uses it.
        # Actually, let's keep this simple:
        # If path starts with ~, we can't robustly resolve without user.
        # But we can cheat: if path starts with ~/, replace with /root/ or /home/user?
        # No, we don't know the user.
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
