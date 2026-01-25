import os
import json
import datetime
import shlex
from ssh_honeypot.core.filesystem import resolve_path, expand_wildcards


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

        if "--help" in args:
            return (
                """Usage: ls [OPTION]... [FILE]...
List information about the FILEs (the current directory by default).
Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.

Mandatory arguments to long options are mandatory for short options too.
  -a, --all                  do not ignore entries starting with .
  -A, --almost-all           do not list implied . and ..
      --author               with -l, print the author of each file
  -b, --escape               print C-style escapes for nongraphic characters
      --block-size=SIZE      with -l, scale sizes by SIZE when printing them;
                               e.g., '--block-size=M'; see SIZE format below
  -B, --ignore-backups       do not list implied entries ending with ~
  -c                         with -lt: sort by, and show, ctime (time of last
                             modification of file status information);
                             with -l: show ctime and sort by name;
                             otherwise: sort by ctime, newest first
  -C                         list entries by columns
      --color[=WHEN]         color the output WHEN; more info below
  -d, --directory            list directories themselves, not their contents
  -D, --dired                generate output designed for Emacs' dired mode
  -f                         list all entries in directory order
  -F, --classify[=WHEN]      append indicator (one of */=>@|) to entries WHEN
      --file-type            likewise, except do not append '*'
      --format=WORD          across -x, commas -m, horizontal -x, long -l,
                             single-column -1, verbose -l, vertical -C
      --full-time            like -l --time-style=full-iso
  -g                         like -l, but do not list owner
      --group-directories-first
                             group directories before files;
                             can be augmented with a --sort option, but any
                             use of --sort=none (-U) disables grouping
  -G, --no-group             in a long listing, don't print group names
  -h, --human-readable       with -l and -s, print sizes like 1K 234M 2G etc.
      --si                   likewise, but use powers of 1000 not 1024
  -H, --dereference-command-line
                             follow symbolic links listed on the command line
      --dereference-command-line-symlink-to-dir
                             follow each command line symbolic link
                             that points to a directory
      --hide=PATTERN         do not list implied entries matching shell PATTERN
                             (overridden by -a or -A)
      --hyperlink[=WHEN]     hyperlink file names WHEN
      --indicator-style=WORD
                             append indicator with style WORD to entry names:
                             none (default), slash (-p),
                             file-type (--file-type), classify (-F)
  -i, --inode                print the index number of each file
  -I, --ignore=PATTERN       do not list implied entries matching shell PATTERN
  -k, --kibibytes            default to 1024-byte blocks for file system usage;
                             used only with -s and per directory totals
  -l                         use a long listing format
  -L, --dereference          when showing file information for a symbolic
                             link, show information for the file the link
                             references rather than for the link itself
  -m                         fill width with a comma separated list of entries
  -n, --numeric-uid-gid      like -l, but list numeric user and group IDs
  -N, --literal              print entry names without quoting
  -o                         like -l, but do not list group information
  -p, --indicator-style=slash
                             append / indicator to directories
  -q, --hide-control-chars   print ? instead of nongraphic characters
      --show-control-chars   show nongraphic characters as-is (the default,
                             unless program is 'ls' and output is a terminal)
  -Q, --quote-name           enclose entry names in double quotes
      --quoting-style=WORD   use quoting style WORD for entry names:
                             literal, locale, shell, shell-always,
                             shell-escape, shell-escape-always, c, escape
                             (overrides QUOTING_STYLE environment variable)
  -r, --reverse              reverse order while sorting
  -R, --recursive            list subdirectories recursively
  -s, --size                 print the allocated size of each file, in blocks
  -S                         sort by file size, largest first
      --sort=WORD            sort by WORD instead of name: none (-U), size (-S),
                             time (-t), version (-v), extension (-X), width
      --time=WORD            change the default of using modification times;
                               access time (-u): atime, access, use;
                               change time (-c): ctime, status;
                               birth time: birth, creation;
                             with -l, WORD determines which time to show;
                             with --sort=time, sort by WORD (newest first)
      --time-style=TIME_STYLE
                             time/date format with -l; see TIME_STYLE below
  -t                         sort by time, newest first; see --time
  -T, --tabsize=COLS         assume tab stops at each COLS instead of 8
  -u                         with -lt: sort by, and show, access time;
                             with -l: show access time and sort by name;
                             otherwise: sort by access time, newest first
  -U                         do not sort; list entries in directory order
  -v                         natural sort of (version) numbers within text
  -w, --width=COLS           set output width to COLS.  0 means no limit
  -x                         list entries by lines instead of by columns
  -X                         sort alphabetically by entry extension
  -Z, --context              print any security context of each file
      --zero                 end each output line with NUL, not newline
  -1                         list one file per line
      --help        display this help and exit
      --version     output version information and exit

The SIZE argument is an integer and optional unit (example: 10K is 10*1024).
Units are K,M,G,T,P,E,Z,Y (powers of 1024) or KB,MB,... (powers of 1000).
Binary prefixes can be used, too: KiB=K, MiB=M, and so on.

The TIME_STYLE argument can be full-iso, long-iso, iso, locale, or +FORMAT.
FORMAT is interpreted like in date(1).  If FORMAT is FORMAT1<newline>FORMAT2,
then FORMAT1 applies to non-recent files and FORMAT2 to recent files.
TIME_STYLE prefixed with 'posix-' takes effect only outside the POSIX locale.
Also the TIME_STYLE environment variable sets the default style to use.

The WHEN argument defaults to 'always' and can also be 'auto' or 'never'.

Using color to distinguish file types is disabled both by default and
with --color=never.  With --color=auto, ls emits color codes only when
standard output is connected to a terminal.  The LS_COLORS environment
variable can change the settings.  Use the dircolors(1) command to set it.

Exit status:
 0  if OK,
 1  if minor problems (e.g., cannot access subdirectory),
 2  if serious trouble (e.g., cannot access command-line argument).

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation <https://www.gnu.org/software/coreutils/ls>
or available locally via: info '(coreutils) ls invocation'
""",
                {},
                {},
            )
        flags = set()
        raw_paths = []

        for arg in args[1:]:
            if arg.startswith("-"):
                # Handle combined flags like -lrt
                for char in arg:
                    if char != "-":
                        flags.add(char)
            else:
                raw_paths.append(arg)

        # Wildcard Expansion and Path Collection
        targets = []
        if not raw_paths:
            targets.append(".")
        else:
            for p in raw_paths:
                if any(x in p for x in ["*", "?", "["]):
                    expanded = expand_wildcards(self.db, p, context)
                    if expanded:
                        targets.extend(expanded)
                    else:
                        targets.append(p)  # Keep literal if no match
                else:
                    targets.append(p)

        cwd = context.get("cwd", "/")
        ip = context.get("client_ip")
        user = context.get("user", "root")

        all_items = []

        # Process all targets
        for target in targets:
            target_path = resolve_path(cwd, target)

            is_dir_check = self.db.is_managed_directory(ip, user, target_path)
            node = self.db.get_user_node(ip, user, target_path)

            if node:
                if node["type"] == "directory":
                    # Get items
                    items = self.db.list_user_dir(ip, user, target_path)
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
        show_hidden = "a" in flags
        visible_items = []
        for item in all_items:
            fname = os.path.basename(item["path"])
            if not show_hidden and fname.startswith("."):
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
        if len(targets) == 1 and not raw_paths:
            listing_dir = True  # ls (implied .)
        elif len(targets) == 1:
            # Check if that target was a directory
            t_path = resolve_path(cwd, targets[0])
            if self.db.is_managed_directory(ip, user, t_path):
                listing_dir = True

        # Sort
        sort_key = lambda x: os.path.basename(x["path"])
        reverse = False

        if "t" in flags:
            sort_key = lambda x: x.get("created_at", "")
            reverse = True

        if "r" in flags:
            reverse = not reverse

        visible_items.sort(key=sort_key, reverse=reverse)

        # Format Output
        output_lines = []

        if "l" in flags:
            # Long format
            if show_hidden and listing_dir:
                now_str = datetime.datetime.now().strftime("%b %d %H:%M")
                output_lines.append(f"drwxr-xr-x 2 {user} {user} 4096 {now_str} .")
                output_lines.append(f"drwxr-xr-x 2 {user} {user} 4096 {now_str} ..")

            for item in visible_items:
                meta = {}
                try:
                    meta = json.loads(item.get("metadata", "{}"))
                except:
                    pass

                perms = meta.get("permissions", "-rw-r--r--")
                if item.get("type") == "directory" and not perms.startswith("d"):
                    perms = "d" + perms[1:]

                # Mock links
                links = 1
                if item.get("type") == "directory":
                    links = 2

                owner = meta.get("owner", user)
                group = meta.get("group", user)
                size = meta.get("size", 4096 if item["type"] == "directory" else 0)

                ts_str = item.get("created_at", "")
                try:
                    ts = datetime.datetime.fromisoformat(ts_str)
                    date_str = ts.strftime("%b %d %H:%M")
                except:
                    date_str = datetime.datetime.now().strftime("%b %d %H:%M")

                fname = os.path.basename(item["path"])

                color_start = ""
                color_end = "\033[0m"
                if item["type"] == "directory":
                    color_start = "\033[01;34m"
                elif "x" in perms:
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
                fname = os.path.basename(item["path"])

                meta = {}
                try:
                    meta = json.loads(item.get("metadata", "{}"))
                except:
                    pass
                perms = meta.get("permissions", "")

                color_start = ""
                color_end = "\033[0m"
                if item["type"] == "directory":
                    color_start = "\033[01;34m"
                elif "x" in perms or item.get("type") == "file":
                    if "x" in perms:
                        color_start = "\033[01;32m"
                    else:
                        color_end = ""
                else:
                    color_end = ""

                names.append(f"{color_start}{fname}{color_end}")

            output = "  ".join(names) + "\n"

        return output, {}, {"source": "handler", "cached": False}
