import os
import shlex
from ssh_honeypot.handlers.base import BaseHandler
from ssh_honeypot.core.filesystem import resolve_path


class LsattrCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handle 'lsattr' command.
        Simulates listing file attributes.
        """
        try:
            args = shlex.split(cmd)
        except:
            args = cmd.split()

        cwd = context.get("cwd", "/")
        ip = context.get("client_ip")
        user = context.get("user", "root")

        # Flags (basic support)
        flags = set()
        raw_paths = []
        for arg in args[1:]:
            if arg.startswith("-") and len(arg) > 1:
                for char in arg[1:]:
                    flags.add(char)
            else:
                raw_paths.append(arg)

        if not raw_paths:
            raw_paths.append(".")

        # In honeypot, we use a fixed attribute string for realism
        # 'e' (extents) is very common on modern Linux (ext4)
        DEFAULT_ATTRS = "--------------e-------"

        targets = []
        for p in raw_paths:
            abs_path = resolve_path(cwd, p)
            targets.append((p, abs_path))

        output_lines = []
        errors = []

        for original_p, abs_path in targets:
            # Check existence
            node = self.db.get_user_node(ip, user, abs_path)
            if not node:
                node = self.db.get_fs_node(abs_path)

            if not node:
                # lsattr: No such file or directory while trying to stat /tmp/fake
                errors.append(
                    f"lsattr: No such file or directory while trying to stat {original_p}"
                )
                continue

            if node["type"] == "directory" and "d" not in flags:
                # List items in directory
                items = self.db.list_user_dir(ip, user, abs_path)
                # If nothing in DB, maybe check FS?
                if not items:
                    # For realism, we can't easily list "everything" without DB/LLM,
                    # but we can show nothing if it's an empty honey dir.
                    pass

                for item in items:
                    fname = os.path.basename(item["path"])
                    if not fname.startswith(".") or "a" in flags:
                        output_lines.append(f"{DEFAULT_ATTRS} {item['path']}")
            else:
                # Show file or dir itself
                output_lines.append(f"{DEFAULT_ATTRS} {abs_path}")

        result = ""
        if errors:
            result += "\n".join(errors) + "\n"
        if output_lines:
            result += "\n".join(output_lines) + "\n"

        return result, {}, {"source": "handler", "cached": False}
