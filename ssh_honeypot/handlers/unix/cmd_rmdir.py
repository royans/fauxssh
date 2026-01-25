from ssh_honeypot.handlers.base import BaseHandler
from ssh_honeypot.core.filesystem import resolve_path


class RmdirCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'rmdir' command.
        Removes empty directories.
        """
        parts = cmd.split()
        if len(parts) < 2:
            return (
                "rmdir: missing operand\n",
                {},
                {"source": "handler", "cached": False},
            )

        target_path = parts[1]
        if target_path.startswith("-"):
            if len(parts) > 2:
                target_path = parts[2]
            else:
                return (
                    "rmdir: flags not fully supported\n",
                    {},
                    {"source": "handler", "cached": False},
                )

        cwd = context.get("cwd", "/")
        abs_path = resolve_path(cwd, target_path)

        # Permission check
        allowed = (
            abs_path.startswith("/tmp/")
            or abs_path.startswith("/home/")
            or abs_path.startswith("/root/")
        )
        if not allowed:
            return (
                f"rmdir: failed to remove '{target_path}': Permission denied\n",
                {},
                {"source": "handler", "cached": False},
            )

        client_ip = context.get("client_ip")
        user = context.get("user")

        if not self.db:
            return (
                "Internal Error: DB not available\n",
                {},
                {"source": "handler", "cached": False},
            )

        # Check if exists and is dir
        curr = self.db.get_user_node(client_ip, user, abs_path)
        if not curr:
            return (
                f"rmdir: failed to remove '{target_path}': No such file or directory\n",
                {},
                {"source": "handler", "cached": False},
            )

        if curr.get("type") != "dir":
            return (
                f"rmdir: failed to remove '{target_path}': Not a directory\n",
                {},
                {"source": "handler", "cached": False},
            )

        # Check if empty from user FS perspective
        user_files = self.db.list_user_dir(client_ip, user, abs_path)
        if len(user_files) > 0:
            return (
                f"rmdir: failed to remove '{target_path}': Directory not empty\n",
                {},
                {"source": "handler", "cached": False},
            )

        self.db.delete_user_file(client_ip, user, abs_path)
        return (
            "",
            {"file_modifications": [{"action": "delete", "path": abs_path}]},
            {"source": "handler", "cached": False},
        )
