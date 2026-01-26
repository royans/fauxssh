import os
import shlex
from ssh_honeypot.handlers.base import BaseHandler
from ssh_honeypot.core.filesystem import resolve_path


class ChattrCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handle 'chattr' command.
        Simulates changing file attributes.
        """
        try:
            args = shlex.split(cmd)
        except:
            args = cmd.split()

        if len(args) < 2:
            return (
                "Usage: chattr [-RVf] [-+=aAcCdDeijPsStTu] [-v version] files...\n",
                {},
                {"source": "handler", "cached": False},
            )

        # Basic help check
        if "--help" in args:
            return (
                "Usage: chattr [-RVf] [-+=aAcCdDeijPsStTu] [-v version] files...\n",
                {},
                {"source": "handler", "cached": False},
            )

        # Extract flags and targets
        targets = []
        for arg in args[1:]:
            if arg.startswith("-") or arg.startswith("+") or arg.startswith("="):
                continue
            targets.append(arg)

        if not targets:
            return (
                "chattr: Must use at least one file\n",
                {},
                {"source": "handler", "cached": False},
            )

        cwd = context.get("cwd", "/")
        ip = context.get("client_ip")
        user = context.get("user", "root")

        errors = []
        for target in targets:
            abs_path = resolve_path(cwd, target)
            # Check if managed
            node = self.db.get_user_node(ip, user, abs_path)
            if not node:
                # Check global FS
                node = self.db.get_fs_node(abs_path)

            if not node:
                # Use chattr specific error format
                # chattr: No such file or directory while trying to stat /tmp/test
                errors.append(
                    f"chattr: No such file or directory while trying to stat {target}"
                )

        if errors:
            return (
                "\n".join(errors) + "\n",
                {},
                {"source": "handler", "cached": False},
            )

        # If all files exist, return empty output (success)
        return "", {}, {"source": "handler", "cached": False}
