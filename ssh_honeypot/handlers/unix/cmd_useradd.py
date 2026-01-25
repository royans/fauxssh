from ssh_honeypot.handlers.base import BaseHandler


class UseraddCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'useradd' command to create a fake user.
        usage: useradd [options] LOGIN
        """
        # Permission check
        if context.get("user") != "root":
            return (
                "useradd: Permission denied.\n",
                {},
                {"source": "handler", "cached": False},
            )

        parts = cmd.split()
        if len(parts) < 2:
            return (
                "Usage: useradd [options] LOGIN\n",
                {},
                {"source": "handler", "cached": False},
            )

        username = parts[-1]
        # Ignoring flags

        if not username or username.startswith("-"):
            for p in parts[1:]:
                if not p.startswith("-"):
                    username = p
                    break

        if not username or username.startswith("-"):
            return (
                "Usage: useradd [options] LOGIN\n",
                {},
                {"source": "handler", "cached": False},
            )

        # Mock success
        # We could actually add to a list of users in DB if we want?
        # For now, just silent success.
        return "", {}, {"source": "handler", "cached": False}
