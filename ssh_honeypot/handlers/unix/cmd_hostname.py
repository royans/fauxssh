from ssh_honeypot.handlers.base import BaseHandler
from ssh_honeypot.core.config import config


class HostnameCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'hostname' command.
        """
        # Use persona hostname if available
        sys_conf = config.get("persona", "system") or {}
        h = (
            sys_conf.get("hostname")
            or config.get("server", "hostname")
            or "npc-main-server-01"
        )

        # Parse basic args
        parts = cmd.split()
        if len(parts) > 1:
            if parts[1].startswith("-"):
                # -i, etc.
                if "i" in parts[1]:
                    return (
                        f"{context.get('honeypot_ip', '127.0.0.1')}\n",
                        {},
                        {"source": "handler", "cached": False},
                    )
            else:
                # Attempt to set hostname -> Permission denied (unless root)
                if context.get("user") != "root":
                    return (
                        f"hostname: you must be root to change the host name\n",
                        {},
                        {"source": "handler", "cached": False},
                    )
                else:
                    # Fake set success (no persistence)
                    return "", {}, {"source": "handler", "cached": False}

        return f"{h}\n", {}, {"source": "handler", "cached": False}
