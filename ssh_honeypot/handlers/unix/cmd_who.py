from ssh_honeypot.handlers.base import BaseHandler
from datetime import datetime


class WhoCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles the 'who' command locally using HoneyDB session data.
        Format: user TTY DATE TIME (IP)
        """
        # db is self.db

        sessions = []
        if self.db:
            sessions = self.db.get_active_sessions()

        output = []

        # Inject Persona Users
        from ssh_honeypot.core.config import config

        persona_users = config.get("persona", "system", "users") or []
        for p_user in persona_users:
            if not any(s["user"] == p_user for s in sessions):
                # Add a fake session for this persona user
                import random

                tty = f"pts/{random.randint(10, 50)}"
                # Mock a start time ~ few hours ago
                time_str = (
                    datetime.now().replace(
                        hour=random.randint(0, 8), minute=random.randint(0, 59)
                    )
                ).strftime("%Y-%m-%d %H:%M")
                line = f"{p_user:<8} {tty:<12} {time_str} (127.0.0.1)"
                output.append(line)

        for s in sessions:

            # standard who format:
            # root     pts/0        2023-10-27 10:00 (192.168.1.55)

            # Parse start_time to format it like 'who' does (YYYY-MM-DD HH:MM)
            # DB stores as ISO or similar default.
            try:
                # Try parsing ISO
                dt = datetime.fromisoformat(s["start_time"])
                time_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                # Fallback if parsing fails
                time_str = str(s["start_time"])[:16]

            line = f"{s['user']:<8} {s['tty']:<12} {time_str} ({s['ip']})"
            output.append(line)

        return "\n".join(output) + "\n", {}, {"source": "local", "cached": False}
