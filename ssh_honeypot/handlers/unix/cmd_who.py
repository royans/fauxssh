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
