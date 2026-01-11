from ssh_honeypot.handlers.base import BaseHandler
from datetime import datetime


class WCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles the 'w' command.
        Header: 18:00:00 up 10 days,  4:20,  2 users,  load average: 0.00, 0.01, 0.05
        Body: USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
        """
        # db is self.db

        sessions = []
        if self.db:
            sessions = self.db.get_active_sessions()

        # 1. Header
        now = datetime.now()
        current_time_str = now.strftime("%H:%M:%S")

        # Fake Uptime (Logic: server started 10 days ago + random?)
        # Or just static meaningful uptime.
        uptime_days = 21
        uptime_hours = 4
        uptime_mins = 20

        user_count = len(sessions)

        header = f" {current_time_str} up {uptime_days} days, {uptime_hours}:{uptime_mins},  {user_count} users,  load average: 0.00, 0.01, 0.05"

        output = [header]
        output.append(
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"
        )

        for s in sessions:
            user = s["user"][:8]
            tty = s["tty"]
            ip = s["ip"][:16]  # Truncate if too long

            try:
                dt = datetime.fromisoformat(s["start_time"])
                login_at = dt.strftime("%H:%M")
            except:
                login_at = "00:00"

            idle = "0.00s"  # Simplification
            jcpu = "0.00s"
            pcpu = "0.00s"
            what = "-bash"  # Standard shell

            line = f"{user:<8} {tty:<8} {ip:<16} {login_at:<8} {idle:<6} {jcpu:<6} {pcpu:<6} {what}"
            output.append(line)

        return "\n".join(output) + "\n", {}, {"source": "local", "cached": False}
