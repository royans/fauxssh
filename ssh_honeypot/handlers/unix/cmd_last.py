from ssh_honeypot.handlers.base import BaseHandler
from datetime import datetime


class LastCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'last' command.
        Format:
        user     pts/0        192.168.1.55     Tue Oct 27 10:00   still logged in
        """
        limit = 20
        if "-n" in cmd:
            parts = cmd.split()
            try:
                idx = parts.index("-n")
                limit = int(parts[idx + 1])
            except:
                pass

        # Get Protocol from context (default to None to show all if missing)
        protocol = context.get("protocol")

        # Get Ignored IPs
        from ssh_honeypot.core.utils import get_ignored_ips

        ignored_ips = get_ignored_ips()

        sessions = []
        if self.db:
            sessions = self.db.get_recent_sessions(limit, protocol=protocol)

        output = []
        import random

        for s in sessions:
            # FILTER: Ignore specific IPs
            if s["ip"] in ignored_ips:
                continue

            user = s["user"][:8]
            tty = s["tty"]
            ip_str = s["ip"]

            # ANONYMIZE: Randomize last 2 octets for visualization
            try:
                ip_parts = ip_str.split(".")
                if len(ip_parts) == 4:
                    ip_parts[2] = str(random.randint(0, 255))
                    ip_parts[3] = str(random.randint(1, 254))
                    ip_str = ".".join(ip_parts)
            except:
                pass

            # Format: Tue Oct 27 10:00
            try:
                start_dt = datetime.fromisoformat(s["start_time"])
                start_str = start_dt.strftime("%a %b %d %H:%M")
            except:
                start_str = "Unknown"

            duration_str = "still logged in"
            if s.get("end_time"):
                try:
                    end_dt = datetime.fromisoformat(s["end_time"])
                    # duration = end_dt - start_dt
                    # format (HH:MM)
                    # keeping it simple standard "down" or duration
                    duration_str = f"- {end_dt.strftime('%H:%M')}"
                except:
                    duration_str = "- down"

            line = f"{user:<8} {tty:<12} {ip_str:<16} {start_str:<16}   {duration_str}"
            output.append(line)

        # wtmp begins header
        output.append("\nwtmp begins Wed Jan 01 00:00:00 2026")
        return "\n".join(output) + "\n", {}, {"source": "local", "cached": False}
