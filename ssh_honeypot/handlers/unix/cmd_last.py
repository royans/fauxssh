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
        from ssh_honeypot.core.config import config

        # Inject Persona Users (Historical)
        if not self.db:
            return (
                "\nwtmp begins Wed Jan 01 00:00:00 2026\n",
                {},
                {"source": "handler", "cached": False},
            )

        persona_users = config.get("persona", "system", "users") or []
        for p_user in persona_users:
            if p_user is None:
                continue
            if isinstance(p_user, dict):
                p_user = p_user.get("name")

            if not p_user:
                continue

            p_user = str(p_user)

            # Add 1-2 fake historical entries for this user
            for _ in range(random.randint(1, 2)):
                tty = f"pts/{random.randint(0, 10)}"
                ip_stub = "10.0.0." + str(random.randint(2, 254))
                # Random date in last few days
                days_ago = random.randint(1, 5)
                login_dt = datetime.now().replace(
                    day=datetime.now().day - days_ago, hour=random.randint(8, 20)
                )
                start_str = login_dt.strftime("%a %b %d %H:%M")
                dur_hours = random.randint(1, 8)
                line = f"{p_user:<8} {tty:<12} {ip_stub:<16} {start_str:<16}   ({dur_hours:02d}:{random.randint(0, 59):02d})"
                output.append(line)

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
        return "\n".join(output) + "\n", {}, {"source": "handler", "cached": False}
