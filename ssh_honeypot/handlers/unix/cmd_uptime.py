from ssh_honeypot.handlers.base import BaseHandler
import datetime
import random


class UptimeCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'uptime' command.
        """
        now_dt = datetime.datetime.now()
        now_str = now_dt.strftime("%H:%M:%S")

        # Base uptime: ~14 days (1209600s) + jitter
        base_seconds = 1209600
        # Add seconds since midnight
        now = datetime.datetime.now()
        seconds_today = (
            now - now.replace(hour=0, minute=0, second=0, microsecond=0)
        ).total_seconds()

        total_seconds = base_seconds + seconds_today

        days = int(total_seconds // 86400)
        rem = total_seconds % 86400
        hours = int(rem // 3600)
        minutes = int((rem % 3600) // 60)

        # Randomize load slightly to look alive
        l1 = round(random.uniform(0.01, 0.20), 2)
        l5 = round(random.uniform(0.01, 0.15), 2)
        l15 = round(random.uniform(0.00, 0.10), 2)

        # Format: 17:05:01 up 14 days,  7:22,  2 users,  load average: 0.12, 0.08, 0.02
        return (
            f" {now_str} up {days} days, {hours}:{minutes:02d},  1 user,  load average: {l1:.2f}, {l5:.2f}, {l15:.2f}\n",
            {},
            {"source": "handler", "cached": False},
        )
