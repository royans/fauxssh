from ssh_honeypot.handlers.base import BaseHandler
import datetime


class DateCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'date' command.
        """
        # Note: We should ideally use a fixed time in Persona/Config for even better realism,
        # but for now we follow the existing logic of using host time.
        return (
            datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y\n"),
            {},
            {"source": "handler", "cached": False},
        )
