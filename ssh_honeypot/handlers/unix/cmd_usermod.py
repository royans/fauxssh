from ssh_honeypot.handlers.base import BaseHandler


class UsermodCommand(BaseHandler):
    def handle(self, cmd, context):
        if context.get("user") != "root":
            return (
                "usermod: Permission denied.\n",
                {},
                {"source": "handler", "cached": False},
            )
        return "", {}, {"source": "handler", "cached": False}
