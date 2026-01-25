from ssh_honeypot.handlers.base import BaseHandler


class ChattrCommand(BaseHandler):
    def handle(self, cmd, context):
        return "", {}, {"source": "handler", "cached": False}
