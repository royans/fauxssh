from ssh_honeypot.handlers.base import BaseHandler


class IdCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'id' command.
        """
        user = context.get("user", "alabaster")
        # Simulate typical uid/gid
        if user == "root":
            return (
                "uid=0(root) gid=0(root) groups=0(root)\n",
                {},
                {"source": "handler", "cached": False},
            )
        else:
            return (
                f"uid=1000({user}) gid=1000({user}) groups=1000({user}),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)\n",
                {},
                {"source": "handler", "cached": False},
            )
