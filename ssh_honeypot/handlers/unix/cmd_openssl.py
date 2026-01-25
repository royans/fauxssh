from ssh_honeypot.handlers.base import BaseHandler


class OpensslCommand(BaseHandler):
    def handle(self, cmd, context):
        parts = cmd.split()
        if len(parts) < 2:
            return (
                "openssl:Error: 'openssl' is an invalid command.\nStandard commands\nlist ...\n",
                {},
                {"source": "handler", "cached": False},
            )

        subcmd = parts[1]

        if subcmd == "version":
            return (
                "OpenSSL 3.0.11 19 Sep 2023 (Library: OpenSSL 3.0.11 19 Sep 2023)\n",
                {},
                {"source": "handler", "cached": False},
            )

        if subcmd == "req":
            return (
                "Generating a RSA private key\n................+++++\nwriting new private key to 'privkey.pem'\n-----\n",
                {},
                {"source": "handler", "cached": False},
            )

        return "", {}, {"source": "handler", "cached": False}
