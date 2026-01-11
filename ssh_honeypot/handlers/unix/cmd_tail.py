from ssh_honeypot.handlers.base import BaseHandler


class TailCommand(BaseHandler):
    def handle(self, cmd, context):
        parts = cmd.split()
        num_lines = 10
        files = []

        i = 1
        while i < len(parts):
            arg = parts[i]
            if arg.startswith("-n"):
                if arg == "-n":
                    if i + 1 < len(parts):
                        try:
                            num_lines = int(parts[i + 1])
                            i += 2
                            continue
                        except:
                            pass
                else:
                    try:
                        num_lines = int(arg[2:])
                    except:
                        pass
            elif arg.startswith("-") and len(arg) > 1 and arg[1:].isdigit():
                try:
                    num_lines = int(arg[1:])
                except:
                    pass
            elif not arg.startswith("-"):
                files.append(arg)
            i += 1

        content = ""
        if not files:
            content = context.get("stdin", "")
        else:
            c, src = self._generate_or_get_content("tail", files[0], context)
            content = c

        lines = content.splitlines(keepends=True)
        if len(lines) > num_lines:
            return "".join(lines[-num_lines:]), {}, {"source": "local", "cached": False}
        return "".join(lines), {}, {"source": "local", "cached": False}
