from ssh_honeypot.handlers.base import BaseHandler


class WcCommand(BaseHandler):
    def handle(self, cmd, context):
        parts = cmd.split()

        show_lines = False
        show_words = False
        show_chars = False
        target_path = None

        for p in parts[1:]:
            if p.startswith("-"):
                if "l" in p:
                    show_lines = True
                if "w" in p:
                    show_words = True
                if "c" in p or "m" in p:
                    show_chars = True
            else:
                target_path = p

        if not (show_lines or show_words or show_chars):
            show_lines = True
            show_words = True
            show_chars = True

        content = ""
        source = "local"
        if context.get("stdin"):
            content = context["stdin"]
            source = "pipe"
            target_path = ""
        else:
            if not target_path:
                return "0 0 0\n", {}, {}
            content, source = self._generate_or_get_content("wc", target_path, context)

        lines = content.split("\n")
        if lines and lines[-1] == "":
            lines.pop()

        c_lines = len(lines)
        c_words = len(content.split())
        c_chars = len(content)

        out_parts = []
        if show_lines:
            out_parts.append(str(c_lines))
        if show_words:
            out_parts.append(str(c_words))
        if show_chars:
            out_parts.append(str(c_chars))

        if target_path:
            out_parts.append(target_path)

        return (
            " ".join(out_parts) + "\n",
            {},
            {"source": source, "cached": source == "local"},
        )
