from ssh_honeypot.handlers.base import BaseHandler
import shlex
import re


class SedCommand(BaseHandler):
    def handle(self, cmd, context):
        try:
            parts = shlex.split(cmd)
        except:
            parts = cmd.split()

        if len(parts) < 2:
            return "", {}, {}

        # Parse args
        # Expected syntax: sed [options] 'script' [input-file]
        # Or: sed [options] -e 'script' [input-file]

        args = parts[1:]
        script = None
        files = []

        # Simple parser
        i = 0
        while i < len(args):
            arg = args[i]
            if arg.startswith("-"):
                # Handle flags
                if arg == "-e":
                    if i + 1 < len(args):
                        script = args[
                            i + 1
                        ]  # Accumulate? sed allows multiple -e. For now take last or combine.
                        i += 1
                elif arg == "-r" or arg == "-E":
                    # Extended regex - not fully supported in simple mock but we note it
                    pass
                i += 1
                continue

            if script is None:
                script = arg
            else:
                files.append(arg)
            i += 1

        content = ""
        source = "local"

        if context.get("stdin"):
            content = context["stdin"]
            source = "pipe"
        elif files:
            target_path = files[0]
            content, source = self._generate_or_get_content(
                "sed_target", target_path, context
            )
        else:
            # No input
            return "", {}, {}

        if not script:
            return content, {}, {"source": source, "cached": False}

        # Handle simple substitution: s/regex/replacement/flags
        # Also handle multiple commands separated by ;

        result_content = content
        commands = script.split(";")

        for command in commands:
            command = command.strip()
            if not command:
                continue

            if command.startswith("s/"):
                # s/find/replace/flags
                # Delimiter is /
                # But delimiter can be anything, e.g. s#find#replace#
                delim = command[1]

                # regex split?
                # parts: ['', 'find', 'replace', 'flags'] (if using s/find/replace/flags)
                # But 'find' or 'replace' might contain escaped delimiter.
                # Simple implementation: split by delimiter

                # NOTE: This is naive. Better regex needed or manual parsing.
                # For `s/^ *//` -> parts: s, ^ *, ,

                pattern = (
                    f"^{command[1]}(.*?){command[1]}(.*?){command[1]}([a-zA-Z0-9]*)$"
                )
                match = re.match(pattern, command)
                if match:
                    find_pat = match.group(1)
                    replace_pat = match.group(2)
                    flags = match.group(3)

                    count = 0
                    if "g" in flags:
                        count = 0  # Replace all (re.sub default is 0)
                    else:
                        count = 1

                    try:
                        result_content = re.sub(
                            find_pat,
                            replace_pat,
                            result_content,
                            count=count,
                            flags=re.MULTILINE,
                        )
                    except Exception as e:
                        # Regex fail
                        pass
                else:
                    # Maybe it's s/foo/bar (no trailing slash implies no flags? usually s/foo/bar/)
                    # Try s/foo/bar format
                    pattern_noflags = f"^{command[1]}(.*?){command[1]}(.*?)$"
                    # But standard sed s/// usually has 3 delimiters. s/a/b is invalid, must be s/a/b/
                    # Let's assume the user command `s/^ *//` is valid (it is).
                    pass

        return result_content, {}, {"source": "local", "cached": False}
