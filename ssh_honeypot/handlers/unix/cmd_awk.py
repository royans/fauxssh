from ssh_honeypot.handlers.base import BaseHandler
import shlex
import re
import hashlib


class AwkCommand(BaseHandler):
    def handle(self, cmd, context):
        try:
            parts = shlex.split(cmd)
        except:
            parts = cmd.split()

        if len(parts) < 2:
            return "", {}, {}

        args = parts[1:]
        script = None
        files = []
        fs_delim = " "  # Default FS is space

        i = 0
        while i < len(args):
            arg = args[i]
            if arg.startswith("-"):
                if arg.startswith("-F"):
                    if len(arg) > 2:
                        fs_delim = arg[2:]
                    elif i + 1 < len(args):
                        fs_delim = args[i + 1]
                        i += 1
                elif arg == "-f":
                    # Script file - logic complexity increased, likely fallback to generic if we can't read it
                    # But for now, ignore or skip
                    if i + 1 < len(args):
                        i += 1
                elif arg.startswith("-v"):
                    if len(arg) == 2 and i + 1 < len(args):
                        i += 1

                i += 1
                continue

            if script is None and not "-f" in cmd:  # Naive check
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
                "awk_data", target_path, context
            )

        # Local execution for simple scripts
        # 1. 'NF{print; exit}' (print first non-empty line)
        # 2. '/Model name/ {gsub(...); print $2; exit}' (Detailed extraction)
        # 3. '{print $N}'

        if not script:
            return "", {}, {}

        # Normalize script
        script = script.strip()

        # Case 1: 'NF{print; exit}' or 'NF {print; exit}'
        if "NF" in script and "print" in script and "exit" in script:
            for line in content.splitlines():
                if line.strip():
                    return line + "\n", {}, {"source": "handler", "cached": False}
            return "", {}, {"source": "handler", "cached": False}

        # Case 2: Simple Print $N
        # '{print $2}'
        match_print = re.match(r"^\{?\s*print \$(\d+)\s*;?\s*\}?$", script)
        if match_print:
            idx = int(match_print.group(1)) - 1
            out = []
            for line in content.splitlines():
                if not line.strip():
                    continue
                fields = line.split(fs_delim) if fs_delim != " " else line.split()

                if 0 <= idx < len(fields):
                    out.append(fields[idx])
                else:
                    out.append("")
            return "\n".join(out) + "\n", {}, {"source": "handler", "cached": False}

        # Case 3: The complex cpuinfo extraction
        if "/Model name/" in script:
            for line in content.splitlines():
                if "Model name" in line:
                    fields = line.split(fs_delim) if fs_delim != " " else line.split()
                    if len(fields) >= 2:
                        val = fields[1]
                        val = val.strip()
                        return val + "\n", {}, {"source": "handler", "cached": False}
            return "", {}, {"source": "handler", "cached": False}

        # Fallback to current Generic/LLM handler
        content_hash = hashlib.md5(content.encode("utf-8", "ignore")).hexdigest()
        cache_key = f"{cmd}::data_hash={content_hash}"
        cached = self.db.get_cached_response(cache_key, context.get("cwd"))
        if cached:
            j, t = self._extract_json_or_text(cached)
            r, u = self._process_llm_json(j, t)
            return r, u, {"source": "cache", "cached": True}

        # Warn: prompt string expects target_path but we might be using stdin (content)
        t_label = files[0] if files else "STDIN"
        prompt = f"Command: {cmd}\n\nInput ({t_label}) Content:\n```\n{content[:5000]}\n```\n\n(INSTRUCTION: Execute the awk command on the provided content. Return ONLY stdout.)"

        resp = self.llm.generate_response(
            prompt, context.get("cwd"), context.get("history", []), [], []
        )
        self.db.cache_response(cache_key, context.get("cwd"), resp)
        j, t = self._extract_json_or_text(resp)
        r, u = self._process_llm_json(j, t)
        return r, u, {"source": "llm", "cached": False}
