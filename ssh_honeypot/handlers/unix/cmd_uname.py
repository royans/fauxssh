from ssh_honeypot.handlers.base import BaseHandler
from ssh_honeypot.core.config import config


class UnameCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'uname' command.
        """
        # Default: Linux
        kernel_name = "Linux"
        sys_conf = config.get("persona", "system") or {}
        nodename = (
            sys_conf.get("hostname")
            or config.get("server", "hostname")
            or "npc-main-server-01"
        )

        kernel_release = (
            config.get("persona", "kernel_release") or "5.10.0-21-cloud-amd64"
        )
        kernel_version = (
            config.get("persona", "kernel_version")
            or "#1 SMP Debian 5.10.162-1 (2023-01-21)"
        )
        machine = config.get("persona", "machine") or "x86_64"
        processor = "x86_64"
        hardware_platform = "x86_64"
        os_name = "GNU/Linux"

        parts = cmd.split()
        flags = set()
        for p in parts[1:]:
            if p.startswith("-"):
                for char in p[1:]:
                    flags.add(char)

        # If no flags, default is -s (Kernel name)
        if not flags:
            return f"{kernel_name}\n", {}, {"source": "handler", "cached": False}

        if "a" in flags or "all" in flags:  # -a is --all
            return (
                f"{kernel_name} {nodename} {kernel_release} {kernel_version} {machine} {os_name}\n",
                {},
                {"source": "handler", "cached": False},
            )

        out = []
        if "s" in flags:
            out.append(kernel_name)
        if "n" in flags:
            out.append(nodename)
        if "r" in flags:
            out.append(kernel_release)
        if "v" in flags:
            out.append(kernel_version)
        if "m" in flags:
            out.append(machine)
        if "p" in flags:
            out.append(processor)
        if "i" in flags:
            out.append(hardware_platform)
        if "o" in flags:
            out.append(os_name)

        if not out:  # Default is -s
            return f"{kernel_name}\n", {}, {"source": "handler", "cached": False}

        return " ".join(out) + "\n", {}, {"source": "handler", "cached": False}
