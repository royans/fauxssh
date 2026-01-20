from ssh_honeypot.handlers.base import BaseHandler
import time


class AptCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'apt' and 'apt-get' commands.
        """
        # Distro Check
        from ssh_honeypot.core.config import config

        distro = config.get("persona", "system", "distro_id") or "debian"
        if distro not in ["debian", "ubuntu", "kali"]:
            return (
                f"-bash: apt: command not found\n",
                {},
                {"source": "local", "cached": False},
            )

        user = context.get("user", "unknown")

        # Permission check
        if user != "root":
            return (
                f"E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n",
                {},
                {"source": "local", "cached": False},
            )

        parts = cmd.split()
        if len(parts) < 2:
            return (
                "apt 1.0.9.8.5 for amd64 compiled on Jan 15 2026 12:00:00\nUsage: apt [options] command\n       apt [options] install|remove pkg1 [pkg2 ...]\n       apt [options] source pkg1 [pkg2 ...]\n\napt is a commandline package manager and provides commands for\nsearching and managing as well as querying information about packages.\nIt provides the same functionality as the specialized APT tools,\nlike apt-get and apt-cache, but enables options more suitable for\ninteractive use by default.\n",
                {},
                {"source": "local", "cached": False},
            )

        subcmd = parts[1]

        if subcmd == "update":
            output = """Hit:1 http://security.debian.org/debian-security bookworm-security InRelease
Hit:2 http://deb.debian.org/debian bookworm InRelease
Hit:3 http://deb.debian.org/debian bookworm-updates InRelease
Reading package lists... Done
"""
            return output, {}, {"source": "local", "cached": False}

        elif subcmd == "upgrade":
            output = """Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Calculating upgrade... Done
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
"""
            return output, {}, {"source": "local", "cached": False}

        elif subcmd == "install":
            if len(parts) < 3:
                return (
                    "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
                    {},
                    {"source": "local", "cached": False},
                )

            packages = parts[2:]
            # Filter out flags
            packages = [p for p in packages if not p.startswith("-")]

            if not packages:
                return (
                    "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
                    {},
                    {"source": "local", "cached": False},
                )

            pkg_str = " ".join(packages)
            output = f"""Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  {pkg_str}
0 upgraded, {len(packages)} newly installed, 0 to remove and 0 not upgraded.
Need to get 0 B/42.5 kB of archives.
After this operation, 1024 kB of additional disk space will be used.
Selecting previously unselected package {packages[0]}.
(Reading database ... 45210 files and directories currently installed.)
Preparing to unpack .../{packages[0]}_1.0.0_amd64.deb ...
Unpacking {packages[0]} (1.0.0) ...
Setting up {packages[0]} (1.0.0) ...
Processing triggers for man-db (2.9.4-2) ...
"""
            return output, {}, {"source": "local", "cached": False}

        elif subcmd == "remove":
            if len(parts) < 3:
                return (
                    "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
                    {},
                    {"source": "local", "cached": False},
                )

            packages = parts[2:]
            packages = [p for p in packages if not p.startswith("-")]

            if not packages:
                return (
                    "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
                    {},
                    {"source": "local", "cached": False},
                )

            pkg_str = " ".join(packages)
            output = f"""Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages will be REMOVED:
  {pkg_str}
0 upgraded, 0 newly installed, {len(packages)} to remove and 0 not upgraded.
After this operation, 0 B of additional disk space will be used.
(Reading database ... 45210 files and directories currently installed.)
Removing {packages[0]} (1.0.0) ...
Processing triggers for man-db (2.9.4-2) ...
"""
            return output, {}, {"source": "local", "cached": False}

        else:
            return (
                f"E: Invalid operation {subcmd}\n",
                {},
                {"source": "local", "cached": False},
            )
