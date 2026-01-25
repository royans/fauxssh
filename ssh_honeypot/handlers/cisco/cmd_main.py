import os
import random
import datetime


def handle_cisco_show(cmd, context):
    """
    Handles 'show' commands for Cisco IOS.
    """
    parts = cmd.split()
    if len(parts) < 2:
        return "% Incomplete command.\n", {}, {"source": "handler", "cached": False}

    sub = parts[1]

    if sub == "version":
        uptime = "1 week, 2 days, 4 hours, 12 minutes"
        hostname = (
            context.get("persona_config", {})
            .get("system", {})
            .get("hostname", "Router")
        )
        output = f"""
Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE4, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2013 by Cisco Systems, Inc.
Compiled Wed 26-Jun-13 02:35 by mnguyen

ROM: Bootstrap program is C2960 boot loader
BOOTLDR: C2960 Boot Loader (C2960-HBOOT-M) Version 12.2(44)SE5, RELEASE SOFTWARE (fc1)

{hostname} uptime is {uptime}
System returned to ROM by power-on
System image file is "flash:/c2960-lanbasek9-mz.150-2.SE4.bin"

This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use. Delivery of Cisco cryptographic products does not imply
third-party authority to import, export, distribute or use encryption.
Importers, exporters, distributors and users are responsible for
compliance with U.S. and local country laws. By using this product you
agree to comply with applicable laws and regulations. If you are unable
to comply with U.S. and local laws, return this product immediately.

A summary of U.S. laws governing Cisco cryptographic products may be found at:
http://www.cisco.com/wwl/export/crypto/tool/stqrg.html

If you require further assistance please contact us by sending email to
export@cisco.com.

cisco WS-C2960-24TC-L (PowerPC405) processor (revision D0) with 65536K bytes of memory.
Processor board ID FOC12345678
Last reset from power-on
1 Virtual Ethernet interface
24 FastEthernet interfaces
2 Gigabit Ethernet interfaces
The password-recovery mechanism is enabled.

64K bytes of flash-simulated non-volatile configuration memory.
Base ethernet MAC Address       : 00:1B:2C:3D:4E:5F
Motherboard assembly number     : 73-9876-01
Power supply part number        : 341-0097-02
Motherboard serial number       : FOC12345678
Power supply serial number      : DCA12345678
Model revision number           : D0
Motherboard revision number     : A0
Model number                    : WS-C2960-24TC-L
System serial number            : FOC12345678
Top Assembly Part Number        : 800-26671-02
Top Assembly Revision Number    : A0
Variation revision              : 0
Clemmette revision              : 1.0
Video BIOS revision             : 0.0
 
Switch Ports Model              SW Version            SW Image                 
------ ----- -----              ----------            ----------               
*    1 26    WS-C2960-24TC-L    15.0(2)SE4            C2960-LANBASEK9-M        

Configuration register is 0xF
"""
        return output, {}, {"source": "handler", "cached": False}

    elif sub in ["running-config", "run", "conf", "config", "configuration"]:
        # Check Privilege Level
        priv = context.get("env", {}).get("privilege_level", 0)
        if priv < 15:
            return (
                "% Invalid input detected at '^' marker.\n",
                {},
                {"source": "handler", "cached": False},
            )

        hostname = (
            context.get("persona_config", {})
            .get("system", {})
            .get("hostname", "Router")
        )

        # PERSISTENCE: Check stored config in VFS (simulated NVRAM/RAM)
        # We store it in a hidden file in the user's root or similar.
        # Using context['db'] to access VFS would be ideal, but handlers return 'updates' typically.
        # Ideally we read from context['env'] which persists for session, OR check HoneyDB.
        # Since we want it modifiable, let's use context['env'] for session persistence for now.
        # Real persistence across sessions requires HoneyDB file I/O which is async-ish via updates.

        stored_config = context.get("env", {}).get("cisco_running_config")

        if not stored_config:
            # 1. Try DB Persistent Cache for this Persona
            db = context.get("db")
            persona_name = context.get("persona_config", {}).get("name", "default")
            cache_key = f"cisco_running_config:{persona_name}"

            if db:
                # Use PERSONA_CONFIG as a pseudo-CWD for global config storage
                stored_config = db.get_cached_response(cache_key, "PERSONA_CONFIG")

            if not stored_config:
                # 2. Try Persona Default
                persona_defaults = context.get("persona_config", {}).get("defaults", {})
                if "running_config" in persona_defaults:
                    stored_config = persona_defaults["running_config"]

            # 3. Fallback to LLM if no default
            if not stored_config:
                llm = context.get("llm")
                if llm:
                    prompt = f"""Generate a realistic Cisco IOS running-configuration for a switch named '{hostname}'.
Include standard interfaces (Vlan1, FastEthernet0/1-24, GigabitEthernet0/1-2), basic services (timestamps, password-encryption), and line vty configuration.
Output ONLY the raw configuration text, starting with 'version 15.0' or similar. Do not include markdown blocks."""

                    stored_config = llm.generate_response(
                        command="generate_cisco_config",
                        cwd="/",
                        history_context=[],
                        known_paths=[],
                        file_list=[],
                        override_prompt=prompt,
                    )
                    stored_config = (
                        stored_config.replace("```cisco", "").replace("```", "").strip()
                    )

                    # Store in DB for persistence across sessions
                    if db and stored_config:
                        db.cache_response(cache_key, "PERSONA_CONFIG", stored_config)
                else:
                    stored_config = f"! Fallback Config\nhostname {hostname}\nend"

        # Save to env for persistence in this session
        updates = {"env": {"cisco_running_config": stored_config}}

        output = (
            f"Building configuration...\n\nCurrent configuration : {len(stored_config)} bytes\n"
            + stored_config
            + "\n"
        )
        return output, updates, {"source": "handler", "cached": False}

    elif sub == "ip":
        if len(parts) > 2 and parts[2] == "interface":
            if len(parts) > 3 and "brief" in parts[3]:
                output = """
Interface              IP-Address      OK? Method Status                Protocol
Vlan1                  unassigned      YES manual administratively down down    
FastEthernet0/1        unassigned      YES manual down                  down    
FastEthernet0/2        unassigned      YES manual down                  down    
GigabitEthernet0/1     unassigned      YES manual down                  down    
"""
                return output, {}, {"source": "handler", "cached": False}

    return (
        "% Invalid input detected at '^' marker.\n",
        {},
        {"source": "handler", "cached": False},
    )


def handle_cisco_enable(cmd, context):
    updates = {"env": {"privilege_level": 15}}
    return "", updates, {"source": "handler", "cached": False}


def handle_cisco_configure(cmd, context):
    parts = cmd.split()
    if len(parts) > 1 and parts[1] == "terminal":
        priv = context.get("env", {}).get("privilege_level", 0)
        if priv < 15:
            return (
                "% Type 'enable' to enter privileged mode first.\n",
                {},
                {"source": "handler", "cached": False},
            )

        updates = {"env": {"config_mode": True}}
        return (
            "Enter configuration commands, one per line.  End with CNTL/Z.\n",
            updates,
            {"source": "handler", "cached": False},
        )

    return (
        "% Invalid input detected at '^' marker.\n",
        {},
        {"source": "handler", "cached": False},
    )


def handle_cisco_exit(cmd, context):
    # Downgrade or disconnect
    config_mode = context.get("env", {}).get("config_mode", False)
    priv = context.get("env", {}).get("privilege_level", 0)

    updates = {}

    if config_mode:
        updates["env"] = {"config_mode": False}
        return (
            """
%SYS-5-CONFIG_I: Configured from console by console
""",
            updates,
            {"source": "handler", "cached": False},
        )

    if priv == 15:
        updates["env"] = {"privilege_level": 1}
        return "", updates, {"source": "handler", "cached": False}

    return "disconnect", {}, {"source": "handler", "cached": False}


def handle_cisco_write(cmd, context):
    return (
        "Building configuration...\n[OK]\n",
        {},
        {"source": "handler", "cached": False},
    )


def handle_cisco_help(cmd, context):
    """
    Handles '?' and 'help'.
    """
    priv = context.get("env", {}).get("privilege_level", 0)

    # Common commands
    cmds = [
        ("access-enable", "Create a temporary Access-List entry"),
        ("access-profile", "Apply user-profile to interface"),
        ("clear", "Reset functions"),
        ("connect", "Open a terminal connection"),
        ("disable", "Turn off privileged commands"),
        ("disconnect", "Disconnect an existing network connection"),
        ("enable", "Turn on privileged commands"),
        ("exit", "Exit from the EXEC"),
        ("help", "Description of the interactive help system"),
        ("lock", "Lock the terminal"),
        ("login", "Log in as a particular user"),
        ("logout", "Exit from the EXEC"),
        ("ping", "Send echo messages"),
        ("resume", "Resume an active network connection"),
        ("set", "Set system parameter (not Config)"),
        ("show", "Show running system information"),
        ("ssh", "Open an ssh connection"),
        ("systat", "Display information about terminal lines"),
        ("telnet", "Open a telnet connection"),
        ("terminal", "Set terminal line parameters"),
        ("traceroute", "Trace route to destination"),
        ("tunnel", "Open a tunnel connection"),
        ("where", "List active connections"),
    ]

    if priv >= 15:
        # Add Priv Exec commands
        cmds.extend(
            [
                ("cd", "Change current directory"),
                ("clock", "Manage the system clock"),
                ("configure", "Enter configuration mode"),
                ("copy", "Copy configuration or image data"),
                ("debug", "Debugging functions (see also 'undebug')"),
                ("delete", "Delete a file"),
                ("dir", "List files on a filesystem"),
                ("format", "Format a filesystem"),
                ("fsck", "Filesystem check"),
                ("mkdir", "Create new directory"),
                ("more", "Display the contents of a file"),
                ("no", "Negate a command or set its defaults"),
                ("pwd", "Display current directory"),
                ("reload", "Halt and perform a cold restart"),
                ("rename", "Rename a file"),
                ("rmdir", "Remove existing directory"),
                ("send", "Send a message to other tty lines"),
                ("setup", "Run the SETUP command facility"),
                ("test", "Test subsystems, memory, and interfaces"),
                ("undebug", "Disable debugging functions (see also 'debug')"),
                ("vlan", "Configure VLAN parameters"),
                (
                    "write",
                    "Write running configuration to memory, network, or terminal",
                ),
            ]
        )

    cmds.sort(key=lambda x: x[0])

    output = "Exec commands:\n"
    for c, desc in cmds:
        output += f"  {c:<15} {desc}\n"

    return output, {}, {"source": "handler", "cached": False}


# New Handlers


def handle_cisco_ping(cmd, context):
    parts = cmd.split()
    target = parts[1] if len(parts) > 1 else "target"
    output = f"Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to {target}, timeout is 2 seconds:\n!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/2/4 ms\n"
    return output, {}, {"source": "handler", "cached": False}


def handle_cisco_traceroute(cmd, context):
    parts = cmd.split()
    target = parts[1] if len(parts) > 1 else "target"
    output = f"""Type escape sequence to abort.
Tracing the route to {target}

  1 192.168.1.1 4 msec 0 msec 4 msec
  2 10.0.0.1 8 msec 4 msec 8 msec
  3 {target} 8 msec 8 msec 8 msec
"""
    return output, {}, {"source": "handler", "cached": False}


def handle_cisco_clear(cmd, context):
    return "\\033[2J\\033[H", {}, {"source": "handler", "cached": False}


def handle_cisco_disable(cmd, context):
    updates = {"env": {"privilege_level": 1}}
    return "", updates, {"source": "handler", "cached": False}


def handle_cisco_ssh(cmd, context):
    return (
        "% SSH connections not allowed from this terminal\n",
        {},
        {"source": "handler", "cached": False},
    )


def handle_cisco_telnet(cmd, context):
    return (
        "% Telnet connections not allowed from this terminal\n",
        {},
        {"source": "handler", "cached": False},
    )


def handle_cisco_connect(cmd, context):
    return "% Connection failed\n", {}, {"source": "handler", "cached": False}


def handle_cisco_disconnect(cmd, context):
    return "% No active connection\n", {}, {"source": "handler", "cached": False}


def handle_cisco_resume(cmd, context):
    return "% No active connection\n", {}, {"source": "handler", "cached": False}


def handle_cisco_lock(cmd, context):
    return (
        "Password: \n% Password locked\n",
        {},
        {"source": "handler", "cached": False},
    )


def handle_cisco_login(cmd, context):
    return "% Logged in\n", {}, {"source": "handler", "cached": False}


def handle_cisco_logout(cmd, context):
    return "disconnect", {}, {"source": "handler", "cached": False}


def handle_cisco_systat(cmd, context):
    output = """
    Line     User      Host(s)                  Idle       Location
*  0 con 0             idle                 00:00:00       
"""
    return output, {}, {"source": "handler", "cached": False}


def handle_cisco_where(cmd, context):
    return "% No active connections\n", {}, {"source": "handler", "cached": False}


def handle_cisco_terminal(cmd, context):
    return "", {}, {"source": "handler", "cached": False}


def handle_cisco_invalid(cmd, context):
    return (
        "% Invalid input detected at '^' marker.\n",
        {},
        {"source": "handler", "cached": False},
    )


def handle_cisco_hostname(cmd, context):
    parts = cmd.split()
    if len(parts) < 2:
        return "% Incomplete command.\n", {}, {"source": "handler", "cached": False}

    new_hostname = parts[1]

    # Validation (basic alphanumeric)
    if not new_hostname.replace("-", "").replace("_", "").isalnum():
        return (
            "% Invalid input detected at '^' marker.\n",
            {},
            {"source": "handler", "cached": False},
        )

    updates = {"env": {}}
    updates["env"]["hostname_override"] = new_hostname

    # Update running config if it exists
    current_config = context.get("env", {}).get("cisco_running_config")
    if current_config:
        import re

        # Regex to replace 'hostname <whatever>' with 'hostname <new>'
        # Handles case where it might be at start of line or indented
        new_config = re.sub(
            r"(^|\n)\s*hostname\s+\S+", f"\\1hostname {new_hostname}", current_config
        )
        updates["env"]["cisco_running_config"] = new_config

    return "", updates, {"source": "handler", "cached": False}


def handle_cisco_shell(cmd, context):
    """
    Simulates a 'jailbreak' into a system shell.
    Switches the session's effective handler type to Unix via env flag.
    """
    updates = {"env": {"cisco_jailbreak": True}}
    # Realistic-ish output for a router dropping to shell
    return (
        "\nEntering sensitive shell mode... Type 'exit' to return.\n# ",
        updates,
        {"source": "handler", "cached": False},
    )


def handle_cisco_system(cmd, context):
    return handle_cisco_shell(cmd, context)


def handle_cisco_linuxshell(cmd, context):
    return handle_cisco_shell(cmd, context)
