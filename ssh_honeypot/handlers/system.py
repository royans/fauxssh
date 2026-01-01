import datetime
import random
from .base import BaseHandler

try:
    from ..config_manager import config
except ImportError:
    from config_manager import config

class SystemHandler(BaseHandler):
    def __init__(self, db, llm):
        super().__init__(db, llm)
        self.FILESYSTEMS = [
            {"fs": "/dev/sda1", "mount": "/", "size": "40G", "used": "8.2G", "avail": "30G", "use": "22%", "type": "ext4"},
            {"fs": "udev", "mount": "/dev", "size": "3.9G", "used": "0", "avail": "3.9G", "use": "0%", "type": "devtmpfs"},
            {"fs": "tmpfs", "mount": "/run", "size": "796M", "used": "1.2M", "avail": "795M", "use": "1%", "type": "tmpfs"},
            {"fs": "/dev/sda15", "mount": "/boot/efi", "size": "124M", "used": "6.1M", "avail": "118M", "use": "5%", "type": "vfat"}
        ]
        
        # Static File Registry for Persona Consistency (Dynamic from Config)
        k_rel = config.get('persona', 'kernel_release') or "5.10.0-21-cloud-amd64"
        k_ver = config.get('persona', 'kernel_version') or "#1 SMP Debian 5.10.162-1 (2023-01-21)"
        d_ver = config.get('persona', 'distro_version_id') or "11"
        d_pretty = config.get('persona', 'distro_pretty_name') or "Debian GNU/Linux 11 (bullseye)"
        d_version_text = config.get('persona', 'distro_version') or "11 (bullseye)"

        self.STATIC_FILES = {
            '/etc/issue': f"Debian GNU/Linux {d_ver} \\n \\l\n\n",
            '/etc/debian_version': f"{d_ver}.7\n",
            '/proc/version': f"Linux version {k_rel} (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110) {k_ver}\n",
            '/etc/os-release': f"""PRETTY_NAME="{d_pretty}"
NAME="Debian GNU/Linux"
VERSION_ID="{d_ver}"
VERSION="{d_version_text}"
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
"""
        }
        
        self.DYNAMIC_FILES = {
            '/proc/uptime': self.generate_proc_uptime
        }

    def generate_proc_uptime(self):
        # Match handle_uptime's "14 days, 3:12" roughly.
        # 14 days = 1209600s
        # 3h 12m = 11520s
        # Total ~ 1.22 million seconds
        # We add some randomness to simulated "now" vs boot
        base_uptime = 1221120.0 
        idle_time = base_uptime * 0.98 # Mostly idle
        
        # Add small jitter based on time of day (minutes)
        now_min = datetime.datetime.now().minute
        jitter = now_min * 60
        
        up = base_uptime + jitter
        idle = idle_time + jitter
        
        return f"{up:.2f} {idle:.2f}\n"

    def get_dynamic_file(self, path):
        if path in self.DYNAMIC_FILES:
            return self.DYNAMIC_FILES[path]()
        return None

    def handle_hostname(self, cmd, context):
        h = config.get('server', 'hostname') or 'npc-main-server-01'
        
        # Parse basic args
        parts = cmd.split()
        if len(parts) > 1:
             if parts[1].startswith('-'):
                 # -f, -i, etc. Just ignore or return standard
                 if 'i' in parts[1]:
                     return f"{context.get('honeypot_ip', '127.0.0.1')}\n", {}
             else:
                 # Attempt to set hostname -> Permission denied (unless root)
                 if context.get('user') != 'root':
                     return f"hostname: you must be root to change the host name\n", {}
                 else:
                     # Fake set success (no persistence)
                     return "", {}
                     
        return f"{h}\n", {}

    def handle_uname(self, cmd, context):
        # Default: Linux
        kernel_name = "Linux"
        nodename = context.get('hostname') or "npc-main-server-01"
        try:
            nodename = config.get('server', 'hostname') or nodename
        except: pass
        
        kernel_release = "5.10.0-21-cloud-amd64"
        kernel_version = "#1 SMP Debian 5.10.162-1 (2023-01-21)"
        machine = "x86_64"
        processor = "unknown"
        hardware_platform = "unknown"
        os_name = "GNU/Linux"
        
        parts = cmd.split()
        flags = set()
        for p in parts[1:]:
            if p.startswith('-'):
                for char in p[1:]:
                    flags.add(char)
        
        # If no flags, default is -s (Kernel name)
        if not flags:
            return f"{kernel_name}\n", {}
        
        if 'a' in flags or 'all' in flags: # -a is --all
             return f"{kernel_name} {nodename} {kernel_release} {kernel_version} {machine} {os_name}\n", {}
        
        out = []
        if 's' in flags: out.append(kernel_name)
        if 'n' in flags: out.append(nodename)
        if 'r' in flags: out.append(kernel_release)
        if 'v' in flags: out.append(kernel_version)
        if 'm' in flags: out.append(machine)
        if 'p' in flags: out.append(processor)
        if 'i' in flags: out.append(hardware_platform)
        if 'o' in flags: out.append(os_name)
        
        if not out: # Default is -s
            return f"{kernel_name}\n", {}
            
        return " ".join(out) + "\n", {}

    def handle_uptime(self, cmd, context):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Randomize load slightly to look alive
        l1 = round(random.uniform(0.01, 0.20), 2)
        l5 = round(random.uniform(0.01, 0.15), 2)
        l15 = round(random.uniform(0.00, 0.10), 2)
        
        return f" {now} up 14 days,  3:12,  2 users,  load average: {l1:.2f}, {l5:.2f}, {l15:.2f}\n", {}

    def handle_ifconfig(self, cmd, context):
        hp_ip = context.get('honeypot_ip', '192.168.1.55')
        out = f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet {hp_ip}  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::20c:29ff:fe1a:2b3c  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:1a:2b:3c  txqueuelen 1000  (Ethernet)
        RX packets 23412  bytes 14502312 (13.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19821  bytes 3421901 (3.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4  bytes 240 (240.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4  bytes 240 (240.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
"""
        return out, {}

    def _get_ram_info(self):
        total = 8124220 # 8GB
        used = int(total * random.uniform(0.15, 0.40))
        free = int(total * random.uniform(0.10, 0.30))
        buff = total - used - free
        return total, used, free, buff

    def handle_free(self, cmd, context):
        total, used, free, buff = self._get_ram_info()
        return f"""              total        used        free      shared  buff/cache   available
Mem:        {total}     {used}     {free}       14200     {buff}     {int(free*1.5)}
Swap:       2097148           0     2097148
""", {}

    def handle_df(self, cmd, context):
        try:
            out = ["Filesystem      Size  Used Avail Use% Mounted on"]
            for disk in self.FILESYSTEMS:
                out.append(f"{disk['fs']:<12} {disk['size']:>5} {disk['used']:>5} {disk['avail']:>5} {disk['use']:>4} {disk['mount']}")
            return "\n".join(out) + "\n", {}
        except Exception as e:
            print(f"[ERROR] handle_df failed: {e}")
            return f"Internal Error: {e}\n", {}
        
    def handle_mount(self, cmd, context):
        out = []
        for disk in self.FILESYSTEMS:
            out.append(f"{disk['fs']} on {disk['mount']} type {disk['type']} (rw,relatime)")
        out.append("proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)")
        out.append("sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)")
        return "\n".join(out) + "\n", {}

    def handle_netstat(self, cmd, context):
        client_ip = context.get('client_ip', '10.0.0.2')
        hp_ip = context.get('honeypot_ip', '192.168.1.55')
        out = f"""Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0    232 {hp_ip}:22            {client_ip}:54321         ESTABLISHED
udp        0      0 0.0.0.0:68              0.0.0.0:*                          
"""
        return out, {}

    def handle_nproc(self, cmd, context):
        # Consistent with AMD EPYC 9654 (96 cores, 192 threads)
        # /proc/cpuinfo says "siblings : 192"
        return "192\n", {}


    def get_static_file(self, path):
        """Returns static content for specific system files if defined."""
        return self.STATIC_FILES.get(path)
