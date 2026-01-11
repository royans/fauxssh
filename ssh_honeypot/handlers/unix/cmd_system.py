import datetime
import random
from ssh_honeypot.handlers.base import BaseHandler

try:
    from ssh_honeypot.core.logging_setup import log
except ImportError:
    from ssh_honeypot.core.logging_setup import log

try:
    from ssh_honeypot.core.config import config
except ImportError:
    from ssh_honeypot.core.config import config

import time

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

        self.STATIC_FILES = {}
        
        self.DYNAMIC_FILES = {
            '/proc/uptime': self.generate_proc_uptime,
            '/proc/cpuinfo': self.generate_proc_cpuinfo,
            '/proc/version': self.generate_proc_version
        }

    def _get_uptime_seconds(self):
        # Base uptime: ~14 days (1209600s) + jitter
        # We use a deterministic base + time of day to simulated a continuously running server
        # without effective reboots unless we want to reset.
        # But for 'uptime' command consistency, we just need it to be consistent within a short window?
        # Simpler: Just make it look like it's been up 14 days + however many hours/seconds since start of day
        
        base_days = 14
        base_seconds = 1209600
        
        now = datetime.datetime.now()
        # Add seconds since midnight + jitter
        seconds_today = (now - now.replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds()
        
        total_uptime = base_seconds + seconds_today
        idle_time = total_uptime * 95 # Mostly idle (192 cores means lots of idle time sum)
        
        return total_uptime, idle_time

    def generate_proc_uptime(self):
        up, idle = self._get_uptime_seconds()
        return f"{up:.2f} {idle:.2f}\n"

    def generate_proc_version(self):
        # Linux version 5.10.0-21-cloud-amd64 (debian-kernel@lists.debian.org) (gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.162-1 (2023-01-21)
        return "Linux version 5.10.0-21-cloud-amd64 (debian-kernel@lists.debian.org) (gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.162-1 (2023-01-21)\n"

    def generate_proc_cpuinfo(self):
        # Generate 192 cores (loop) to match nproc
        # AMD EPYC 9654
        out = []
        for i in range(192):
             out.append(f"processor\t: {i}")
             out.append("vendor_id\t: AuthenticAMD")
             out.append("cpu family\t: 25")
             out.append("model\t\t: 17")
             out.append("model name\t: AMD EPYC 9654 96-Core Processor")
             out.append("stepping\t: 1")
             out.append("microcode\t: 0xa10113e")
             out.append("cpu MHz\t\t: 2400.000")
             out.append("cache size\t: 1024 KB")
             out.append("physical id\t: 0")
             out.append("siblings\t: 192")
             out.append(f"core id\t\t: {i % 96}")
             out.append(f"cpu cores\t: 96")
             out.append("apicid\t\t: 0")
             out.append("initial apicid\t: 0")
             out.append("fpu\t\t: yes")
             out.append("fpu_exception\t: yes")
             out.append("cpuid level\t: 16")
             out.append("wp\t\t: yes")
             out.append("flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf pni pclmulqdq monitor ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 invpcid_single hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a avx512f avx512dq rdseed adx smap avx512ifma clflushopt clwb avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local avx512_bf16 clzero irperf xsaveerptr rdpru wbnoinvd amd_ppin arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avx512vbmi umip pku ospke avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq la57 rdpid overflow_recov succor smca fsrm")
             out.append("bugs\t\t: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass retbleed smp_rsb_alternate_prediction")
             out.append("bogomips\t: 4799.86")
             out.append("TLB size\t: 3584 4K pages")
             out.append("clflush size\t: 64")
             out.append("cache_alignment\t: 64")
             out.append("address sizes\t: 52 bits physical, 57 bits virtual")
             out.append("power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]")
             out.append("")
        return "\n".join(out)

    def get_dynamic_file(self, path):
        if path in self.DYNAMIC_FILES:
            return self.DYNAMIC_FILES[path]()
        return None

    def handle_lscpu(self, cmd, context):
        # Output matching the cpuinfo above
        out = """Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
Address sizes:                   52 bits physical, 57 bits virtual
CPU(s):                          192
On-line CPU(s) list:             0-191
Thread(s) per core:              2
Core(s) per socket:              96
Socket(s):                       1
NUMA node(s):                    1
Vendor ID:                       AuthenticAMD
CPU family:                      25
Model:                           17
Model name:                      AMD EPYC 9654 96-Core Processor
Stepping:                        1
Frequency boost:                 enabled
CPU MHz:                         2400.000
CPU max MHz:                     3700.0000
CPU min MHz:                     1500.0000
BogoMIPS:                        4799.86
Virtualization:                  AMD-V
L1d cache:                       3 MiB
L1i cache:                       3 MiB
L2 cache:                        96 MiB
L3 cache:                        384 MiB
NUMA node0 CPU(s):               0-191
Vulnerability Itlb multihit:     Not affected
Vulnerability L1tf:              Not affected
Vulnerability Mds:               Not affected
Vulnerability Meltdown:          Not affected
Vulnerability Mmio stale data:   Not affected
Vulnerability Retbleed:          Not affected
Vulnerability Spec store bypass: Mitigation; Speculative Store Bypass disabled via prctl and seccomp
Vulnerability Spectre v1:        Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:        Mitigation; Retpolines, IBPB: conditional, IBRS_FW, STIBP: always-on, RSB filling, PBRSB-eIBRS: Not affected
Vulnerability Srbds:             Not affected
Vulnerability Tsx async abort:   Not affected
Flags:                           fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf pni pclmulqdq monitor ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 invpcid_single hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a avx512f avx512dq rdseed adx smap avx512ifma clflushopt clwb avx512cd sha_ni avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local avx512_bf16 clzero irperf xsaveerptr rdpru wbnoinvd amd_ppin arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avx512vbmi umip pku ospke avx512_vbmi2 gfni vaes vpclmulqdq avx512_vnni avx512_bitalg avx512_vpopcntdq la57 rdpid overflow_recov succor smca fsrm
"""
        return out, {}

    def handle_lspci(self, cmd, context):
        # Realistic NVIDIA H100 output + standard system
        out = """00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 01)
00:02.0 VGA compatible controller: Cirrus Logic GD 5446
00:03.0 VGA compatible controller: NVIDIA Corporation H100 PCIe [Hopper] (rev a1)
00:04.0 Ethernet controller: Red Hat, Inc. Virtio network device
00:05.0 Communication controller: Red Hat, Inc. Virtio console
00:06.0 SCSI storage controller: Red Hat, Inc. Virtio block device
00:07.0 Unclassified device [00ff]: Red Hat, Inc. Virtio memory balloon
10:00.0 Non-Volatile memory controller: Amazon.com, Inc. NVMe SSD Controller (rev 01)
"""
        return out, {}

    def handle_dmidecode(self, cmd, context):
         # Usually requires root (except for help/version or some flags? no usually root)
         if context.get('user') != 'root':
             return "Permission denied\n", {}
             
         if '-s processor-version' in cmd or '--string processor-version' in cmd:
            try:
                 proc_ver = config.get('persona', 'processor_version') or "Intel(R) Xeon(R) Platinum 8480+"
            except:
                 proc_ver = "Intel(R) Xeon(R) Platinum 8480+"
            return f"{proc_ver}\n", {}

         out = """# dmidecode 3.3
Getting SMBIOS data from sysfs.
SMBIOS 2.8 present.

Handle 0x0100, DMI type 1, 27 bytes
System Information
	Manufacturer: Google
	Product Name: Google Compute Engine
	Version: Not Specified
	Serial Number: GoogleCloud-12345
	UUID: 12345678-1234-1234-1234-1234567890AB
	Wake-up Type: Power Switch
	SKU Number: Not Specified
	Family: Not Specified

Handle 0x2000, DMI type 32, 11 bytes
System Boot Information
	Status: No errors detected
"""
         return out, {}
    
    def handle_last(self, cmd, context):
        # Realistic last output
        user = context.get('user', 'root')
        ip = context.get('client_ip', '1.2.3.4')
        now = datetime.datetime.now()
        cur_str = now.strftime("%a %b %d %H:%M")
        
        # Fake history
        out = []
        out.append(f"{user:<8} pts/0        {ip:<16} {cur_str}   still logged in")
        # Add some previous fake logins
        out.append(f"root     pts/1        192.168.1.100    Tue Oct 10 12:00 - 13:00  (01:00)")
        out.append(f"admin    pts/0        10.0.0.50        Mon Oct  9 09:30 - 10:15  (00:45)")
        out.append(f"reboot   system boot  5.10.0-21-cloud  Mon Oct  9 09:00   still running")
        
        return "\n".join(out) + "\n", {}
    
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
        processor = "x86_64"
        hardware_platform = "x86_64"
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
        now_dt = datetime.datetime.now()
        now_str = now_dt.strftime("%H:%M:%S")
        
        # Calculate human friendly uptime from our consistent source
        total_seconds, _ = self._get_uptime_seconds()
        
        days = int(total_seconds // 86400)
        rem = total_seconds % 86400
        hours = int(rem // 3600)
        minutes = int((rem % 3600) // 60)
        
        # Randomize load slightly to look alive
        l1 = round(random.uniform(0.01, 0.20), 2)
        l5 = round(random.uniform(0.01, 0.15), 2)
        l15 = round(random.uniform(0.00, 0.10), 2)
        
        # Format: 17:05:01 up 14 days,  7:22,  2 users,  load average: 0.12, 0.08, 0.02
        return f" {now_str} up {days} days, {hours}:{minutes:02d},  1 user,  load average: {l1:.2f}, {l5:.2f}, {l15:.2f}\n", {}

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
            log.error(f"[ERROR] handle_df failed: {e}")
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
