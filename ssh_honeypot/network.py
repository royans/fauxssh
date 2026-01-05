from .config_manager import config
import random

class NetworkPersona:
    """
    Maintains the consistent network state for the honeypot.
    Defines Interfaces, IPs, MACs, and Routing tables.
    """
    def __init__(self):
        # Load from Persona Config
        net_conf = config.get('persona', 'network') or {}
        sys_conf = config.get('persona', 'system') or {}
        
        self.hostname = sys_conf.get('hostname', "h100-AI-cluster-01")
        self.domain = "internal" # Could be part of hostname extraction
        
        # IP Configuration
        interfaces = net_conf.get('interfaces', {})
        self.ip_eth0 = interfaces.get('eth0', "172.16.20.5")
        
        # Simple/Naive Netmask derivation (Class C default)
        self.mask_eth0 = "255.255.255.0"
        self.cidr_suffix = "24"
        self.cidr_eth0 = f"{self.ip_eth0}/{self.cidr_suffix}"
        
        # Broadcast (Naive: assume .255)
        ip_parts = self.ip_eth0.split('.')
        if len(ip_parts) == 4:
            self.bcast_eth0 = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
        else:
            self.bcast_eth0 = "192.168.1.255"

        routes = net_conf.get('routes', {})
        self.gateway = routes.get('default', "172.16.20.1")
        
        # Consistent Random MACs
        # We ideally want these persistent per persona, but random per session is okay for now?
        # Actually, if we restart server, they change. 
        # Ideally we hash the hostname or something to get consistent MACs?
        # For now, keep random but maybe seeded?
        self.mac_eth0 = f"02:00:17:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"
        self.mac_lo = "00:00:00:00:00:00"
        
        # Stats (increment for realism)
        self.rx_bytes = 1024 * 1024 * random.randint(100, 500)
        self.tx_bytes = 1024 * 1024 * random.randint(50, 200)

    def get_ip_addr_output(self):
        """Generates 'ip addr' output"""
        return f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether {self.mac_eth0} brd ff:ff:ff:ff:ff:ff
    inet {self.cidr_eth0} brd {self.bcast_eth0} scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::{self.mac_eth0.replace(':', '')}/64 scope link 
       valid_lft forever preferred_lft forever"""

    def get_ip_route_output(self):
        """Generates 'ip route' output"""
        return f"""default via {self.gateway} dev eth0 
172.16.20.0/24 dev eth0 proto kernel scope link src {self.ip_eth0} 
169.254.0.0/16 dev eth0 scope link metric 1000"""

    def get_ifconfig_output(self):
        """Generates 'ifconfig' output"""
        return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet {self.ip_eth0}  netmask 255.255.255.0  broadcast {self.bcast_eth0}
        inet6 fe80::{self.mac_eth0.replace(':', '')}  prefixlen 64  scopeid 0x20<link>
        ether {self.mac_eth0}  txqueuelen 1000  (Ethernet)
        RX packets 562145  bytes {self.rx_bytes} ({self.rx_bytes / 1024 / 1024:.1f} MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 45120  bytes {self.tx_bytes} ({self.tx_bytes / 1024 / 1024:.1f} MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 120  bytes 8192 (8.0 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 120  bytes 8192 (8.0 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"""

# Global Singleton
network_persona = NetworkPersona()
