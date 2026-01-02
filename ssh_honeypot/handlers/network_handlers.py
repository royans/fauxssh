import sys
import os
import time

# Add parent dir to path to find network.py if needed, 
# though relative imports should work if run as module.
try:
    from ..network import network_persona
except (ImportError, ValueError):
    try:
        from ssh_honeypot.network import network_persona
    except ImportError:
        # Fallback if running from inside ssh_honeypot/handlers directly or similar
        # Add ssh_honeypot root to path roughly
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))
        from network import network_persona

def handle_ip(args):
    """
    Handles 'ip' command. 
    Supports: 
      ip addr, ip a, ip addr show
      ip route, ip r
      ip link, ip l
    """
    if not args:
        # 'ip' without args usually prints help, but for honeypot just return addr
        return network_persona.get_ip_addr_output()
        
    cmd = args[0]
    
    if cmd in ['addr', 'a', 'address']:
        return network_persona.get_ip_addr_output()
    elif cmd in ['route', 'r']:
        return network_persona.get_ip_route_output()
    elif cmd in ['link', 'l']:
        # Simplified: just return addr output for link too, or strip inet lines
        # For realism, link output is similar but without IP addresses
        full = network_persona.get_ip_addr_output()
        lines = []
        for line in full.split('\n'):
            if "inet" not in line:
                lines.append(line)
        return '\n'.join(lines)
        
    return network_persona.get_ip_addr_output() # Default fallback

def handle_ifconfig(args):
    """
    Handles 'ifconfig' command.
    Supports: -a, interface name (eth0, lo)
    """
    # Check for specific interface or -a
    show_all = False
    target_iface = None
    
    for arg in args:
        if arg == '-a':
            show_all = True
        elif not arg.startswith('-'):
            target_iface = arg
            
    full_output = network_persona.get_ifconfig_output()
    
    if target_iface:
        # Simple extraction logic
        # ifconfig output format has interface at start of block
        blocks = full_output.split('\n\n')
        for block in blocks:
            if block.startswith(target_iface + ":"):
                return block + '\n'
        return f"{target_iface}: error fetching interface information: Device not found\n"
        
    return full_output

def handle_netstat(args, client_ip="192.168.1.100"):
    """
    Handles 'netstat' command.
    Supports: -r (route), -n (numeric), -t (tcp), -u (udp), -l (listening), -a (all)
    """
    # Parse Flags
    flags = set()
    for arg in args:
        if arg.startswith('-'):
            for char in arg[1:]:
                flags.add(char)
                
    # Logic
    if 'r' in flags:
        # Route Table
        return f"""Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         {network_persona.gateway}     0.0.0.0         UG        0 0          0 eth0
{network_persona.ip_eth0.rsplit('.', 1)[0] + '.0'}     0.0.0.0         255.255.255.0   U         0 0          0 eth0
"""

    # Default: Active Internet Connections (Servers and Established)
    attacker_port = 54321 # Static or random?
    
    # TCP Listening Ports
    tcp_ports = [
        ("0.0.0.0:22", "0.0.0.0:*", "LISTEN"),
        ("0.0.0.0:80", "0.0.0.0:*", "LISTEN"),
        ("127.0.0.1:3306", "0.0.0.0:*", "LISTEN"), # Internal MySQL
        (f"{network_persona.ip_eth0}:22", f"{client_ip}:{attacker_port}", "ESTABLISHED"), # Established SSH
    ]
    
    udp_ports = [
        ("0.0.0.0:68", "0.0.0.0:*", "") # DHCP
    ]
    
    output = []
    output.append("Active Internet connections (servers and established)")
    output.append("Proto Recv-Q Send-Q Local Address           Foreign Address         State")
    
    # Filter Logic
    show_listening = 'l' in flags or 'a' in flags
    show_established = 'l' not in flags or 'a' in flags 
    
    # TCP
    if 't' in flags or not ('u' in flags or 'x' in flags): # Default includes TCP
        for local, foreign, state in tcp_ports:
            if state == "LISTEN":
                if show_listening:
                    output.append(f"tcp        0      0 {local:<23} {foreign:<23} {state}")
            elif state == "ESTABLISHED":
                if show_established:
                    output.append(f"tcp        0     64 {local:<23} {foreign:<23} {state}")

    # UDP
    if 'u' in flags or not ('t' in flags or 'x' in flags):
        for local, foreign, state in udp_ports:
             if show_listening:
                 output.append(f"udp        0      0 {local:<23} {foreign:<23} {state}")

    return '\n'.join(output) + '\n'

def handle_ss(args, client_ip="192.168.1.100"):
    """
    Handles 'ss' command.
    """
    attacker_port = 54321
    header = "Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port   Process"
    
    rows = [
        f"tcp    LISTEN  0       128      0.0.0.0:22           0.0.0.0:*                      ",
        f"tcp    LISTEN  0       128      0.0.0.0:80           0.0.0.0:*                      ",
        f"tcp    ESTAB   0       0        {network_persona.ip_eth0}:22        {client_ip}:{attacker_port}                     "
    ]
    
    return header + "\n" + "\n".join(rows) + "\n"

def handle_ping(args):
    """
    Handles 'ping' command.
    Simulates network latency and packet loss.
    Supports: -c count
    """
    import time
    import random
    
    # Defaults
    count = 4
    target = "unknown"
    
    # Parse args (Naive)
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
            
        if arg == '-c':
            if i + 1 < len(args):
                try:
                    count = int(args[i+1])
                    if count > 20: count = 20 # Cap for safety
                    skip = True
                except:
                    pass
            continue
            
        if not arg.startswith('-'):
            target = arg
            
    if target == "unknown":
        return "ping: usage error: Destination address required"
        
    # Determine IP and Latency
    resolved_ip = "1.1.1.1" # Default fallback
    latency_base = 0.020 # 20ms
    latency_jitter = 0.005 # 5ms
    
    if target in ["localhost", "127.0.0.1", network_persona.hostname, "0"]:
        resolved_ip = "127.0.0.1"
        latency_base = 0.0001
        latency_jitter = 0.0001
    elif target in [network_persona.ip_eth0, "172.16.20.5"]:
        resolved_ip = network_persona.ip_eth0
        latency_base = 0.0001
        latency_jitter = 0.0001
    elif target.replace('.','').isdigit():
        # Looks like IP
        resolved_ip = target
        latency_base = random.uniform(0.010, 0.150)
    else:
        # Domain name - Fake resolution
        # Hash target to get semi-consistent IP
        h = sum(ord(c) for c in target)
        resolved_ip = f"142.250.{h%255}.{h%254}"
        latency_base = random.uniform(0.020, 0.100)
        
    output = []
    output.append(f"PING {target} ({resolved_ip}) 56(84) bytes of data.")
    
    total_time = 0
    received = 0
    
    for seq in range(1, count + 1):
        # Simulate Delay
        delay = latency_base + random.uniform(-latency_jitter, latency_jitter)
        if delay < 0: delay = 0.0001
        
        # Sleep to simulate network time (blocks the thread, creating feel of latency)
        # Note: In production this blocks the handler thread. 
        # Since we are single-threaded per session (mostly), this pauses the user's terminal.
        # This is DESIRED behavior for ping.
        time.sleep(delay)
        total_time += delay
        
        delay_ms = delay * 1000
        output.append(f"64 bytes from {resolved_ip}: icmp_seq={seq} ttl=64 time={delay_ms:.2f} ms")
        received += 1
        
    # Stats
    output.append(f"\n--- {target} ping statistics ---")
    loss = 0
    output.append(f"{count} packets transmitted, {received} received, {loss}% packet loss, time {int(total_time*1000)}ms")
    min_t = (latency_base - latency_jitter) * 1000
    max_t = (latency_base + latency_jitter) * 1000
    avg_t = latency_base * 1000
    output.append(f"rtt min/avg/max/mdev = {min_t:.3f}/{avg_t:.3f}/{max_t:.3f}/{latency_jitter*1000:.3f} ms")
    
    return "\n".join(output)
