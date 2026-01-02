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
    """Handles 'ifconfig' command."""
    return network_persona.get_ifconfig_output()

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

def handle_netstat(args, client_ip):
    """
    Handles 'netstat' command.
    Shows the attacker's connection to port 22.
    """
    import random
    
    # Check flags roughly (simplistic)
    # Default to showing listening and established
    
    attacker_port = random.randint(30000, 60000) # Fake ephemeral port
    
    header = "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State"
    
    rows = [
        f"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN",
        f"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN",
        f"tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN", 
        f"tcp        0      0 {network_persona.ip_eth0}:22        {client_ip}:{attacker_port}       ESTABLISHED",
        f"udp        0      0 127.0.0.53:53           0.0.0.0:*                          ",
        f"udp        0      0 {network_persona.ip_eth0}:68        0.0.0.0:*                          "
    ]
    
    return header + "\n" + "\n".join(rows)

def handle_ss(args, client_ip):
    """
    Handles 'ss' command.
    Modern replacement for netstat.
    """
    import random
    attacker_port = random.randint(30000, 60000)
    
    header = "Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port   Process"
    
    rows = [
        f"tcp    LISTEN  0       128      0.0.0.0:22           0.0.0.0:*                      ",
        f"tcp    LISTEN  0       128      0.0.0.0:80           0.0.0.0:*                      ",
        f"tcp    ESTAB   0       0        {network_persona.ip_eth0}:22        {client_ip}:{attacker_port}                     "
    ]
    
    return header + "\n" + "\n".join(rows)
