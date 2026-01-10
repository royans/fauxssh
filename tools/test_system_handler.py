
import sys
import os

# Path hack
sys.path.append(os.getcwd())

from ssh_honeypot.handlers.unix.cmd_system import SystemHandler

class MockDB:
    pass

class MockLLM:
    pass

def test():
    handler = SystemHandler(MockDB(), MockLLM())
    
    # 1. Check Dynamic /proc/uptime
    u1 = handler.get_dynamic_file('/proc/uptime')
    print(f"[/proc/uptime] {u1.strip()}")
    
    # 2. Check uptime command
    u2, _ = handler.handle_uptime("uptime", {})
    print(f"[uptime cmd]   {u2.strip()}")
    
    # 3. Check consistency (rough check)
    sec1 = float(u1.split()[0])
    if "days" in u2:
        # crude parse "14 days, 7:22"
        # Not strictly necessary to match exactly here, just seeing they work
        pass
        
    # 4. Check Static removal
    issue = handler.get_static_file('/etc/issue')
    print(f"[/etc/issue] (Should be None): {issue}")

if __name__ == "__main__":
    test()
