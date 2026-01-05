
import gzip
import os
import random

def generate():
    # 1. wallet.dat (random binary junk ~4KB)
    wallet_path = "personas/Debian12_GPU_8GB/fs/home/USER/wallet.dat"
    with open(wallet_path, 'wb') as f:
        # Header that looks kinda like BerkeleyDB? Or just random.
        # Magic bytes for BDB: 0x00 0x05 0x31 0x62
        f.write(b'\x00\x05\x31\x62') 
        f.write(os.urandom(4096))
    print(f"Generated {wallet_path}")

    # 2. access_log.old.gz
    log_path = "personas/Debian12_GPU_8GB/fs/home/USER/access_log.old.gz"
    # Generate some fake log content
    content = ""
    for i in range(100):
        ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        content += f"{ip} - - [10/Oct/2021:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326\n"
    
    with gzip.open(log_path, 'wt') as f:
        f.write(content)
    print(f"Generated {log_path}")

if __name__ == "__main__":
    generate()
