
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.command_handler import CommandHandler

class TestPayload(unittest.TestCase):
    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_db = MagicMock()
        # Mock DB returns None for cache (miss)
        self.mock_db.get_cached_response.return_value = None
        self.mock_db.get_fs_node.return_value = None
        
        self.handler = CommandHandler(self.mock_llm, self.mock_db)

    def test_complex_payload(self):
        # exact payload from user (escaped for python string)
        cmd = 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH\nuname=$(uname -s -v -n -m 2>/dev/null)\narch=$(uname -m 2>/dev/null)\nuptime=$(cat /proc/uptime 2>/dev/null | cut -d. -f1)\ncpus=$( (nproc || grep -c "^processor" /proc/cpuinfo) 2>/dev/null | head -1)\ncpu_model=$( (grep -m1 -E "model name|Hardware" /proc/cpuinfo | cut -d: -f2- | sed \'s/^ *//;s/ *$//\' ; lscpu 2>/dev/null | awk -F: \'/Model name/ {gsub(/^ +| +$/,"",$2); print $2; exit}\' ; dmidecode -s processor-version 2>/dev/null | head -n1 ; uname -p 2>/dev/null) | awk \'NF{print; exit}\' )\ngpu_info=$( (lspci 2>/dev/null | grep -i vga; lspci 2>/dev/null | grep -i nvidia) 2>/dev/null | head -n50)\ncat_help=$( (cat --help 2>&1 | tr \'\\n\' \' \') || cat --help 2>&1)\nls_help=$( (ls --help 2>&1 | tr \'\\n\' \' \') || ls --help 2>&1)\nlast_output=$(last 2>/dev/null | head -n 10)\necho "UNAME:$uname"\necho "ARCH:$arch"\necho "UPTIME:$uptime"\necho "CPUS:$cpus"\necho "CPU_MODEL:$cpu_model"\necho "GPU:$gpu_info"\necho "CAT_HELP:$cat_help"\necho "LS_HELP:$ls_help"\necho "LAST:$last_output"'
        
        context = {
            'user': 'royans', 
            'cwd': '/home/royans', 
            'session_id': 'test_sess', 
            'client_ip': '1.2.3.4'
        }

        # Mock LLM response containing 'alabaster' to verify replacement
        # And mimicking the structure of the expected output
        llm_output = """UNAME:Linux web 4.19.0 #1 SMP Debian 4.19.67-2+deb10u2 (2019-11-11) x86_64
ARCH:x86_64
UPTIME:12345
CPUS:2
CPU_MODEL:Intel(R) Xeon(R) CPU
GPU:VGA compatible controller: NVIDIA Corporation
CAT_HELP:Usage: cat [OPTION]... [FILE]...
LS_HELP:Usage: ls [OPTION]... [FILE]...
LAST:root     pts/0        192.168.1.55     Tue Oct 27 10:00   still logged in
alabaster pts/1        192.168.1.55     Tue Oct 27 09:00 - 09:30  (00:30)
"""
        self.mock_llm.generate_response.return_value = llm_output

        # Execute
        print("--- Executing Payload ---")
        response, _, meta = self.handler.process_command(cmd, context)
        
        print("\n--- Response ---")
        print(response)
        print("--- Metadata ---")
        print(meta)

        # Assertions
        # 1. Verify "alabaster" is NOT present (handler uses context user or hardcoded root)
        # Note: simulated logic uses context['user'] so "royans" should be there.
        self.assertIn("royans", response)
        self.assertNotIn("alabaster", response)
        
        # 2. Verify it was intercepted (source=simulated)
        self.assertEqual(meta['source'], 'simulated')
        
        # 3. Verify Realistic Data
        self.assertIn("H100 PCIe", response)
        self.assertIn("Usage: cat", response)
        
        # 4. Verify LLM was NOT called
        self.mock_llm.generate_response.assert_not_called()
        # args check removed since not called

if __name__ == '__main__':
    unittest.main()
