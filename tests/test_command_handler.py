import sys
import os
import pytest
import json
from unittest.mock import MagicMock, patch

# Ensure the root directory is in path so we can import ssh_honeypot as a package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.command_handler import CommandHandler


class TestCommandHandler:

    @pytest.fixture
    def handler(self):
        self.mock_llm = MagicMock()
        self.mock_db = MagicMock()
        # Mocking the cache return to None by default so it hits the handler logic
        self.mock_db.get_cached_response.return_value = None
        self.mock_db.list_fs_dir.return_value = []
        self.mock_db.list_user_dir.return_value = []
        self.mock_db.get_user_node.return_value = None
        self.mock_db.get_fs_node.return_value = None
        return CommandHandler(self.mock_llm, self.mock_db)

    def test_is_allowed_whitelist(self, handler):
        # Allowed commands
        assert handler._is_allowed("ls") is True
        assert handler._is_allowed("cd /tmp") is True
        assert handler._is_allowed("./script.sh") is True
        assert handler._is_allowed("/bin/bash") is True
        assert handler._is_allowed("X=1") is True
        
        # Blocked commands
        assert handler._is_allowed("fakedcmd123") is False
        assert handler._is_allowed("shutdown") is False

    def test_extract_json_or_text_simple_json(self, handler):
        raw = '{"output": "hello", "new_cwd": null}'
        j, t = handler._extract_json_or_text(raw)
        assert j == {"output": "hello", "new_cwd": None}
        assert t == ""

    def test_extract_json_or_text_markdown_json(self, handler):
        raw = '```json\n{"output": "test"}\n```'
        j, t = handler._extract_json_or_text(raw)
        assert j == {"output": "test"}

    def test_extract_json_or_text_raw_text(self, handler):
        raw = "Just plain text output"
        j, t = handler._extract_json_or_text(raw)
        assert j is None
        assert t == raw

    def test_handle_cd_silence(self, handler):
        # Setup context
        context = {
            'cwd': '/home/user',
            'history': [],
            'vfs': {}
        }
        
        # Mock LLM response to include a 'new_cwd' but also some output text (which should be suppressed)
        llm_resp = '{"output": "Allocated directory", "new_cwd": "/home/user/newdir", "file_modifications": []}'
        self.mock_llm.generate_response.return_value = llm_resp
        
        # Run handle_cd
        resp, updates = handler.handle_cd("cd newdir", context)
        
        # Assertions
        # The logic in handle_cd forces 'output' to be empty if 'new_cwd' is present
        assert resp == "" 
        assert updates['new_cwd'] == "/home/user/newdir"
        
        # Ensure LLM was called with correct instructions
        args, _ = self.mock_llm.generate_response.call_args
        assert "INSTRUCTION: Execute directory change" in args[0]

    def test_handle_ls_cache_logic(self, handler):
        context = {'cwd': '/root'}
        
        # 1. Test Fallback to LLM if cache empty
        self.mock_db.list_fs_dir.return_value = []
        self.mock_db.list_user_dir.return_value = [] # Default empty
        self.mock_db.get_user_node.return_value = None
        self.mock_db.get_fs_node.return_value = None
        
        self.mock_llm.generate_response.return_value = '{"output": "file.txt", "generated_files": [{"name": "file.txt", "type": "file"}]}'
        
        resp, updates = handler.handle_ls("ls", context)
        assert "file.txt" in resp
        
        # 2. Test Cache Hit
        self.mock_db.list_fs_dir.return_value = [
            {'path': '/root/old_file.txt', 'metadata': json.dumps({'size': 100})}
        ]
        
        resp_cache, _ = handler.handle_ls("ls", context)
        assert "old_file.txt" in resp_cache
        # LLM should NOT be called again if cache hit (technically logic is: check DB -> if files -> return)
        # However, we called it once in step 1.


    def test_handle_ls_user_uploads(self, handler):
        """Verify ls merges global files and user uploads"""
        context = {'cwd': '/home/user', 'client_ip': '1.2.3.4', 'user': 'user'}
        
        # Global Files
        self.mock_db.list_fs_dir.return_value = [
            {'path': '/home/user/global.txt', 'type': 'file', 'metadata': json.dumps({'size': 10, 'permissions': '-rw-r--r--'})},
            {'path': '/home/user/conflict.txt', 'type': 'file', 'metadata': json.dumps({'size': 10, 'owner': 'root'})}
        ]
        
        # User Files (Uploads)
        self.mock_db.list_user_dir.return_value = [
            {'path': '/home/user/uploaded.txt', 'type': 'file', 'metadata': json.dumps({'size': 20, 'permissions': '-rw-r--r--'})},
            # This should override global conflict.txt
            {'path': '/home/user/conflict.txt', 'type': 'file', 'metadata': json.dumps({'size': 999, 'owner': 'user'})} 
        ]
        
        resp, _ = handler.handle_ls("ls -la", context)
        
        assert "global.txt" in resp
        assert "uploaded.txt" in resp
        assert "conflict.txt" in resp
        
        # Verify size 999 is present (from user file), not size 10 (global)
        assert "999" in resp 


    def test_handle_ls_single_file(self, handler):
        """Verify ls works on a specific file path"""
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'user'}
        
        # Mock User File
        self.mock_db.get_user_node.return_value = {
            'path': '/root/secret.txt',
            'type': 'file',
            'metadata': json.dumps({'size': 123, 'permissions': '-rw-------', 'owner': 'user'})
        }
        
        resp, _ = handler.handle_ls("ls -l /root/secret.txt", context)
        assert "secret.txt" in resp
        assert "123" in resp
        # Should not call list logic
        self.mock_db.list_fs_dir.assert_not_called()


    def test_handle_cat_user_upload(self, handler):
        """Verify cat prioritizes user uploads"""
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'user'}
        
        # Mock User File
        self.mock_db.get_user_node.return_value = {
            'path': '/root/secret.txt',
            'type': 'file',
            'content': "SECRET_UPLOAD_CONTENT"
        }
        
        resp, _, _ = handler.handle_cat("cat secret.txt", context)
        assert "SECRET_UPLOAD_CONTENT" in resp
        # Should not go to global FS or LLM
        self.mock_db.get_fs_node.assert_not_called()


    def test_handle_interpreter_bash(self, handler):
        """Verify bash execution simulation with content injection"""
        context = {'cwd': '/root', 'client_ip': '1.2.3.4', 'user': 'user'}
        
        # Mock User File
        self.mock_db.get_user_node.return_value = {
            'path': '/root/script.sh',
            'type': 'file',
            'content': 'echo "Hello Virtual World"'
        }
        
        # Mock LLM Response
        self.mock_llm.generate_response.return_value = '{"output": "Hello Virtual World"}'
        
        resp, _, _ = handler.handle_bash("bash script.sh", context)
        
        assert "Hello Virtual World" in resp
        
        # Check that LLM was called with the script content
        args, _ = self.mock_llm.generate_response.call_args
        prompt = args[0]
        assert 'echo "Hello Virtual World"' in prompt
        assert 'Act as the bash interpreter' in prompt
        
        # Verify Caching Key includes hash
        args_cache, _ = self.mock_db.cache_response.call_args
        cache_key = args_cache[0]
        # MD5 of 'echo "Hello Virtual World"' is ... let's just check checks for hash
        assert "bash script.sh::hash=" in cache_key

    def test_handle_hostname(self, handler):
        context = {'user': 'root', 'honeypot_ip': '1.2.3.4'}
        
        # Default
        resp, _ = handler.handle_hostname("hostname", context)
        # We perform mocking because handle_hostname tries to import config.
        # But realistically it returns a default string if config missing or populated.
        assert len(resp) > 0
        
        # Test -i
        resp, _ = handler.handle_hostname("hostname -i", context)
        assert "1.2.3.4" in resp

    def test_editors_disabled(self, handler):
        # Editors should be blocked
        # Note: _is_allowed return value depends on STATE_COMMANDS + READ_ONLY_COMMANDS.
        # We removed editors from STATE_COMMANDS.
        assert handler._is_allowed("nano 1.txt") is False
        assert handler._is_allowed("vi 1.txt") is False
        assert handler._is_allowed("vim 1.txt") is False

    def test_handle_uname(self, handler):
        context = {'hostname': 'testbox'}
        
        # Default
        resp, _, _ = handler.handle_uname("uname", context)
        assert "Linux" in resp
        
        # Flag -a
        resp_a, _, _ = handler.handle_uname("uname -a", context)
        assert "Linux" in resp_a
        assert "x86_64" in resp_a
        
        # Flag -r
        resp_r, _, _ = handler.handle_uname("uname -r", context)
        assert "5.10" in resp_r

    def test_handle_ps(self, handler):
        context = {'user': 'root'}
        
        # Mock LLM returning process list with 'alabaster' as placeholder
        llm_resp = json.dumps({
            "processes": [
                {"user": "root", "pid": 1, "ppid": 0, "cpu": 0.1, "mem": 0.1, "start": "12:00", "time": "00:00:10", "command": "/sbin/init"},
                {"user": "root", "pid": 100, "ppid": 1, "cpu": 0.0, "mem": 0.5, "start": "12:01", "time": "00:00:00", "command": "sshd"},
                {"user": "alabaster", "pid": 101, "ppid": 100, "cpu": 0.0, "mem": 0.1, "start": "12:02", "time": "00:00:00", "command": "bash"}
            ]
        })
        self.mock_llm.generate_response.return_value = llm_resp
        
        # 1. Simple PS (should filter based on REPLACED user)
        # Context user is 'root'. 
        # alabaster -> root. So 'bash' (formerly alabaster) becomes 'root'.
        # Since simple ps uses current_user='root', it should SHOW 'bash'.
        resp, _ = handler.handle_ps("ps", context)
        assert "sshd" in resp
        assert "bash" in resp  # Should be preserved because alabaster->root
        
        # Test with context user = 'attacker'
        context2 = {'user': 'attacker'}
        # Clear cache/Force reload not really easy with mocked DB unless we reset mock
        # But handle_ps uses DB mock.
        # We need to ensure DB mock returns None first? 
        # In setup, mock_db.get_cached_response returns None.
        
        resp2, _ = handler.handle_ps("ps", context2)
        # alabaster -> attacker.
        # simple ps filters for 'attacker'.
        # root processes (sshd, init) are HIDDEN.
        # bash (attacker) is SHOWN.
        assert "bash" in resp2
        assert "sshd" not in resp2
        
        # 2. PS -ef (Show all + full format)
        resp_ef, _ = handler.handle_ps("ps -ef", context)
        assert "UID" in resp_ef
        assert "/sbin/init" in resp_ef
        assert "bash" in resp_ef # Should show all users
        
        # 3. PS aux (Show all + user format)
        resp_aux, _ = handler.handle_ps("ps aux", context)
        assert "%CPU" in resp_aux
        assert "sshd" in resp_aux

    def test_handle_md5sum(self, handler):
        # Setup context
        context = {
            'cwd': '/home/user',
            'history': [],
            'vfs': {}
        }
        
        # Mock _generate_or_get_content result
        # We can mock the db call inside it, or just mock the method on the handler instance.
        # Since handler is the CUT, better to mock dependencies.
        # But _generate_or_get_content calls DB then LLM.
        # Let's mock handler._generate_or_get_content to verify integration with md5sum logic only.
        with patch.object(handler, '_generate_or_get_content', return_value=("test content", "local")) as mock_content:
            # 1. Test calculation
            resp, _, _ = handler.handle_md5sum("md5sum file.txt", context)
            
            # MD5("test content") = 9473fdd0d880a43c21b7778d34872157
            expected_hash = "9473fdd0d880a43c21b7778d34872157"
            assert expected_hash in resp
            assert "file.txt" in resp
            
            mock_content.assert_called_with("md5sum", "file.txt", context)
            
        # 2. Test missing arg
        resp_err, _, _ = handler.handle_md5sum("md5sum", context)
        assert "missing operand" in resp_err

    def test_wc_default_file(self, handler):
        # Setup mock
        handler._generate_or_get_content = MagicMock(return_value=("hello world\nline 2", "local"))
        
        cmd = "wc test.txt"
        context = {}
        res, _, _ = handler.handle_wc(cmd, context)
        
        parts = res.split()
        # "hello world\nline 2" -> 2 lines, 4 words, 18 chars
        assert parts[0] == "2"
        assert parts[1] == "4"
        assert parts[2] == "18"
        assert "test.txt" in res

    def test_wc_lines_only_pipe(self, handler):
        cmd = "wc -l"
        context = {'stdin': "a\nb\nc"}
        res, _, _ = handler.handle_wc(cmd, context)
        assert res.strip() == "3"

    def test_wc_lines_words_pipe(self, handler):
        cmd = "wc -lw"
        context = {'stdin': "hello"}
        res, _, _ = handler.handle_wc(cmd, context)
        parts = res.split()
        assert len(parts) == 2
        assert parts[0] == "1" # lines
        assert parts[1] == "1" # words

    def test_nproc(self, handler):
        cmd = "nproc"
        context = {}
        # helper wrapper calls system_handler directly, returning 2 val
        res, _ = handler.handle_nproc(cmd, context)
        assert res.strip() == "192"

    def test_uptime_command(self, handler):
        res, _ = handler.handle_uptime("uptime", {})
        assert "up 14 days" in res
        assert "load average" in res

    def test_proc_uptime(self, handler):
        # /proc/uptime via handle_cat
        context = {'cwd': '/root'}
        res, _, meta = handler.handle_cat("cat /proc/uptime", context)
        parts = res.strip().split()
        assert len(parts) == 2
        assert float(parts[0]) > 1000000 
        assert meta['source'] == 'local'

    def test_handle_grep_basic(self, handler):
        # Basic grep via pipe
        cmd = "grep hello"
        context = {'stdin': "hello\nworld\nhello world"}
        res, _, _ = handler.handle_grep(cmd, context)
        assert len(res.strip().split('\n')) == 2
        assert "hello" in res
        assert "world" in res # third line "hello world"

        # -v invert
        cmd = "grep -v hello"
        res, _, _ = handler.handle_grep(cmd, context)
        assert res.strip() == "world"

    def test_grep_regex_m1(self, handler):
        from unittest.mock import MagicMock
        cpuinfo = """model name	: AMD EPYC 9654
model name	: AMD EPYC 9654
Hardware	: FakeHardware
Other		: Something
"""
        # Mock content retrieval
        handler._generate_or_get_content = MagicMock(return_value=(cpuinfo, 'local'))
        
        cmd = 'grep -m1 -E "model name|Hardware" /proc/cpuinfo'
        context = {'cwd': '/root'}
        
        res, _, _ = handler.handle_grep(cmd, context)
        lines = res.strip().split('\n')
        assert len(lines) == 1
        res, _, _ = handler.handle_grep(cmd, context)
        lines = res.strip().split('\n')
        assert len(lines) == 1
        assert "model name" in lines[0]

    def test_pipe_parsing_quotes(self, handler):
        # Regression test: Ensure | inside quotes is NOT treated as pipe
        cmd = 'echo "hello|world"'
        context = {}
        res, _, meta = handler.process_command(cmd, context)
        assert "hello|world" in res
        assert "command not found" not in res
        
        # Test REAL pipe works
        cmd = 'echo hello | grep hello'
        res, _, _ = handler.process_command(cmd, context)
        assert "hello" in res

    def test_alabaster_replacement(self, handler):
        # Test that 'alabaster' in LLM output is replaced by current user
        handler.llm.generate_response.return_value = "Hello alabaster, welcome Alabaster!"
        
        context = {'user': 'admin', 'session_id': 'test', 'cwd': '/root'}
        cmd = 'hello_command' # Unknown command -> generic handler
        
        # We need generic handler to be triggered.
        # process_command calls handle_generic if unknown.
        # But generic is not in the whitelist unless we mock _is_allowed or add it?
        # Actually generic is fallback IF _is_allowed passes? 
        # No, process_command checks whitelist.
        # If I use a whitelisted command that uses generic logic?
        # Or I just call handle_generic directly for this unit test.
        
        res, _, _ = handler.handle_generic(cmd, context)
        
        assert "Hello admin" in res
        assert "welcome Admin" in res # Capitalization check

    def test_dmidecode_processor(self, handler):
        cmd = "dmidecode -s processor-version"
        context = {}
        res, _, meta = handler.handle_dmidecode(cmd, context)
        assert "Intel(R) Xeon(R) Platinum 8480+" in res
        assert meta['source'] == 'local'

        # Test fallback
        cmd = "dmidecode -t bios"
        handler.handle_generic = MagicMock(return_value=("Mock LLM", {}, {'source': 'llm'}))
        res, _, meta = handler.handle_dmidecode(cmd, context)
        assert res == "Mock LLM"
        handler.handle_generic.assert_called_once()

    def test_handle_ip_integration(self, handler):
        # We need to mock the network_handlers inside the handler instance
        handler.network_handlers = MagicMock()
        handler.network_handlers.handle_ip.return_value = "Mock IP Addr Output"
        
        cmd = "ip addr"
        context = {}
        res, _ = handler.handle_ip(cmd, context)
        
        assert "Mock IP Addr Output" in res
        # Verify args passed (addr)
        handler.network_handlers.handle_ip.assert_called_with(['addr'])

    def test_handle_ifconfig_integration(self, handler):
        handler.network_handlers = MagicMock()
        handler.network_handlers.handle_ifconfig.return_value = "Mock Ifconfig Output"
        
        cmd = "ifconfig"
        context = {}
        res, _ = handler.handle_ifconfig(cmd, context)
        
        assert "Mock Ifconfig Output" in res
        handler.network_handlers.handle_ifconfig.assert_called_with([])

    def test_handle_ping_integration(self, handler):
        handler.network_handlers = MagicMock()
        handler.network_handlers.handle_ping.return_value = "Mock Ping Output"
        
        cmd = "ping -c 2 localhost"
        context = {}
        res, _ = handler.handle_ping(cmd, context)
        
        assert "Mock Ping Output" in res
        # Verify args passed (['-c', '2', 'localhost'])
        # Split logic in handler is cmd.split()[1:]
        expected_args = ['-c', '2', 'localhost']
        handler.network_handlers.handle_ping.assert_called_with(expected_args)
