import unittest
from unittest.mock import MagicMock, patch
import json
import time
import sys

# Define Safe MagicMock class that propagates __code__ property
class SafeMagicMock(MagicMock):
    @property
    def __code__(self):
        # Return a dummy code object to satisfy inspection
        return (lambda: None).__code__

def create_safe_mock():
    # Use the safe class that propagates behavior to children
    m = SafeMagicMock()
    m.pytest_plugins = None
    m.__name__ = "mock_module"
    return m

sys.modules['mcp'] = create_safe_mock()
sys.modules['mcp.server'] = create_safe_mock()
sys.modules['mcp.server.fastmcp'] = create_safe_mock()
sys.modules['mcp.server.sse'] = create_safe_mock()
sys.modules['uvicorn'] = create_safe_mock()
sys.modules['starlette'] = create_safe_mock()
sys.modules['starlette.applications'] = create_safe_mock()
sys.modules['starlette.routing'] = create_safe_mock()
sys.modules['starlette.responses'] = create_safe_mock()
sys.modules['starlette.middleware'] = create_safe_mock()
sys.modules['starlette.middleware.cors'] = create_safe_mock()


# Import decoupled logic
# Note: we import from ssh_honeypot.services.mcp.server
# This should work even if MCP is missing because we catch ImportError at module level there.
from ssh_honeypot.services.mcp.server import (
    tool_audit_compliance_sum,
    tool_get_cloud_credentials,
    tool_run_system_command,
    tool_query_database, # Added
    check_quota_and_throttle,
    CLIENT_STATE
)

class TestMCPServer(unittest.TestCase):
    
    def setUp(self):
        # Reset throttling state
        CLIENT_STATE.clear()
        
        # Mock Config
        self.config_patcher = patch('ssh_honeypot.services.mcp.server.config')
        self.mock_config = self.config_patcher.start()
        # Default config
        self.mock_config.get.side_effect = lambda section, key: {
            ('mcp', 'max_llm_calls'): 5,
            ('mcp', 'throttle_delay'): 0.01 # Fast for tests
        }.get((section, key))

    def tearDown(self):
        self.config_patcher.stop()

    def test_audit_compliance_sum(self):
        result = tool_audit_compliance_sum(2, 2)
        self.assertEqual(result, 4) # Funny but accurate

    def test_get_cloud_credentials_aws(self):
        res = tool_get_cloud_credentials('aws')
        data = json.loads(res)
        self.assertTrue(data['access_key'].startswith('AKIA'))
        self.assertTrue('secret_key' in data)

    def test_get_cloud_credentials_unknown(self):
        res = tool_get_cloud_credentials('azure')
        self.assertIn("Error", res)

    @patch('time.sleep') 
    def test_quota_and_throttling(self, mock_sleep):
        ip = "1.2.3.4"
        
        # 1. First call - Allowed
        allowed, msg = check_quota_and_throttle(ip)
        self.assertTrue(allowed)
        
        # 2. Burst calls (should trigger sleep but stay allowed until quota)
        # Limit is 5. We did 1. We need 4 more to fill bucket (0->1, 1->2, 2->3, 3->4, 4->5).
        # Actually logic is > max. max=5.
        # Call 1: 0>5 False. -> 1.
        # Call 2: 1>5 False. -> 2.
        # Call 3: 2>5 False. -> 3.
        # Call 4: 3>5 False. -> 4.
        # Call 5: 4>5 False. -> 5.
        # Call 6: 5>5 False. -> 6. 
        # Call 7: 6>5 True. Blocked.
        # So we need 5 more calls after first to reach 6 calls total (allowed), then 7th fails.
        # Let's just loop range(5) to get to total 6 calls made.
        for _ in range(5):
            allowed, _ = check_quota_and_throttle(ip)
            self.assertTrue(allowed)
            
        # Check if sleep was called (we did fast calls)
        self.assertTrue(mock_sleep.called)

        # 7th call - Should fail
        allowed, msg = check_quota_and_throttle(ip)
        self.assertFalse(allowed)
        self.assertEqual(msg, "Quota Exceeded")

    def test_run_system_command_success(self):
        # Mock CommandHandler and DB
        mock_handler = MagicMock()
        mock_db = MagicMock()
        
        # Mock process_command return
        mock_handler.process_command.return_value = ("Output", {}, {})
        
        res = tool_run_system_command("ls -la", mock_handler, mock_db)
        
        self.assertEqual(res, "Output")
        # Verify Handler called
        mock_handler.process_command.assert_called_once()
        args, _ = mock_handler.process_command.call_args
        self.assertEqual(args[0], "ls -la")
        self.assertEqual(args[1]['client_ip'], "127.0.0.1")
        self.assertEqual(args[1]['user'], "ops_admin")
        
        # Verify Logging
        mock_db.log_interaction.assert_called_once()


    def test_run_system_command_quota_fail(self):
        mock_handler = MagicMock()
        mock_db = MagicMock()
        ip = "127.0.0.1" # Hardcoded in tool currently
        
        # Exhaust quota
        CLIENT_STATE[ip] = {'llm_calls': 100, 'last_req': 0, 'req_count': 0}
        
        res = tool_run_system_command("ls", mock_handler, mock_db)
        self.assertIn("Quota Exceeded", res)
        
        # Verify handler NOT called
        mock_handler.process_command.assert_not_called()

    def test_query_database_cache_hit(self):
        mock_db = MagicMock()
        mock_llm = MagicMock()
        
        # Cache hit
        mock_db.get_cached_response.return_value = "Cached Result"
        
        res = tool_query_database("SELECT * FROM users", mock_db, mock_llm)
        self.assertEqual(res, "Cached Result")
        # LLM not called
        mock_llm.generate_response.assert_not_called()
        
    def test_query_database_cache_miss(self):
        mock_db = MagicMock()
        mock_llm = MagicMock()
        
        # Cache miss
        mock_db.get_cached_response.return_value = None
        mock_llm.generate_response.return_value = "Fake DB Result"
        
        res = tool_query_database("SELECT * FROM billing", mock_db, mock_llm)
        self.assertEqual(res, "Fake DB Result")
        # LLM called
        mock_llm.generate_response.assert_called_once()
        # Cached updated
        mock_db.cache_response.assert_called_once()

if __name__ == '__main__':
    unittest.main()
