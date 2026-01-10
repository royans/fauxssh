
import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.http_server.server import HoneyHTTPHandler
from ssh_honeypot.core.llm import LLMInterface

class TestHttpLLMIntegration(unittest.TestCase):
    def test_do_get_calls_llm_correctly(self):
        """
        Regression Test: Ensure handle_honey_request calls llm.generate_response
        with valid arguments (fixing the 'unexpected keyword argument' crash).
        """
        # Mock Server and its components
        mock_server = MagicMock()
        mock_db = MagicMock()
        mock_llm = MagicMock()
        mock_server.honey_db = mock_db
        mock_server.honey_db = mock_db
        mock_server.llm_interface = mock_llm
        mock_db.check_llm_rate_limit.return_value = (True, "OK") # Rate Limit Mock
        
        # Prepare mock request socket
        mock_request = MagicMock()
        mock_client_addr = ('127.0.0.1', 54321)
        # rfile needs to be a byte stream for parse_request to read the request line
        mock_request.makefile.return_value.readline.return_value = b"GET /test.html HTTP/1.1\r\n"
        
        # Patching log to suppress output
        with patch('ssh_honeypot.services.http_server.server.log'):
            handler = HoneyHTTPHandler(mock_request, mock_client_addr, mock_server)
            
            # Setup path manually if needed (likely set by parse_request but we can override)
            handler.path = "/test.html"
            handler.headers = {'User-Agent': 'TestAgent'}
            
            # Mock DB cache miss to force LLM call
            mock_db.get_cached_response.return_value = None
            
            # Action: Call the method that was crashing
            handler.handle_honey_request("GET")
            
            # Verification
            mock_llm.generate_response.assert_called_once()
            
            # Check the kwargs to ensure we are using 'override_prompt' and NOT 'system_override'
            args, kwargs = mock_llm.generate_response.call_args
            self.assertIn('override_prompt', kwargs, "Must use 'override_prompt' kwarg")
            self.assertNotIn('system_override', kwargs, "Must NOT use 'system_override' kwarg (Regression)")

if __name__ == '__main__':
    unittest.main()
