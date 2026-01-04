
import pytest
from unittest.mock import MagicMock
from ssh_honeypot.command_handler import CommandHandler

class TestComplexAssignment:
    @pytest.fixture
    def handler(self):
        mock_llm = MagicMock()
        mock_db = MagicMock()
        mock_db.log_interaction = MagicMock()
        return CommandHandler(mock_llm, mock_db)

    def test_complex_assignment_offload(self, handler):
        # Command: cpus=$( (nproc || grep ...) | head -1 )
        cmd = 'cpus=$( (nproc || grep -c "^processor" /proc/cpuinfo) 2>/dev/null | head -1)'
        
        # Mock LLM and DB
        handler.db.get_cached_response.return_value = None
        handler.llm.generate_response.return_value = '{"output": "4"}'
        
        context = {'env': {}, 'user': 'root', 'cwd': '/'}
        out, updates, meta = handler.process_command(cmd, context)
        
        # Assertions
        # 1. Output should be empty (assignment)
        assert out.strip() == ""
        
        # 2. Env should be updated
        assert updates.get('env', {}).get('cpus') == "4", "Failed to assign variable from complex command"
        
        # 3. LLM should have been called
        # Verify the prompt contained the complex logic
        # Note: Exact string match depends on sanitization
        called_args = handler.llm.generate_response.call_args
        assert called_args is not None
        prompt_sent = called_args[0][0] # First arg is prompt
        assert "nproc" in prompt_sent or "processor" in prompt_sent
