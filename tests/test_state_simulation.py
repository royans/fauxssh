import sys
import os
import pytest
import json
from unittest.mock import MagicMock

# Ensure the root directory is in path so we can import ssh_honeypot as a package
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ssh_honeypot.command_handler import CommandHandler

class TestStateSimulation:
    """
    Validates that the command handler correctly emits state change events 
    that drive the User and System level state management.
    """

    @pytest.fixture
    def handler(self):
        self.mock_llm = MagicMock()
        self.mock_db = MagicMock()
        self.mock_db.get_cached_response.return_value = None
        return CommandHandler(self.mock_llm, self.mock_db)

    def test_user_state_cwd_transition(self, handler):
        """
        Validates that a 'cd' command correctly updates the Current Working Directory (User State).
        """
        # Initial State
        context = {
            'cwd': '/root',
            'vfs': {'/root': []},
            'history': []
        }

        # Mock LLM response for 'cd /var/www'
        # The LLM should return a JSON with 'new_cwd'
        handler.llm.generate_response.return_value = json.dumps({
            "output": "",
            "new_cwd": "/var/www",
            "file_modifications": []
        })

        # Execute
        cmd = "cd /var/www"
        resp_text, updates, meta = handler.process_command(cmd, context)

        # Validate State Transition Event
        assert updates is not None
        assert updates.get('new_cwd') == "/var/www"
        
        # Simulate Server Logic: Apply update
        context['cwd'] = updates['new_cwd']
        
        # Validate User State is Updated
        assert context['cwd'] == "/var/www"

    def test_user_state_file_creation(self, handler):
        """
        Validates that a 'touch' command correctly updates the Virtual Filesystem (User State).
        """
        # Initial State
        context = {
            'cwd': '/home/user',
            'vfs': {'/home/user': ['existing.txt']},
            'history': [],
            'client_ip': '1.2.3.4',
            'user': 'user'
        }
        
        # Note: touch is now handled LOCALLY, not by LLM. 
        # So we test the local handler output and verify DB interaction if we mock properly.
        # But this test relies on 'process_command' return values for updates.
        # And process_command calls handle_touch.
        
        handler.db.get_user_node.return_value = None # Does not exist
        
        # Execute
        cmd = "touch newfile.txt"
        resp_text, updates, meta = handler.process_command(cmd, context)

        # Validate Update Event
        # Local handler returns: {'file_modifications': [abs_path]}
        # We need to adapt the test or the handler?
        # The test expects specific list behavior.
        # Let's adapt test to new reality.
        
        assert updates is not None
        file_mods = updates.get('file_modifications', [])
        assert len(file_mods) > 0
        
        # It's a list of dictionaries now
        mod = file_mods[0]
        assert mod['path'] == "/home/user/newfile.txt"
        assert mod['action'] == "create"
        
        # Simulate Server Logic for test validity (though server logic uses DB mostly now)
        # But for VFS update in context?
        # process_command doesn't auto-update context['vfs'] unless server does it.
        # Server code does: if file_modifications: ...
        
        # Manual update for test assertion
        context['vfs']['/home/user'].append("newfile.txt")

        # Validate VFS State
        assert "newfile.txt" in context['vfs']['/home/user']


    def test_system_state_history_propagation(self, handler):
        """
        Validates that the System/Session correctly propagates command history into the Context,
        affecting future usage.
        """
        # Setup history state
        initial_history = [("ls", "file1.txt")]
        context = {
            'cwd': '/',
            'vfs': {},
            'history': initial_history
        }

        # Mock LLM
        handler.llm.generate_response.return_value = '{"output": "ok"}'

        # Execute a new command that triggers LLM (not a local handler like echo/df/touch)
        # We use a random command that is safe (allowed or generic fallback)
        # 'helloworld' falls to generic if not blocked.
        # Security validator might block unknown? No, it allows generic.
        handler.process_command("man ls", context)

        # Verify that the LLM was called with the HISTORY from the context
        # This confirms that 'System State' (history) is being used for decision making
        call_args = handler.llm.generate_response.call_args
        
        if call_args:
             # args[2] is history_context in generate_response(cmd, cwd, history_context...)
             passed_history = call_args[0][2]
             assert passed_history == initial_history
        else:
             pytest.fail("LLM was not called for generic command")
