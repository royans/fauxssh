import sys
import os
import io

# Setup path
sys.path.append(os.getcwd())

from ssh_honeypot.core.command_handler import CommandHandler
from unittest.mock import MagicMock

def test_crash():
    print("Testing Cisco Enable Command...")
    
    # Mock LLM and DB
    mock_llm = MagicMock()
    mock_db = MagicMock()
    mock_db.list_user_dir.return_value = []
    
    handler = CommandHandler(mock_llm, mock_db)
    
    # Cisco Context
    context = {
        'env': {},
        'cwd': '/',
        'user': 'root',
        'persona_config': {
            'system': {'handler_type': 'cisco_ios', 'hostname': 'Switch'},
            'defaults': {}
        },
        'client_ip': '127.0.0.1'
    }
    
    try:
        # Run enable
        res = handler.process_command("enable", context)
        print(f"Result: {res}")
        
    except Exception as e:
        print(f"CRASH: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_crash()
