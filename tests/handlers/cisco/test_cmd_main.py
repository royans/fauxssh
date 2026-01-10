
import pytest
import sys
import os
from unittest.mock import MagicMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from ssh_honeypot.handlers.cisco.cmd_main import (
    handle_cisco_show, 
    handle_cisco_enable, 
    handle_cisco_configure, 
    handle_cisco_exit,
    handle_cisco_help
)

class TestCiscoHandlers:
    
    def test_show_version(self):
        cmd = "show version"
        context = {'persona_config': {'system': {'hostname': 'MyRouter'}}}
        out, updates, meta = handle_cisco_show(cmd, context)
        assert "Cisco IOS Software" in out
        assert "MyRouter uptime is" in out
        
    def test_enable(self):
        cmd = "enable"
        context = {'env': {}}
        out, updates, meta = handle_cisco_enable(cmd, context)
        assert updates['env']['privilege_level'] == 15
        
    def test_conf_terminal_denied_low_priv(self):
        cmd = "configure terminal"
        context = {'env': {'privilege_level': 1}}
        out, updates, meta = handle_cisco_configure(cmd, context)
        assert "Type 'enable'" in out
        
    def test_conf_terminal_allowed(self):
        cmd = "configure terminal"
        context = {'env': {'privilege_level': 15}}
        out, updates, meta = handle_cisco_configure(cmd, context)
        assert updates['env']['config_mode'] is True
        assert "Enter configuration commands" in out
        
    def test_exit_config_mode(self):
        cmd = "exit"
        context = {'env': {'config_mode': True, 'privilege_level': 15}}
        out, updates, meta = handle_cisco_exit(cmd, context)
        assert updates['env']['config_mode'] is False
        assert "Configured from console" in out
        
    def test_exit_enable_mode(self):
        cmd = "exit"
        context = {'env': {'config_mode': False, 'privilege_level': 15}}
        out, updates, meta = handle_cisco_exit(cmd, context)
        assert updates['env']['privilege_level'] == 1
        
    def test_show_run_hidden(self):
        cmd = "show running-config"
        context = {'env': {'privilege_level': 1}}
        out, updates, meta = handle_cisco_show(cmd, context)
        assert "% Invalid input" in out
        
    def test_show_run_visible(self):
        cmd = "show run"
        context = {'env': {'privilege_level': 15}, 'persona_config': {'system': {'hostname': 'R1'}}}
        out, updates, meta = handle_cisco_show(cmd, context)
        assert "Current configuration" in out
        assert "hostname R1" in out

    def test_help_exec(self):
        cmd = "?"
        context = {'env': {'privilege_level': 1}}
        out, updates, meta = handle_cisco_help(cmd, context)
        assert "Exec commands:" in out
        assert "enable" in out
        assert "configure" not in out # Should be hidden in low priv

    def test_help_priv_exec(self):
        cmd = "?"
        context = {'env': {'privilege_level': 15}}
        out, updates, meta = handle_cisco_help(cmd, context)
        assert "Exec commands:" in out
        assert "enable" in out
        assert "configure" in out

    def test_ping(self):
        # Need to import new handlers first if not already imported in test file
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_ping
        out, _, _ = handle_cisco_ping("ping 1.1.1.1", {})
        assert "Success rate is 100 percent" in out

    def test_traceroute(self):
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_traceroute
        out, _, _ = handle_cisco_traceroute("traceroute 8.8.8.8", {})
        assert "Tracing the route to 8.8.8.8" in out

    def test_ssh_denied(self):
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_ssh
        out, _, _ = handle_cisco_ssh("ssh user@host", {})
        assert "not allowed" in out

    def test_alias_sh(self):
        # 'sh' maps to show handler in dispatch, but let's verify the handler accepts it
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_show
        out, _, _ = handle_cisco_show("sh version", {'persona_config': {'system': {'hostname': 'R1'}}})
        assert "Cisco IOS Software" in out

    def test_invalid_shell(self):
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_invalid
        out, _, _ = handle_cisco_invalid("shell", {})
        assert "% Invalid input" in out

    def test_show_conf(self):
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_show
        # Must be priv 15
        context = {'env': {'privilege_level': 15}, 'persona_config': {'system': {'hostname': 'R1'}}}
        out, _, _ = handle_cisco_show("show conf", context)
        assert "Current configuration" in out

    def test_hostname_change(self):
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_hostname
        # Setup initial config
        initial_config = "version 15.0\nhostname Router\nend"
        context = {'env': {'cisco_running_config': initial_config}}
        
        out, updates, _ = handle_cisco_hostname("hostname NewSwitch", context)
        
        assert updates['env']['hostname_override'] == "NewSwitch"
        assert "hostname NewSwitch" in updates['env']['cisco_running_config']
        assert "hostname Router" not in updates['env']['cisco_running_config']

    def test_show_conf_low_priv(self):
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_show
        context = {'env': {'privilege_level': 1}}
        out, _, _ = handle_cisco_show("show conf", context)
        assert "% Invalid input" in out

    def test_show_conf_from_persona(self):
        from ssh_honeypot.handlers.cisco.cmd_main import handle_cisco_show
        
        # Inject defaults into persona
        context = {
            'env': {'privilege_level': 15},
            'persona_config': {
                'system': {'hostname': 'R1'},
                'defaults': {'running_config': "hostname StaticConf\nend"}
            },
            # LLM not provided, or mocked to fail if called
            'llm': None 
        }
        
        out, updates, _ = handle_cisco_show("show conf", context)
        
        assert "hostname StaticConf" in out
        assert updates['env']['cisco_running_config'] == "hostname StaticConf\nend"
