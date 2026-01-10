import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_grep import GrepCommand

class TestGrepCommand:
    @pytest.fixture
    def handler(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        return GrepCommand(self.mock_db, self.mock_llm)

    def test_handle_grep_basic(self, handler):
        # Basic grep via pipe
        cmd = "grep hello"
        context = {'stdin': "hello\nworld\nhello world"}
        res, _, _ = handler.handle(cmd, context)
        assert len(res.strip().split('\n')) == 2
        assert "hello" in res
        assert "world" in res # third line "hello world"

        # -v invert
        cmd = "grep -v hello"
        res, _, _ = handler.handle(cmd, context)
        assert res.strip() == "world"

    def test_grep_regex_m1(self, handler):
        cpuinfo = """model name	: AMD EPYC 9654
model name	: AMD EPYC 9654
Hardware	: FakeHardware
Other		: Something
"""
        # Mock content retrieval via _generate_or_get_content logic
        # Since we can't easily patch the method on the instance if it's inherited without setup,
        # we mock the DB calls involved.
        # OR we can patch the method on the instance.
        
        with pytest.MonkeyPatch.context() as m:
            # We can't monkeypatch instance method easily on just ONE instance without binding.
            # But we can replace the method on the object.
            handler._generate_or_get_content = MagicMock(return_value=(cpuinfo, 'local'))
            
            cmd = 'grep -m1 -E "model name|Hardware" /proc/cpuinfo'
            context = {'cwd': '/root'}
            
            res, _, _ = handler.handle(cmd, context)
            lines = res.strip().split('\n')
            assert len(lines) == 1
            assert "model name" in lines[0]
