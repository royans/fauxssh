import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_tail import TailCommand

class TestTailCommand:
    @pytest.fixture
    def handler(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        return TailCommand(self.mock_db, self.mock_llm)

    def test_tail_basic(self, handler):
        content = "\n".join([f"line{i}" for i in range(20)])
        handler._generate_or_get_content = MagicMock(return_value=(content, "local"))
        res, _, _ = handler.handle("tail file.txt", {})
        lines = res.splitlines()
        assert len(lines) == 10
        assert lines[-1] == "line19"

    def test_tail_n(self, handler):
        content = "\n".join([f"line{i}" for i in range(20)])
        handler._generate_or_get_content = MagicMock(return_value=(content, "local"))
        res, _, _ = handler.handle("tail -n 3 file.txt", {})
        lines = res.splitlines()
        assert len(lines) == 3
        assert lines[-1] == "line19"
        assert lines[0] == "line17"

    def test_tail_stdin(self, handler):
        context = {'stdin': "a\nb\nc\nd\ne"}
        res, _, _ = handler.handle("tail -n 2", context)
        assert res.strip() == "d\ne"
