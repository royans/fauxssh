import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_head import HeadCommand


class TestHeadCommand:
    @pytest.fixture
    def handler(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        return HeadCommand(self.mock_db, self.mock_llm)

    def test_head_basic(self, handler):
        handler._generate_or_get_content = MagicMock(
            return_value=("line1\nline2\nline3\n" * 5, "local")
        )
        res, _, _ = handler.handle("head file.txt", {})
        lines = res.splitlines()
        assert len(lines) == 10

    def test_head_n(self, handler):
        handler._generate_or_get_content = MagicMock(
            return_value=("line1\nline2\nline3\n" * 5, "local")
        )
        res, _, _ = handler.handle("head -n 2 file.txt", {})
        lines = res.splitlines()
        assert len(lines) == 2

    def test_head_stdin(self, handler):
        context = {"stdin": "a\nb\nc\nd\ne"}
        res, _, _ = handler.handle("head -n 3", context)
        assert res.strip() == "a\nb\nc"
