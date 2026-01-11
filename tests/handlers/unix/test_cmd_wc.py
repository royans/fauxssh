import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_wc import WcCommand


class TestWcCommand:
    @pytest.fixture
    def handler(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        return WcCommand(self.mock_db, self.mock_llm)

    def test_wc_default_file(self, handler):
        # Setup mock
        handler._generate_or_get_content = MagicMock(
            return_value=("hello world\nline 2", "local")
        )

        cmd = "wc test.txt"
        context = {}
        res, _, _ = handler.handle(cmd, context)

        parts = res.split()
        # "hello world\nline 2" -> 2 lines, 4 words, 18 chars
        assert parts[0] == "2"
        assert parts[1] == "4"
        assert parts[2] == "18"
        assert "test.txt" in res

    def test_wc_lines_only_pipe(self, handler):
        cmd = "wc -l"
        context = {"stdin": "a\nb\nc"}
        res, _, _ = handler.handle(cmd, context)
        assert res.strip() == "3"

    def test_wc_lines_words_pipe(self, handler):
        cmd = "wc -lw"
        context = {"stdin": "hello"}
        res, _, _ = handler.handle(cmd, context)
        parts = res.split()
        assert len(parts) == 2
        assert parts[0] == "1"  # lines
        assert parts[1] == "1"  # words
