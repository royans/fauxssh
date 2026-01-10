import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_cut import CutCommand

class TestCutCommand:
    @pytest.fixture
    def handler(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        return CutCommand(self.mock_db, self.mock_llm)

    def test_cut_fields_delimiter(self, handler):
        context = {'stdin': "col1,col2,col3\nval1,val2,val3"}
        # cut -d, -f2
        res, _, _ = handler.handle("cut -d, -f2", context)
        lines = res.strip().split('\n')
        assert lines[0] == "col2"
        assert lines[1] == "val2"

    def test_cut_fields_range(self, handler):
        context = {'stdin': "1:2:3:4:5"}
        # cut -d: -f2-4
        res, _, _ = handler.handle("cut -d: -f2-4", context)
        assert res.strip() == "2:3:4"

    def test_cut_error(self, handler):
        res, _, _ = handler.handle("cut", {})
        assert "you must specify a list of bytes" in res
