import pytest
from unittest.mock import MagicMock
from ssh_honeypot.handlers.unix.cmd_id import IdCommand
from ssh_honeypot.handlers.unix.cmd_date import DateCommand
import datetime


class TestMigratedHandlers:
    @pytest.fixture
    def id_handler(self):
        return IdCommand(MagicMock(), MagicMock())

    @pytest.fixture
    def date_handler(self):
        return DateCommand(MagicMock(), MagicMock())

    def test_id_root(self, id_handler):
        context = {"user": "root"}
        output, updates, meta = id_handler.handle("id", context)
        assert "uid=0(root)" in output
        assert "gid=0(root)" in output
        assert "groups=0(root)" in output

    def test_id_non_root(self, id_handler):
        context = {"user": "testuser"}
        output, updates, meta = id_handler.handle("id", context)
        assert "uid=1000(testuser)" in output
        assert "gid=1000(testuser)" in output
        assert "groups=1000(testuser)" in output

    def test_date_basic(self, date_handler):
        context = {}
        output, updates, meta = date_handler.handle("date", context)
        # Check format like "Fri Jan 30 04:57:29 UTC 2026"
        # We can at least check for current year
        year = str(datetime.datetime.now().year)
        assert year in output
        assert len(output.split()) >= 5
