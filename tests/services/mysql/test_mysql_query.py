import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from ssh_honeypot.services.mysql.session import HoneyMySQLSession
from ssh_honeypot.services.mysql.dummy_data import SYSTEM_VARIABLES, DUMMY_DATABASES
import sqlglot
from sqlglot import exp


class MockConnection:
    def __init__(self):
        self.reader = MagicMock()
        self.reader.get_extra_info.return_value = ("127.0.0.1", 12345)


@pytest.fixture
def mock_session():
    db = MagicMock()
    # LLMInterface.query is synchronous, so use MagicMock
    llm = MagicMock()
    llm.query.return_value = (
        '{"columns": ["fake"], "rows": [["data"]]}'  # Default LLM response
    )
    config = {}
    return HoneyMySQLSession(db, llm, config)


@pytest.mark.asyncio
async def test_init(mock_session):
    conn = MockConnection()
    await mock_session.init(conn)
    assert mock_session.client_address == ("127.0.0.1", 12345)
    # Verify IP context set?
    from ssh_honeypot.services.mysql.context import client_ip_ctx

    assert client_ip_ctx.get() == "127.0.0.1"


@pytest.mark.asyncio
async def test_handle_local_select_variables(mock_session):
    # Test SELECT @@version
    sql = "SELECT @@version"
    parsed = sqlglot.parse_one(sql)

    # We call the internal method or query? Let's check query flow
    # Need to simulate sqlglot behavior inside query()
    # But since query() calls _handle_local_select, let's unit test _handle_local_select first
    # or just call query() which is better integration test.

    rows, cols = await mock_session.query(sql, sql)

    # sqlglot/mysql-mimic tends to return column names as uppercase or consistent with SQL
    assert cols == ["@@VERSION"]
    assert rows[0][0] == SYSTEM_VARIABLES["@@version"]


@pytest.mark.asyncio
async def test_handle_local_select_multiple(mock_session):
    # Test SELECT @@version, @@hostname
    sql = "SELECT @@version, @@hostname"
    rows, cols = await mock_session.query(sql, sql)

    assert cols == ["@@VERSION", "@@HOSTNAME"]
    assert rows[0][0] == SYSTEM_VARIABLES["@@version"]
    assert rows[0][1] == SYSTEM_VARIABLES["@@hostname"]


@pytest.mark.asyncio
async def test_handle_table_select(mock_session):
    mock_session.current_db = "production_db"
    sql = "SELECT * FROM users"
    rows, cols = await mock_session.query(sql, sql)

    assert cols == DUMMY_DATABASES["production_db"]["users"]["columns"]
    assert len(rows) == len(DUMMY_DATABASES["production_db"]["users"]["rows"])


@pytest.mark.asyncio
async def test_handle_use_db(mock_session):
    sql = "USE production_db"
    rows, cols = await mock_session.query(sql, sql)
    assert mock_session.current_db == "production_db"
    assert rows == []

    sql2 = "USE other_db"
    rows, cols = await mock_session.query(sql2, sql2)
    assert mock_session.current_db == "other_db"


@pytest.mark.asyncio
async def test_fallback_to_llm(mock_session):
    # Complex query not handled locally
    sql = "SELECT * FROM unknown_table WHERE id > 5"

    mock_session.llm_interface.query.return_value = (
        '{"columns": ["id"], "rows": [[10]]}'
    )

    rows, cols = await mock_session.query(sql, sql)

    mock_session.llm_interface.query.assert_called_once()
    assert cols == ["id"]
    assert rows == [[10]]


@pytest.mark.asyncio
async def test_malformed_sql_fallback(mock_session):
    # Malformed SQL should ideally go to LLM or return error
    # Our code: try parse -> except -> llm
    sql = "SELECT * FROM"  # Incomplete

    mock_session.llm_interface.query.return_value = '{"columns": [], "rows": []}'

    rows, cols = await mock_session.query(sql, sql)

    # Verify it went to LLM
    mock_session.llm_interface.query.assert_called_once()
