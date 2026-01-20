import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from ssh_honeypot.services.mysql.session import HoneyMySQLSession
from ssh_honeypot.services.mysql.dummy_data import SYSTEM_VARIABLES, DUMMY_DATABASES
import sqlglot
from sqlglot import exp
from mysql_mimic import ResultColumn, ColumnType


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
    # Mock LLM to return list for query() simulation
    # _llm_query returns (rows, columns)
    # The session._llm_query calls llm.query() which returns JSON string.
    # The session._llm_query then processes it.

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

    rows, cols = await mock_session.query(parsed, sql, {})

    # Cols could be ResultColumn objects or strings.
    # Logic in session.py line 217: return [tuple(row)], columns
    # where columns is list of strings (alias_or_name or key)

    assert [c for c in cols] == ["@@VERSION"]
    assert rows[0][0] == SYSTEM_VARIABLES["@@version"]


@pytest.mark.asyncio
async def test_handle_local_select_multiple(mock_session):
    # Test SELECT @@version, @@hostname
    sql = "SELECT @@version, @@hostname"
    parsed = sqlglot.parse_one(sql)
    rows, cols = await mock_session.query(parsed, sql, {})

    assert [c for c in cols] == ["@@VERSION", "@@HOSTNAME"]
    assert rows[0][0] == SYSTEM_VARIABLES["@@version"]
    assert rows[0][1] == SYSTEM_VARIABLES["@@hostname"]


@pytest.mark.asyncio
async def test_handle_table_select(mock_session):
    mock_session.current_db = "production_db"
    sql = "SELECT * FROM users"
    parsed = sqlglot.parse_one(sql)
    rows, cols = await mock_session.query(parsed, sql, {})

    # _handle_table_select returns (rows, columns) from DUMMY_DATABASES directly
    # DUMMY_DATABASES["production_db"]["users"]["columns"] is ["id", "username", ...] (strings)

    assert cols == DUMMY_DATABASES["production_db"]["users"]["columns"]
    assert len(rows) == len(DUMMY_DATABASES["production_db"]["users"]["rows"])


@pytest.mark.asyncio
async def test_handle_use_db(mock_session):
    sql = "USE production_db"
    parsed = sqlglot.parse_one(sql)
    rows, cols = await mock_session.query(parsed, sql, {})
    assert mock_session.current_db == "production_db"
    assert rows == []

    sql2 = "USE other_db"
    parsed2 = sqlglot.parse_one(sql2)
    rows, cols = await mock_session.query(parsed2, sql2, {})
    assert mock_session.current_db == "other_db"


@pytest.mark.asyncio
async def test_fallback_to_llm(mock_session):
    # Complex query not handled locally
    sql = "SELECT * FROM unknown_table WHERE id > 5"
    parsed = sqlglot.parse_one(sql)

    # _llm_query logic:
    # calls llm_interface.query -> returns JSON string
    # parses JSON
    # returns rows (list of lists) and columns (list of ResultColumn objects with type VAR_STRING)

    # We mocked llm_interface.query to return '{"columns": ["fake"], "rows": [["data"]]}' in fixture
    # But let's override for this test
    mock_session.llm_interface.query.return_value = (
        '{"columns": ["id"], "rows": [[10]]}'
    )

    rows, cols = await mock_session.query(parsed, sql, {})

    mock_session.llm_interface.query.assert_called_once()

    # Check that cols are ResultColumn objects
    assert len(cols) == 1
    assert isinstance(cols[0], ResultColumn)
    assert cols[0].name == "id"
    assert cols[0].type == ColumnType.VAR_STRING

    assert rows == [[10]]


@pytest.mark.asyncio
async def test_malformed_sql_fallback(mock_session):
    # Malformed SQL should ideally go to LLM or return error
    # Our code: mysql-mimic calls parse(), if ParseError, it calls query() with a fallback (Wait, mysql-mimic handles parse errors?)
    # Session._parse handles parse errors and returns special objects or empty list?
    # Actually Session._parse (which we override) returns list of expressions.
    # If parse error, we implemented fallback in _parse to split by newline or something.
    # But here we are calling query() directly.

    sql = "SELECT * FROM"  # Incomplete

    # If we pass explicit expression (as if parser managed to produce something or we force it)
    # But if sql is malformed, sqlglot.parse_one might fail.
    # The test intent is: verify unexpected/unparseable queries go to LLM.
    # If we pass None as expression (simulating parse failure if logic allowed)?
    # Or just pass a dummy expression that isn't Select/Use.

    # Let's verify what happens if we pass a random expression
    parsed = sqlglot.exp.Literal.string("whatever")  # Just some expression

    mock_session.llm_interface.query.return_value = '{"columns": [], "rows": []}'

    rows, cols = await mock_session.query(parsed, sql, {})

    # Verify it went to LLM because parsed is not Select or Use
    mock_session.llm_interface.query.assert_called_once()
