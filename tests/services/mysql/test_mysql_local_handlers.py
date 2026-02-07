import unittest
from unittest.mock import MagicMock
from ssh_honeypot.services.mysql.session import HoneyMySQLSession
from ssh_honeypot.services.mysql.dummy_data import DUMMY_DATABASES, SYSTEM_VARIABLES


class MockLLM:
    def query(self, prompt, protocol="mysql"):
        return '{"columns": ["mock"], "rows": [["llm_fallback"]]}'


class TestMySQLLocalHandlers(unittest.IsolatedAsyncioTestCase):
    async def test_show_tables(self):
        session = HoneyMySQLSession(None, MockLLM(), {})
        session.current_db = "production_db"

        # Test SHOW TABLES
        results = await session.handle_query("SHOW TABLES", {})
        assert results is not None
        rows, cols = results

        # Verify columns
        assert len(cols) == 1
        # Accept either Tables_in_production_db or just Tables
        col_name = getattr(cols[0], "name", str(cols[0]))
        assert "Tables" in col_name

        # Verify rows (from dummy_data.py)
        # production_db has users, products, orders
        table_names = [r[0] for r in rows]
        assert "users" in table_names
        assert "products" in table_names
        assert "orders" in table_names

    async def test_show_databases(self):
        session = HoneyMySQLSession(None, MockLLM(), {})

        results = await session.handle_query("SHOW DATABASES", {})
        rows, cols = results

        db_names = [r[0] for r in rows]
        assert "information_schema" in db_names
        assert "production_db" in db_names
        assert "Database" in getattr(cols[0], "name", str(cols[0]))

    async def test_select_database(self):
        session = HoneyMySQLSession(None, MockLLM(), {})
        session.current_db = "production_db"

        results = await session.handle_query("SELECT DATABASE()", {})
        rows, cols = results

        assert rows[0][0] == "production_db"
        col_name = getattr(cols[0], "name", str(cols[0]))
        assert col_name in ("DATABASE()", "SCHEMA()")

    async def test_select_version(self):
        session = HoneyMySQLSession(None, MockLLM(), {})

        results = await session.handle_query("SELECT VERSION()", {})
        rows, cols = results

        expected = SYSTEM_VARIABLES["@@version"]
        assert rows[0][0] == expected

    async def test_select_variable(self):
        session = HoneyMySQLSession(None, MockLLM(), {})

        results = await session.handle_query("SELECT @@version", {})
        rows, cols = results

        expected = SYSTEM_VARIABLES["@@version"]
        assert rows[0][0] == expected

    async def test_show_variables(self):
        session = HoneyMySQLSession(None, MockLLM(), {})

        results = await session.handle_query("SHOW VARIABLES", {})
        rows, cols = results

        assert len(cols) == 2
        var_map = {r[0]: r[1] for r in rows}

        assert "version" in var_map
        assert var_map["version"] == SYSTEM_VARIABLES["@@version"]
        assert "hostname" in var_map

    async def test_fallback_to_llm(self):
        session = HoneyMySQLSession(None, MockLLM(), {})

        # Unknown command should fallback
        results = await session.handle_query("SELECT * FROM weird_table", {})
        rows, cols = results

        assert rows[0][0] == "llm_fallback"
