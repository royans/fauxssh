import logging
import asyncio
from mysql_mimic.session import Session as MysqlSession
from ssh_honeypot.services.mysql.context import client_ip_ctx
from ssh_honeypot.services.mysql.dummy_data import SYSTEM_VARIABLES, DUMMY_DATABASES
import sqlglot
from sqlglot import exp

log = logging.getLogger("ssh_honeypot")


class HoneyMySQLSession(MysqlSession):
    def __init__(self, honey_db, llm_interface, config):
        super().__init__()
        self.honey_db = honey_db
        self.llm_interface = llm_interface
        self.config = config
        self.username = None
        self.current_db = "production_db"
        self.client_address = "unknown"

    async def init(self, connection):
        # We can access connection info here
        # Defensive attribute access for different mysql-mimic versions
        peername = None

        # Try writer (asyncio standard)
        writer = getattr(connection, "writer", None)
        if writer:
            peername = writer.get_extra_info("peername")

        # Try reader
        if not peername:
            reader = getattr(connection, "reader", None)
            if reader:
                peername = reader.get_extra_info("peername")

        # Try direct access (if Connection wraps transport or has helper)
        if not peername and hasattr(connection, "get_extra_info"):
            peername = connection.get_extra_info("peername")

        # Try 'stream' attribute (common in mysql-mimic)
        if not peername:
            stream = getattr(connection, "stream", None)
            if stream and hasattr(stream, "get_extra_info"):
                peername = stream.get_extra_info("peername")

        # Try accessing _writer (sometimes private) as last resort
        if not peername:
            _writer = getattr(connection, "_writer", None)
            if _writer and hasattr(_writer, "get_extra_info"):
                peername = _writer.get_extra_info("peername")

        self.client_address = peername
        if self.client_address:
            client_ip_ctx.set(self.client_address[0])
        else:
            log.warning(
                f"[MySQL] Could not determine client IP from connection: {dir(connection)}"
            )

        log.info(f"[*] MySQL Connection from {self.client_address}")

    async def query(self, expression, sql):
        log.info(f"[MySQL] Query from {self.client_address}: {sql}")

        # 1. Parse SQL
        try:
            parsed = sqlglot.parse_one(expression)
        except Exception as e:
            log.debug(f"[MySQL] Parse Error (falling back to LLM): {e}")
            return await self._llm_query(sql)

        # 2. Handle simple SELECTs locally
        if isinstance(parsed, exp.Select):
            # Check for system variables like SELECT @@version
            # Simple heuristic: look for expressions that are just variables or functions we know
            results = self._handle_local_select(parsed)
            if results is not None:
                return results

            # Check for FROM clause to handle table selects
            table_name = None
            for table in parsed.find_all(exp.Table):
                table_name = table.name
                break

            if table_name:
                results = self._handle_table_select(table_name)
                if results is not None:
                    return results

        # 3. Handle USE database
        if isinstance(parsed, exp.Use):
            db_name = parsed.this.name
            self.current_db = db_name
            return [], []

        # 4. Fallback to LLM for everything else (complex selects, updates, etc)
        return await self._llm_query(sql)

    def _handle_local_select(self, parsed):
        """Attempts to handle SELECT statements purely with local variables."""
        # This is a simplification. We look for projections (select expressions)
        # and see if we map them to our SYSTEM_VARIABLES.

        # Build columns and row
        row = []
        columns = []

        for expression in parsed.expressions:
            # sqlglot expression -> string representation roughly
            # e.g. @@version -> "@@version"
            # CURRENT_USER() -> "CURRENT_USER()"

            key = expression.sql(dialect="mysql").upper()

            # Normalize key checks
            val = None
            for sys_k, sys_v in SYSTEM_VARIABLES.items():
                if sys_k.upper() == key or sys_k.upper() == key.replace(
                    "@@SESSION.", "@@"
                ).replace("@@GLOBAL.", "@@"):
                    val = sys_v
                    break

            if val is not None:
                columns.append(expression.alias_or_name or key)
                row.append(val)
            else:
                # If ANY column is unknown, we abort local handling for safety
                # unless it's just a constant?
                # For now, abort to allow mixed queries to go to LLM or fail gracefully
                return None

        return [tuple(row)], columns

    def _handle_table_select(self, table_name):
        """Attempts to return data from dummy tables."""
        # Look in current DB
        db_data = DUMMY_DATABASES.get(self.current_db) or DUMMY_DATABASES.get(
            "production_db"
        )
        if not db_data:
            return None

        table_data = db_data.get(table_name)
        if table_data:
            return table_data["rows"], table_data["columns"]

        # Try information_schema mapping as fallback
        if self.current_db == "information_schema" or table_name.lower() == "tables":
            # Special case for 'show tables' which often maps to SELECT ... FROM information_schema.tables
            # But sqlglot might show 'SHOW TABLES' as a command?
            # Mimic handles show tables automatically? No, we impl query.
            # If table_name is tables, return schema
            return (
                DUMMY_DATABASES["information_schema"]["tables"]["rows"],
                DUMMY_DATABASES["information_schema"]["tables"]["columns"],
            )

        return None

    async def _llm_query(self, sql):
        """Forwards query to LLM to generate plausible rows."""
        log.info(f"[MySQL] Forwarding to LLM: {sql}")

        # Prompt Engineering
        prompt = f"""
        You are a MySQL server for a corporate 'production_db'. 
        The current database is '{self.current_db}'.
        
        The user executed:
        SQL: {sql}
        
        Return the result set as a JSON object with 'columns' (list of strings) and 'rows' (list of lists of values).
        Make the data look realistic for a production enterprise environment.
        If the query is an UPDATE/INSERT/DELETE, return empty columns/rows but assume success.
        If the query contains syntax errors, return reasonable error or empty.
        
        JSON Format:
        {{
            "columns": ["id", "name"],
            "rows": [[1, "admin"], [2, "test"]]
        }}
        """

        try:
            resp = self.llm_interface.query(prompt)
            # Clean and parse JSON
            import json
            import re

            # Extract JSON block
            match = re.search(r"\{.*\}", resp, re.DOTALL)
            if match:
                data = json.loads(match.group(0))
                return data.get("rows", []), data.get("columns", [])
            else:
                log.warning("[MySQL] LLM returned invalid format")
                return [], []
        except Exception as e:
            log.error(f"[MySQL] LLM Error: {e}")
            return [], []
