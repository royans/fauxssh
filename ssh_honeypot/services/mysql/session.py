import logging
import asyncio
from mysql_mimic.session import Session as MysqlSession
from mysql_mimic import ResultColumn, ColumnType
from ssh_honeypot.services.mysql.context import client_ip_ctx
from ssh_honeypot.services.mysql.dummy_data import SYSTEM_VARIABLES, DUMMY_DATABASES
import sqlglot
from sqlglot import exp
from ssh_honeypot.core.clogging import clogger

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
        import os

        self.session_id = os.urandom(8).hex()
        # Disable built-in middlewares that cause crashes with sqlglot
        self._middlewares = []

    async def init(self, connection):
        await super().init(connection)
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

        if not peername:
            stream = getattr(connection, "stream", None)
            if stream:
                # 1. Try asyncio get_extra_info on stream.writer
                writer = getattr(stream, "writer", None)
                if writer and hasattr(writer, "get_extra_info"):
                    peername = writer.get_extra_info("peername")

                # 2. Try get_extra_info on stream itself (older mysql-mimic)
                if not peername and hasattr(stream, "get_extra_info"):
                    peername = stream.get_extra_info("peername")

        # Context Fallback
        if not peername:
            ctx_ip = client_ip_ctx.get()
            if ctx_ip and ctx_ip != "0.0.0.0":
                peername = (ctx_ip, 0)

        self.client_address = peername
        if self.client_address:
            # Refresh context if we found a more specific one
            client_ip_ctx.set(self.client_address[0])

        # log.info(f"[*] MySQL Connection from {self.client_address}")

        # Start session in DB
        session_data = {
            "username": self.username or "unknown",
            "password": None,
            "client_version": "unknown",
            "fingerprint": "mysql",
        }
        clogger.log_event(
            "session_start",
            session_data,
            session_id=self.session_id,
            ip=self.client_address[0] if self.client_address else "unknown",
            protocol="mysql",
        )

    async def schema(self):
        """
        Provide the database schema for INFORMATION_SCHEMA queries.
        """
        schema_map = {}
        for db_name, tables in DUMMY_DATABASES.items():
            schema_map[db_name] = {}
            for table_name, table_data in tables.items():
                if "columns" in table_data:
                    cols = {col: "TEXT" for col in table_data["columns"]}
                    schema_map[db_name][table_name] = cols

        if "mysql" not in schema_map:
            schema_map["mysql"] = {}

        # Add basic mysql tables if needed
        return schema_map

    async def data(self):
        """
        Provide data for tables defined in schema().
        """
        data_map = {}
        for db_name, tables in DUMMY_DATABASES.items():
            if db_name == "information_schema":
                continue
            data_map[db_name] = {}
            for table_name, table_data in tables.items():
                data_map[db_name][table_name] = table_data["rows"]
        return data_map

    async def handle_query(self, sql, attrs):
        """
        Override handle_query to bypass the middleware chain which causes
        crashes in sqlglot due to missing functions or data.
        """
        log.debug(f"[MySQL] Handling query (bypassing middlewares): {sql}")
        expressions = self._parse(sql)
        if not expressions:
            return [], []

        last_result = ([], [])
        for expression in expressions:
            try:
                last_result = await self.query(expression, sql, attrs)
            except Exception as e:
                log.error(f"[MySQL] Error in query handling: {e}")
                # Fallback to empty result to prevent protocol crash
                last_result = ([], [])

        return last_result

    async def query(self, expression, sql, attrs):
        log.info(f"[MySQL] Query from {self.client_address}: {sql}")

        # NOTE: 'expression' is already a parsed sqlglot AST.
        # Do NOT call sqlglot.parse_one(expression) unless expression is string (it shouldn't be here)

        results = None

        # 1. Handle simple SELECTs locally
        if isinstance(expression, exp.Select):
            results = self._handle_local_select(expression)
            if results is None:
                # Check for FROM clause to handle table selects
                table_name = None
                for table in expression.find_all(exp.Table):
                    table_name = table.name
                    break

                if table_name:
                    results = self._handle_table_select(table_name)

        # 2. Handle USE command
        if results is None and isinstance(expression, exp.Use):
            db_name = expression.this.name
            # If it's an identifier, it might be quoted
            await self.use(db_name)  # Call the overridden use method
            results = [], []

        # 3. Handle SHOW commands (commonly used for discovery)
        if results is None and isinstance(expression, exp.Show):
            # Fallback to LLM for now, but we could handle common ones like 'SHOW TABLES'
            results = await self._llm_query(sql)

        # 4. Handle SET commands
        if results is None and isinstance(expression, exp.Set):
            # Assume success for SET commands (e.g. SET NAMES)
            results = [], []

        if results is None:
            results = await self._llm_query(sql)

        # Log Interaction with Result summary
        try:
            res_str = ""
            if results and len(results) > 0 and results[0]:
                rows = results[0]
                cols = results[1]
                # Format a small snippet of the result
                col_names = [getattr(c, "name", str(c)) for c in cols]
                res_str = f"Columns: {', '.join(col_names)}\nRows: {len(rows)}\nFirst Row: {rows[0] if rows else 'None'}"
            else:
                res_str = "Empty result set / Success"

            interaction_data = {
                "cwd": "mysql",
                "input": sql,
                "response": res_str,
                "source": "mysql",
            }
            clogger.log_event(
                "interaction",
                interaction_data,
                session_id=self.session_id,
                ip=self.client_address[0] if self.client_address else "unknown",
                protocol="mysql",
            )
        except Exception as le:
            log.error(f"[MySQL] Error logging results: {le}")
            interaction_data = {
                "cwd": "mysql",
                "input": sql,
                "response": None,
                "source": "mysql",
            }
            clogger.log_event(
                "interaction",
                interaction_data,
                session_id=self.session_id,
                ip=self.client_address[0] if self.client_address else "unknown",
                protocol="mysql",
            )

        return results

    def _parse(self, sql):
        try:
            # Default behavior
            return [e for e in self.dialect().parse(sql) if e]
        except sqlglot.errors.ParseError:
            # Fallback: Try splitting by newline if standard parse fails
            # This handles cases like "use mysql\nshow tables" without semicolons

            expressions = []
            parts = sql.split("\n")
            if len(parts) > 1:
                # Check if we can parse the parts individually
                all_valid = True
                temp_exprs = []
                for part in parts:
                    part = part.strip()
                    if not part:
                        continue
                    try:
                        parsed = self.dialect().parse(part)
                        if parsed:
                            temp_exprs.extend([e for e in parsed if e])
                    except:
                        all_valid = False
                        break

                if all_valid and temp_exprs:
                    log.debug(
                        f"[MySQL] Recovered {len(temp_exprs)} expressions by splitting newline"
                    )
                    return temp_exprs

            # Fallback to LLM for syntax errors (let LLM interpret "selet *")
            log.debug(
                f"[MySQL] Parse failed, returning raw fallback for LLM: {sql[:50]}..."
            )
            return [sqlglot.exp.Literal.string("SYNTAX_ERROR_FALLBACK")]

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

    async def use(self, database):
        self.current_db = database
        await super().use(database)

    def _handle_table_select(self, table_name):
        """Attempts to return data from dummy tables."""
        # Look in current DB
        # Use self.database if self.current_db isn't set, or prefer base class?
        # Base class `use` sets self.database.
        db_to_search = self.database or self.current_db or "production_db"

        db_data = DUMMY_DATABASES.get(db_to_search) or DUMMY_DATABASES.get(
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
            resp = self.llm_interface.query(prompt, protocol="mysql")
            # Clean and parse JSON
            import json
            import re

            # Extract JSON block
            match = re.search(r"\{.*\}", resp, re.DOTALL)
            if match:
                data = json.loads(match.group(0))
                rows = data.get("rows", [])
                cols_raw = data.get("columns", [])

                # Explicitly convert to ResultColumn to avoid inference bugs/limitations
                columns = [
                    ResultColumn(name=c, type=ColumnType.VAR_STRING) for c in cols_raw
                ]

                return rows, columns
            else:
                log.warning("[MySQL] LLM returned invalid format")
                return [], []
        except Exception as e:
            log.error(f"[MySQL] LLM Error: {e}")
            return [], []
