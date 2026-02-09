import logging
import asyncio
import sqlite3
import sqlglot
from sqlglot import exp, transpile
from mysql_mimic.session import Session as MysqlSession
from mysql_mimic import ResultColumn, ColumnType
from ssh_honeypot.services.mysql.context import client_ip_ctx
from ssh_honeypot.services.mysql.dummy_data import SYSTEM_VARIABLES, DUMMY_DATABASES
from ssh_honeypot.core.clogging import clogger

log = logging.getLogger("ssh_honeypot.mysql.session")


class HoneyMySQLSession(MysqlSession):
    def __init__(self, honey_db, llm_interface, config):
        super().__init__()
        self.variables.set("version", "5.5.5-10.6.12-MariaDB", force=True)
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

        # Initialize in-memory SQLite DB for local handling
        self.sqlite_conn = sqlite3.connect(":memory:")
        self._init_sqlite_db()

    def _init_sqlite_db(self):
        """Populate in-memory SQLite with dummy data."""
        cursor = self.sqlite_conn.cursor()

        # Create schema and data
        for db_name, tables in DUMMY_DATABASES.items():
            if db_name == "information_schema":
                continue

            for table_name, data in tables.items():
                cols = data["columns"]
                rows = data["rows"]

                # Create Table
                # We treat everything as TEXT or REAL for simplicity in SQLite
                # unless we want to be specific.
                col_defs = ", ".join([f"{col} TEXT" for col in cols])
                create_sql = f"CREATE TABLE {table_name} ({col_defs})"
                try:
                    cursor.execute(create_sql)

                    # Insert Data
                    placeholders = ", ".join(["?"] * len(cols))
                    insert_sql = f"INSERT INTO {table_name} VALUES ({placeholders})"
                    cursor.executemany(insert_sql, rows)
                except Exception as e:
                    log.error(f"[MySQL] Init Error for {table_name}: {e}")

        self.sqlite_conn.commit()

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
        Provide the database schema for INFORMATION_SCHEMA queries (used by mysql-mimic).
        """
        # We still provide this so mysql-mimic knows about tables for basic routing,
        # even though we intercept most queries.
        schema_map = {}
        for db_name, tables in DUMMY_DATABASES.items():
            schema_map[db_name] = {}
            for table_name, table_data in tables.items():
                if "columns" in table_data:
                    # Map all to TEXT for mysql-mimic schema report
                    cols = {col: "TEXT" for col in table_data["columns"]}
                    schema_map[db_name][table_name] = cols

        if "mysql" not in schema_map:
            schema_map["mysql"] = {}

        return schema_map

    def _parse(self, sql):
        try:
            return [e for e in self.dialect().parse(sql) if e]
        except:
            return None

    async def handle_query(self, sql, attrs):
        """
        Overridden handle_query to ensure my custom logic is used
        and multi-statement queries are supported.
        """
        log.debug(f"[MySQL] Handling query: {sql}")

        # --- Payload Capture (MySQL) ---
        try:
            # We need to access payload_manager. Since it's not injected into session,
            # we rely on it being available via `self.honey_db` or instantiate it.
            # Ideally session receives it. But `HoneyMySQLSession` has `honey_db`.
            from ssh_honeypot.core.payload_manager import PayloadManager

            pm = PayloadManager(self.honey_db)
            pm.check_and_queue_text_payload(
                sql,
                self.session_id,
                self.client_address[0] if self.client_address else "unknown",
                source="MySQL",
            )
        except Exception as e:
            log.error(f"[MySQL] Payload Capture Error: {e}")
        # -------------------------------

        expressions = self._parse(sql)
        if expressions is None:
            return await self._llm_query(sql)

        last_result = ([], [])
        for expression in expressions:
            last_result = await self.query(expression, sql, attrs)
        return last_result

    async def query(self, expression, sql, attrs):
        """
        Handle query by either bypassing to local SQLite or forwarding to LLM.
        """
        from .dummy_data import SYSTEM_VARIABLES, DUMMY_DATABASES

        # 1. Handle common SELECT functions and variables locally
        # We check both the parsed expression and the raw SQL for robustness
        if isinstance(expression, exp.Select):
            # Try to identify SELECT @@var, @@var2, etc. or SELECT DATABASE()
            projections = expression.expressions
            if projections:
                row_data = []
                cols = []
                all_matched = True

                for proj in projections:
                    proj_sql = proj.sql(dialect="mysql").upper().strip()

                    # Special case for DATABASE() / SCHEMA()
                    if proj_sql in ("DATABASE()", "SCHEMA()"):
                        row_data.append(self.current_db)
                        cols.append(proj_sql)
                        continue

                    match = None
                    for key, val in SYSTEM_VARIABLES.items():
                        if proj_sql == key.upper():
                            match = (key.upper(), val)
                            break

                    if match:
                        row_data.append(match[1])
                        cols.append(match[0])
                    else:
                        all_matched = False
                        break

                if all_matched:
                    # Return results locally
                    return [tuple(row_data)], cols

        # 2. Handle USE
        if isinstance(expression, exp.Use):
            db_name = expression.this.name
            await self.use(db_name)
            return [], []

        # 3. Handle SELECT / INSERT / UPDATE / DELETE via SQLite
        if isinstance(expression, (exp.Select, exp.Insert, exp.Update, exp.Delete)):
            try:
                # Transpile MySQL -> SQLite
                sqlite_sql_list = transpile(
                    expression.sql(dialect="mysql"), read="mysql", write="sqlite"
                )
                if not sqlite_sql_list:
                    return await self._llm_query(expression.sql(dialect="mysql"))

                sqlite_sql = sqlite_sql_list[0]

                cursor = self.sqlite_conn.cursor()
                cursor.execute(sqlite_sql)

                if isinstance(expression, exp.Select):
                    rows = cursor.fetchall()
                    cols = []
                    if cursor.description:
                        # Return strings for test compatibility
                        cols = [c[0] for c in cursor.description]
                    self._log_interaction(
                        expression.sql(dialect="mysql"), f"Local: {len(rows)} rows"
                    )
                    return rows, cols
                else:
                    self.sqlite_conn.commit()
                    self._log_interaction(
                        expression.sql(dialect="mysql"), "Local Exec (Mutation)"
                    )
                    return [], []

            except Exception as e:
                log.warning(f"[MySQL] SQLite Local Exec Failed: {e}. Fallback to LLM.")
                return await self._llm_query(expression.sql(dialect="mysql"))

        # 4. Handle SHOW
        if isinstance(expression, exp.Show):
            res = self._handle_show(expression)
            if res:
                self._log_interaction(
                    expression.sql(dialect="mysql"), f"Local SHOW: {len(res[0])} rows"
                )
                return res

        # Fallback to LLM
        return await self._llm_query(expression.sql(dialect="mysql"))

    def _log_interaction(self, sql, response):
        interaction_data = {
            "cwd": "mysql",
            "input": sql,
            "response": response[:200] + "..." if len(response) > 200 else response,
            "source": "mysql",
        }
        clogger.log_event(
            "interaction",
            interaction_data,
            session_id=self.session_id,
            ip=self.client_address[0] if self.client_address else "unknown",
            protocol="mysql",
        )

    def _handle_show(self, expression):
        sql = expression.sql(dialect="mysql").upper()

        target = ""
        if "TABLES" in sql:
            target = "TABLES"
        elif "DATABASES" in sql or "SCHEMAS" in sql:
            target = "DATABASES"
        elif "COLUMNS" in sql or "FIELDS" in sql:
            target = "COLUMNS"
        elif "VARIABLES" in sql:
            target = "VARIABLES"

        if target == "TABLES":
            # List tables in SQLite
            cursor = self.sqlite_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            rows = cursor.fetchall()
            # Convert tuples to result
            # SHOW TABLES usually returns 1 col "Tables_in_XY"
            cols = [ResultColumn(f"Tables_in_{self.current_db}", ColumnType.VAR_STRING)]
            return rows, cols

        if target in ("DATABASES", "SCHEMAS"):
            rows = [(db,) for db in DUMMY_DATABASES.keys()]
            cols = [ResultColumn("Database", ColumnType.VAR_STRING)]
            return rows, cols

        if target == "COLUMNS":
            # SHOW COLUMNS FROM table
            import re

            m = re.search(r"FROM\s+([^\s]+)", sql, re.IGNORECASE)
            table = m.group(1).strip("`'\"") if m else None

            if table:
                cursor = self.sqlite_conn.cursor()
                try:
                    cursor.execute(f"PRAGMA table_info({table})")
                    pragma_rows = cursor.fetchall()
                    # SQLite PRAGMA table_info: (id, name, type, notnull, dflt_value, pk)
                    # MySQL SHOW COLUMNS: (Field, Type, Null, Key, Default, Extra)
                    rows = []
                    for pr in pragma_rows:
                        rows.append(
                            (
                                pr[1],  # Field
                                pr[2],  # Type
                                "NO" if pr[3] else "YES",  # Null
                                "PRI" if pr[5] else "",  # Key
                                pr[4],  # Default
                                "",  # Extra
                            )
                        )
                    cols = [
                        ResultColumn("Field", ColumnType.VAR_STRING),
                        ResultColumn("Type", ColumnType.VAR_STRING),
                        ResultColumn("Null", ColumnType.VAR_STRING),
                        ResultColumn("Key", ColumnType.VAR_STRING),
                        ResultColumn("Default", ColumnType.VAR_STRING),
                        ResultColumn("Extra", ColumnType.VAR_STRING),
                    ]
                    return rows, cols
                except:
                    return None

        if target == "VARIABLES":
            from .dummy_data import SYSTEM_VARIABLES

            rows = [
                (k.replace("@@", ""), v)
                for k, v in SYSTEM_VARIABLES.items()
                if k.startswith("@@")
            ]
            cols = [
                ResultColumn("Variable_name", ColumnType.VAR_STRING),
                ResultColumn("Value", ColumnType.VAR_STRING),
            ]
            return rows, cols

        return None

    async def use(self, database):
        self.current_db = database
        await super().use(database)

    async def _llm_query(self, sql):
        """Forwards query to LLM to generate plausible rows."""
        log.info(f"[MySQL] Forwarding to LLM: {sql}")

        # Prompt Engineering
        prompt = f"You are a MySQL server for a corporate 'production_db'. The current database is '{self.current_db}'. The user executed: SQL: {sql} Return the result set as a JSON object with 'columns' (list of strings) and 'rows' (list of lists of values). Make the data look realistic for a production enterprise environment. If the query is an UPDATE/INSERT/DELETE, return empty columns/rows but assume success. If the query contains syntax errors, return reasonable error or empty. JSON Format: {{ 'columns': ['id', 'name'], 'rows': [[1, 'admin'], [2, 'test']] }}"

        try:
            # Check if sync or async
            import inspect

            res = self.llm_interface.query(prompt, protocol="mysql")
            if inspect.isawaitable(res):
                resp = await res
            else:
                resp = res

            if not isinstance(resp, str):
                resp = str(resp)
            import json
            import re

            match = re.search(r"\{.*\}", resp, re.DOTALL)
            if match:
                data = json.loads(match.group(0))
                rows = data.get("rows", [])
                cols_raw = data.get("columns", [])

                # Explicitly convert to ResultColumn to avoid inference bugs/limitations
                # FIX: Ensure column names are strings to prevent 'int' object has no attribute 'encode' crash
                columns = [
                    ResultColumn(name=str(c), type=ColumnType.VAR_STRING)
                    for c in cols_raw
                ]

                self._log_interaction(sql, f"LLM: {len(rows)} rows")
                return rows, columns
            else:
                log.warning("[MySQL] LLM returned invalid format")
                return [], []
        except Exception as e:
            log.error(f"[MySQL] LLM Error: {e}")
            return [], []
