from .db_schema import TABLE_SCHEMAS, INDEXES, ORPHAN_TABLES
from .logging_setup import log


def sync_db_schema(backend):
    """
    Synchronizes the database schema for the given backend.
    Works for both SQLite and Postgres.
    """
    is_postgres = backend.is_postgres

    # Get a connection and cursor from the backend
    if hasattr(backend, "_get_conn"):
        conn = backend._get_conn()
    else:
        # Fallback if the backend doesn't expose _get_conn
        log.error(
            f"[DB] Backend {backend.__class__.__name__} does not expose _get_conn"
        )
        return

    try:
        cursor = conn.cursor()

        # Step 0: Cleanup Orphan Tables (Legacy)
        for table_name in ORPHAN_TABLES:
            try:
                cursor.execute(f"DROP TABLE IF EXISTS {table_name} CASCADE")
                log.info(f"[DB] Dropped legacy orphan table: {table_name}")
            except Exception as e:
                # If cascade is not supported (SQLite), try without it
                try:
                    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
                    log.info(
                        f"[DB] Dropped legacy orphan table (No CASCADE): {table_name}"
                    )
                except Exception as e2:
                    log.warning(f"[DB] Failed to drop legacy table {table_name}: {e2}")

        # Apply SQLite-specific optimizations if needed
        if not is_postgres:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous = NORMAL;")
            cursor.execute("PRAGMA busy_timeout = 30000;")

        for table_name, schema in TABLE_SCHEMAS.items():
            cols = schema.copy()
            primary_keys = cols.pop("PRIMARY_KEY", None)

            col_defs = []
            for col_name, col_type in cols.items():
                # Map abstracted types
                final_type = col_type
                if col_type == "SERIAL_PRIMARY_KEY":
                    final_type = (
                        "SERIAL PRIMARY KEY"
                        if is_postgres
                        else "INTEGER PRIMARY KEY AUTOINCREMENT"
                    )
                elif col_type == "TIMESTAMP":
                    final_type = "TIMESTAMP" if is_postgres else "DATETIME"
                elif col_type == "BOOLEAN":
                    final_type = "BOOLEAN" if is_postgres else "BOOLEAN"

                col_defs.append(f"{col_name} {final_type}")

            pk_clause = ""
            if primary_keys:
                pk_clause = f", PRIMARY KEY ({', '.join(primary_keys)})"

            create_stmt = f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(col_defs)}{pk_clause})"
            cursor.execute(create_stmt)

            # Step 2: Ensure all columns exist (Migration)
            for col_name, col_type in cols.items():
                if "PRIMARY KEY" in col_type:
                    continue

                # Check if column exists
                if is_postgres:
                    cursor.execute(
                        f"""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name='{table_name}' AND column_name='{col_name}'
                    """
                    )
                else:
                    cursor.execute(f"PRAGMA table_info({table_name})")
                    columns = [row[1] for row in cursor.fetchall()]
                    if col_name in columns:
                        continue
                    # Force a "missing" state for the logic below
                    cursor.execute("SELECT 1 WHERE 1=0")

                if not cursor.fetchone():
                    log.info(
                        f"[DB] Adding missing column {col_name} to table {table_name}"
                    )
                    final_type = col_type
                    if col_type == "TIMESTAMP":
                        final_type = "TIMESTAMP" if is_postgres else "DATETIME"
                    elif col_type == "BOOLEAN" and not is_postgres:
                        final_type = "BOOLEAN DEFAULT 0"

                    try:
                        cursor.execute(
                            f"ALTER TABLE {table_name} ADD COLUMN {col_name} {final_type}"
                        )
                    except Exception as e:
                        log.warning(
                            f"[DB] Could not add column {col_name} to {table_name}: {e}"
                        )

        # Step 3: Ensure indexes exist
        for table_name, columns, index_name in INDEXES:
            if isinstance(columns, list):
                cols_str = ", ".join(columns)
            else:
                cols_str = columns

            cursor.execute(
                f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name}({cols_str})"
            )

        conn.commit()
        log.info("[DB] Schema synchronization complete")

    except Exception as e:
        log.error(f"[DB] Error synchronizing schema: {e}")
        conn.rollback()
    finally:
        conn.close()
