import asyncio
from mysql_mimic.session import Session
from mysql_mimic import ResultColumn, ColumnType
from mysql_mimic.packets import make_column_definition_41

# Mocking the crash scenario
# The traceback indicates the error happens in make_column_definition_41 during encode.
# This function is used to send the Column Definition packet, which describes a column IN THE RESULT SET.
# However, if SHOW COLUMNS is executed, the "result set" describes the table's columns.
# So the "columns" of the result set are: Field, Type, Null, Key, Default, Extra.

# If the LLM returns a row for SHOW COLUMNS where one of these values is an integer,
# and mysql_mimic tries to encode it as a string (because it thinks it's a string column), it might crash?

# Actually, the traceback says:
# File "/usr/local/lib/python3.13/site-packages/mysql_mimic/packets.py", line 366, in make_column_definition_41
#    str_len(server_charset.encode(name)),
# AttributeError: 'int' object has no attribute 'encode'

# 'name' here refers to the column name (or alias, or original name, etc).
# If we pass a ResultColumn where 'name' is an integer, this would crash.


async def reproduce():
    print("Attempting to reproduce crash with Integer column name...")
    try:
        # Scenario 1: LLM returns a column name as an integer
        # e.g. "columns": ["id", 123]  <-- 123 is the issue
        # HoneyMySQLSession code:
        # columns = [ResultColumn(name=c, type=ColumnType.VAR_STRING) for c in cols_raw]

        bad_col_name = 123
        # In mysql_mimic, ResultColumn(name=...) expects name to be a string.
        # If we pass an int, it might store it, but crash later when encoding.

        col = ResultColumn(name=bad_col_name, type=ColumnType.VAR_STRING)

        # Simulate what mysql-mimic does internally when sending packet
        # It calls make_column_definition_41(col, ...)

        # We need a dummy charset that has an .encode() method, or use the real one if we can import
        class MockCharset:
            def encode(self, v):
                return v.encode("utf-8")

        print(
            f"Creating ResultColumn with name={bad_col_name} (type {type(bad_col_name)})"
        )

        # This calls the suspect function
        # We need to mock the sequence_id and encoding
        packet = make_column_definition_41(col, 1, MockCharset())
        print("Success? Packet created:", packet)

    except AttributeError as e:
        print(f"\n[CRASH REPRODUCED] Caught expected error: {e}")
    except Exception as e:
        print(f"\n[Different Error] {e}")


if __name__ == "__main__":
    asyncio.run(reproduce())
