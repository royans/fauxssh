import pytest
import os
import subprocess
import time
import socket
import asyncio
from ssh_honeypot.services.mysql.server import HoneyMySQLHandler
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.config import config
from unittest.mock import MagicMock, patch, AsyncMock

import pytest_asyncio

# We need a way to spin up the server in a thread or process for the test
# But since our code is asyncio, we can use pytest-asyncio and run the server task


@pytest_asyncio.fixture
async def mysql_server_port(unused_tcp_port):
    """Starts the MySQL honeypot on a random port for testing."""
    db_mock = MagicMock(spec=HoneyDB)
    db_mock.validate_anti_harvesting.return_value = (True, "")
    llm_mock = AsyncMock()
    llm_mock.query.return_value = '{"columns": ["Field", "Type", "Null", "Key", "Default", "Extra"], "rows": [["amount", "decimal(10,2)", "YES", "", "NULL", ""]]}'

    db_mock.check_root_desperation.return_value = "ALLOW"

    # Start Server
    fake_config = {
        "mysql": {
            "port": unused_tcp_port,
            "enabled": True,
            "auth": {"allow_any": True, "allow_any_rate": 1.0, "weak_passwords": []},
        }
    }
    handler = HoneyMySQLHandler(db_mock, llm_mock, fake_config)

    async def run_server():
        try:
            # Bind to localhost to avoid 0.0.0.0 ambiguity if any
            await handler.serve(host="127.0.0.1", port=unused_tcp_port)
        except Exception as e:
            print(f"SERVER STARTUP ERROR: {e}")
            raise

    server_task = asyncio.create_task(run_server())

    # Wait for port to be open
    for i in range(100):  # 10 seconds
        try:
            with socket.create_connection(("127.0.0.1", unused_tcp_port), timeout=0.1):
                break
        except (ConnectionRefusedError, OSError):
            if i % 10 == 0:
                print(f"Waiting for MySQL port {unused_tcp_port}...")
            await asyncio.sleep(0.1)
    else:
        # Check task status
        if server_task.done():
            try:
                server_task.result()
            except Exception as e:
                pytest.fail(f"MySQL server task failed: {e}")
        pytest.fail("MySQL server failed to start (timeout)")

    yield unused_tcp_port

    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass


def is_mysql_client_available():
    import shutil

    return shutil.which("mysql") is not None


@pytest.mark.skipif(not is_mysql_client_available(), reason="mysql client not found")
@pytest.mark.asyncio
async def test_mysql_interactive_session(mysql_server_port):
    """
    Simulates a user connecting via 'mysql' command line client and running
    the sequence of commands requested by the user.
    """

    # Commands to execute
    # 1. Show databases
    # 2. Use production_db
    # 3. Show tables
    # 4. Insert row into users
    # 5. Delete row from users
    # 6. Select with Order By
    # 7. Select with Group By

    commands = [
        "SHOW DATABASES;",
        "USE production_db;",
        "SHOW TABLES;",
        "SELECT * FROM users;",
        "INSERT INTO users (id, username, role) VALUES (999, 'bad_actor', 'admin');",
        "SELECT * FROM users WHERE id=999;",
        "DELETE FROM users WHERE id=999;",
        "SELECT * FROM users WHERE id=999;",  # Should be empty
        "SELECT role, count(*) FROM users GROUP BY role;",
        "SELECT username FROM users ORDER BY username DESC;",
        "EXIT",
    ]

    # Prepare input for mysql client
    sql_script = "\n".join(commands)

    # Run mysql client
    # -h 127.0.0.1 -P port -u test -ptest
    cmd = [
        "mysql",
        "-h",
        "127.0.0.1",
        "-P",
        str(mysql_server_port),
        "-u",
        "test",
        "-ptest",
        "--batch",  # Tabular output, easier to parse/check
        "--default-character-set=utf8",
    ]

    # Since the server is running in the asyncio loop, we need to run subprocess blocking
    # but verify it finishes.
    # Use subprocess.run

    print(f"Connecting to MySQL on port {mysql_server_port}...")

    # We execute this inside the async test, which blocks the loop if we use subprocess.run
    # But since the server is an asyncio Task, we need to let the loop run.
    # So we run the subprocess in an executor.

    loop = asyncio.get_running_loop()

    def run_client():
        return subprocess.run(
            cmd, input=sql_script.encode("utf-8"), capture_output=True, timeout=10
        )

    result = await loop.run_in_executor(None, run_client)

    output = result.stdout.decode("utf-8")
    stderr = result.stderr.decode("utf-8")

    print("--- MySQL Client Output ---")
    print(output)
    print("--- MySQL Client Stderr ---")
    print(stderr)

    assert result.returncode == 0, f"MySQL client failed: {stderr}"

    # Verification
    assert "production_db" in output
    assert "users" in output
    assert "products" in output

    # Verify INSERT/SELECT
    # We inserted bad_actor, then selected it. It should appear.
    # But then we deleted it.
    # The output is concatenated.
    # Let's check if 'bad_actor' appears.
    assert "bad_actor" in output

    # Verify GROUP BY output (role count)
    # in dummy_data.py users:
    # 1: admin
    # 2: service
    # 3: user
    # + 1 inserted admin (bad_actor)
    # So we expect 'admin' count to be at least 1, maybe 2 if the GROUP BY ran before DELETE?
    # Commands sequence:
    # ... INSERT ...
    # SELECT ... (shows bad_actor)
    # DELETE ...
    # SELECT ... (should not show bad_actor)
    # GROUP BY ... (admin count should be 1 again)

    # Actually checking exact counts is hard with --batch output concatenation
    # But we can check that the SQL didn't error.

    # Verify ORDER BY
    # jdoe, deploy, admin -> sorted desc: jdoe, deploy, admin
    # Check for presence
    assert "jdoe" in output

    # Verify SHOW COLUMNS didn't crash (implicit check if script finished)
    # Let's explicitly add SHOW COLUMNS

    # We iterate again with a separate check for SHOW COLUMNS just to be sure


@pytest.mark.skipif(not is_mysql_client_available(), reason="mysql client not found")
@pytest.mark.asyncio
async def test_mysql_show_columns_crash(mysql_server_port):
    """Verifies SHOW COLUMNS does not crash the server."""
    cmd = [
        "mysql",
        "-h",
        "127.0.0.1",
        "-P",
        str(mysql_server_port),
        "-u",
        "test",
        "-ptest",
        "-e",
        "USE production_db; SHOW COLUMNS FROM orders;",
    ]

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: subprocess.run(cmd, capture_output=True, timeout=5)
    )

    assert result.returncode == 0
    output = result.stdout.decode()
    assert "Field" in output
    assert "amount" in output  # Column in orders
