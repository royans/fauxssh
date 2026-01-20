import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio
from ssh_honeypot.services.mysql.server import HoneyMySQLHandler, client_ip_ctx


def test_mysql_client_connected_cb():
    """
    Integration-style test for HoneyMySQLHandler._client_connected_cb.
    Verifies that the method is asynchronous, sets the IP context, and awaits the superclass.
    Uses asyncio.run() to be compatible with environments lacking pytest-asyncio auto-mode.
    """

    async def _test():
        # Mock dependencies
        mock_db = MagicMock()
        mock_llm = MagicMock()
        mock_config = {}

        # Instantiate handler
        handler = HoneyMySQLHandler(mock_db, mock_llm, mock_config)

        # Mock reader and writer
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.get_extra_info.return_value = ("1.2.3.4", 12345)

        # We need to mock the superclass _client_connected_cb since it starts the protocol
        # and would attempt to create real streams/sessions.
        with patch(
            "mysql_mimic.server.MysqlServer._client_connected_cb",
            new_callable=AsyncMock,
        ) as mock_super_cb:
            # Run the callback
            await handler._client_connected_cb(mock_reader, mock_writer)

            # 1. Verify IP context was set correctly
            assert client_ip_ctx.get() == "1.2.3.4"

            # 2. Verify super()._client_connected_cb was awaited (CRITICAL for the fix)
            mock_super_cb.assert_awaited_once_with(mock_reader, mock_writer)

    asyncio.run(_test())


if __name__ == "__main__":
    test_mysql_client_connected_cb()
    print("Test Passed!")
