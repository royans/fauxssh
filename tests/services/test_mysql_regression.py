import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.mysql.server import HoneyMySQLHandler


class TestMySQLRegression(unittest.TestCase):
    @patch("ssh_honeypot.services.mysql.server.HoneyMySQLSession")
    @patch("ssh_honeypot.services.mysql.server.HoneyMySQLIdentityProvider")
    @patch("ssh_honeypot.services.mysql.server.MysqlServer.__init__")
    def test_server_version_set(self, mock_super_init, mock_identity, mock_session):
        # Setup
        mock_db = MagicMock()
        mock_llm = MagicMock()
        mock_config = {}

        # Init Handler
        handler = HoneyMySQLHandler(mock_db, mock_llm, mock_config)

        # Verify super().__init__ called with server_version
        self.assertTrue(mock_super_init.called)
        call_kwargs = mock_super_init.call_args[1]

        # Beekeeper Studio crash repro prevented if this is set
        self.assertIn("server_version", call_kwargs)
        self.assertIsNotNone(call_kwargs["server_version"])
        self.assertTrue(len(call_kwargs["server_version"]) > 0)
        print(f"Verified server_version is set to: {call_kwargs['server_version']}")


if __name__ == "__main__":
    unittest.main()
