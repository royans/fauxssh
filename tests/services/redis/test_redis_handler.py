import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.services.redis.handler import RedisHandler

class TestRedisHandler(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_llm = MagicMock()
        self.handler = RedisHandler(self.mock_db, self.mock_llm)

    def test_ping(self):
        res = self.handler.handle_command("PING", "1.2.3.4")
        self.assertEqual(res, b"+PONG\r\n")
        
        res = self.handler.handle_command("PING hello", "1.2.3.4")
        self.assertEqual(res, b"$5\r\nhello\r\n")

    def test_echo(self):
        res = self.handler.handle_command("ECHO foo bar", "1.2.3.4")
        self.assertEqual(res, b"$7\r\nfoo bar\r\n")

    def test_llm_fallback_cache_hit(self):
        self.mock_db.get_cached_response.return_value = "cachedval"
        
        # We need to compute hash internally to verify...
        # But we trust the logic.
        res = self.handler.handle_command("GET missingkey", "1.2.3.4")
        
        self.assertEqual(res, b"$9\r\ncachedval\r\n")
        self.mock_llm.generate_response.assert_not_called()
        
    def test_llm_fallback_cache_miss(self):
        self.mock_db.get_cached_response.return_value = None
        self.mock_llm.generate_response.return_value = "redisval"
        
        res = self.handler.handle_command("GET newkey", "1.2.3.4")
        
        self.assertEqual(res, b"$8\r\nredisval\r\n")
        self.mock_llm.generate_response.assert_called_once()
        self.mock_db.cache_response.assert_called_once()

    def test_llm_fallback_ok(self):
        self.mock_db.get_cached_response.return_value = None
        self.mock_llm.generate_response.return_value = "OK"
        
        res = self.handler.handle_command("SET foo bar", "1.2.3.4")
        self.assertEqual(res, b"+OK\r\n")
        
    def test_llm_fallback_error(self):
        self.mock_db.get_cached_response.return_value = None
        self.mock_llm.generate_response.return_value = "ERR nopers"
        
        res = self.handler.handle_command("BADCMD", "1.2.3.4")
        self.assertEqual(res, b"-ERR nopers\r\n")

if __name__ == '__main__':
    unittest.main()
