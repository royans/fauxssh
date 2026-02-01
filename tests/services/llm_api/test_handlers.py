import unittest
import threading
import http.client
import json
import time
from unittest.mock import MagicMock, patch


class TestLLMApiBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1. Patch Config
        cls.patcher_config = patch("ssh_honeypot.core.config.config")
        cls.mock_config = cls.patcher_config.start()

        # Setup robust mock_get
        def mock_get(*args, **kwargs):
            arg_str = str(args)
            if "fake_models" in arg_str:
                return ["llama3:latest", "mistral:latest"]
            if "enabled" in arg_str:
                return True
            # Port is dynamic, handled by ephemeral logic or specific return if asked
            # But server starts with explicitly passed port. Config port is only for verification if needed.
            return kwargs.get("default", None)

        cls.mock_config.get.side_effect = mock_get

        # 2. Patch EventLogger
        cls.patcher_event_logger = patch("ssh_honeypot.core.event_logger.EventLogger")
        cls.patcher_event_logger.start()

        # 3. Patch the global 'clogger' instance to be safe (for handlers using it)
        cls.patcher_clogger = patch("ssh_honeypot.core.clogging.clogger")
        cls.patcher_clogger.start()

    @classmethod
    def tearDownClass(cls):
        cls.patcher_config.stop()
        cls.patcher_event_logger.stop()
        cls.patcher_clogger.stop()


class TestOllamaAPI(TestLLMApiBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from ssh_honeypot.services.llm_api.ollama_handler import OllamaHandler
        from ssh_honeypot.services.llm_api.server import ThreadingHTTPServer

        # Use Port 0 for ephemeral
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), OllamaHandler)
        cls.port = cls.server.server_address[1]  # Get assigned port

        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        super().tearDownClass()

    def test_tags_endpoint(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/api/tags")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        data = json.load(resp)
        self.assertIn("models", data)
        conn.close()

    def test_generate_endpoint_streaming(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        payload = json.dumps({"model": "test-gen", "prompt": "123", "stream": True})
        conn.request("POST", "/api/generate", payload)
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Transfer-Encoding"), "chunked")
        body = resp.read().decode()
        self.assertIn("done", body)
        conn.close()


class TestOpenAIAPI(TestLLMApiBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from ssh_honeypot.services.llm_api.openai_handler import OpenAIHandler
        from ssh_honeypot.services.llm_api.server import ThreadingHTTPServer

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), OpenAIHandler)
        cls.port = cls.server.server_address[1]

        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        super().tearDownClass()

    def test_chat_completions_sse(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        payload = json.dumps(
            {
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
            }
        )
        conn.request("POST", "/v1/chat/completions", payload)
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Type"), "text/event-stream")
        body = resp.read().decode()
        self.assertIn("data: [DONE]", body)
        conn.close()

    def test_options_cors(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("OPTIONS", "/v1/chat/completions")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Access-Control-Allow-Origin"), "*")
        conn.close()
