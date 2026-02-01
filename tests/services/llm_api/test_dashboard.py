import unittest
import sqlite3
import json
import time
import tempfile
import os
from ssh_honeypot.core.database import SQLiteBackend


class TestDashboardStats(unittest.TestCase):
    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(delete=False)
        self.tmp_db.close()
        self.db = SQLiteBackend(self.tmp_db.name)
        self.db._init_db()

    def tearDown(self):
        if hasattr(self, "tmp_db") and os.path.exists(self.tmp_db.name):
            os.unlink(self.tmp_db.name)

    def test_llm_stats_aggregation(self):
        # Insert raw interactions mimicking what OllamaHandler sends
        # Command = "POST /api/generate\n{...}"
        # Source = "llm-api"

        payload1 = json.dumps({"model": "llama3:latest", "prompt": "hi"})
        cmd1 = f"POST /api/generate\n{payload1}"

        payload2 = json.dumps({"model": "mistral:7b", "prompt": "hello"})
        cmd2 = f"POST /api/chat\n{payload2}"

        payload3 = json.dumps({"model": "llama3:latest", "prompt": "yo"})
        cmd3 = f"POST /api/chat\n{payload3}"

        # Insert directly into DB (bypassing clogging/slogging latency)
        # Use explicit UTC time to ensure it matches SQLite's datetime('now')
        from datetime import datetime, timedelta, timezone

        now_utc = datetime.now(timezone.utc)

        # log_interaction signature with named args
        self.db.log_interaction(
            "sess1", "/", cmd1, "resp", "llm-api", duration_ms=10, created_at=now_utc
        )
        self.db.log_interaction(
            "sess2", "/", cmd2, "resp", "llm-api", duration_ms=10, created_at=now_utc
        )
        self.db.log_interaction(
            "sess3", "/", cmd3, "resp", "llm-api", duration_ms=10, created_at=now_utc
        )

        # Insert a non-LLM interaction to ensure separation
        self.db.log_interaction(
            "sess4", "/", "ls -la", "total 0", "ssh", duration_ms=10, created_at=now_utc
        )

        # Verify Stats
        stats = self.db.get_infographic_stats(hours=1)

        # Debug print if empty
        if not stats.get("top_llm_models"):
            print("DEBUG: Stats Empty. Params:", stats.keys())
            conn = self.db._get_conn()
            curs = conn.cursor()
            curs.execute("SELECT timestamp, command, source FROM interactions")
            print("DB ROWS:", curs.fetchall())

        # 1. Check Top Models
        # llama3:latest = 2, mistral:7b = 1
        llm_models = stats.get("top_llm_models", [])
        self.assertEqual(len(llm_models), 2)

        # Convert to dict for easy check
        model_map = {x["item"]: x["count"] for x in llm_models}
        self.assertEqual(model_map.get("llama3:latest"), 2)
        self.assertEqual(model_map.get("mistral:7b"), 1)

        # 2. Check Top Endpoints
        # /api/chat = 2, /api/generate = 1
        llm_endpoints = stats.get("top_llm_endpoints", [])
        self.assertEqual(len(llm_endpoints), 2)

        endpoint_map = {x["item"]: x["count"] for x in llm_endpoints}
        self.assertEqual(endpoint_map.get("POST /api/chat"), 2)
        self.assertEqual(endpoint_map.get("POST /api/generate"), 1)


if __name__ == "__main__":
    unittest.main()
