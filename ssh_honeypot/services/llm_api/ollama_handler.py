import http.server
import json
import time
import hashlib
import random
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from ssh_honeypot.core.clogging import clogger
from ssh_honeypot.core.universal_cache import universal_cache


class OllamaHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def get_client_ip(self):
        # Respect X-Forwarded-For if behind proxy
        headers = getattr(self, "headers", None)
        if headers:
            x_fwd = headers.get("X-Forwarded-For")
            if x_fwd:
                return x_fwd.split(",")[0].strip()
        return self.client_address[0]

    def log_message(self, format, *args):
        # Silence default logging to reduce noise, use core logger instead
        pass

    def do_POST(self):
        if self.path == "/api/generate":
            self.handle_generate()
        elif self.path == "/api/chat":
            self.handle_chat()
        elif self.path == "/api/pull" or self.path == "/api/push":
            # Attackers might try to pull images.
            self.handle_model_op()
        else:
            self.send_error(404, "Not Found")

    def do_GET(self):
        if self.path == "/api/tags":
            self.handle_tags()
        elif self.path == "/":
            # Health check often used by clients
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Ollama is running")
        else:
            self.send_error(404, "Not Found")

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def handle_tags(self):
        """Returns the list of available (fake) models."""
        try:
            fake_models = config.get("llm_api", "ollama", "fake_models") or [
                "llama3:latest"
            ]

            models_data = []
            for m in fake_models:
                models_data.append(
                    {
                        "name": m,
                        "model": m,
                        "modified_at": "2023-11-04T12:00:00Z",
                        "size": 4000000000,
                        "digest": hashlib.sha256(m.encode()).hexdigest(),
                        "details": {
                            "parent_model": "",
                            "format": "gguf",
                            "family": "llama",
                            "families": ["llama"],
                            "parameter_size": "7B",
                            "quantization_level": "Q4_0",
                        },
                    }
                )

            resp = {"models": models_data}
            body = json.dumps(resp).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

            # Log simple interaction
            self._log_interaction(
                "GET /api/tags", None, f"[List Models: {len(fake_models)} items]"
            )

        except Exception as e:
            log.error(f"[Ollama] Error in handle_tags: {e}")
            self.send_error(500)

    def handle_model_op(self):
        """Handles Pull/Push requests generally."""
        # Generic success for pull to simulate presence
        # Log payload
        body = self._read_body()
        resp = {"status": "success"}
        self._send_json(resp)
        self._log_interaction(
            f"POST {self.path}",
            body.decode("utf-8", errors="ignore"),
            "[Simulated Success]",
        )

    def handle_generate(self):
        """Handles /api/generate commands."""
        body_bytes = self._read_body()
        if not body_bytes:
            return

        try:
            payload = json.loads(body_bytes)
            model = payload.get("model", "unknown")
            prompt = payload.get("prompt", "")
            stream = payload.get("stream", True)

            # Log the payload (Harvesting!)
            combined_input = f"POST /api/generate\n{json.dumps(payload)}"
            input_hash = hashlib.md5(combined_input.encode()).hexdigest()

            # 1. Check Cache
            cached = universal_cache.get("llm_api_ollama", input_hash)
            if cached:
                log.info(f"[Ollama] Cache Hit for {input_hash[:8]}")
                # We still stream the cached response for immersion
                self._stream_response(model, cached["output_text"])
                return

            self._log_interaction(
                "POST /api/generate",
                json.dumps(payload),
                f"[Streaming Response] Model: {model}",
                metadata={"model": model},
                input_hash=input_hash,
            )

            if stream:
                self._stream_response(
                    model, input_for_cache=combined_input, input_hash=input_hash
                )
            else:
                resp = {
                    "model": model,
                    "created_at": "2023-01-01T00:00:00Z",
                    "response": "Analysis complete. System secure.",
                    "done": True,
                    "context": [1, 2, 3],
                    "total_duration": 1000000,
                }
                self._send_json(resp)

        except Exception as e:
            log.error(f"[Ollama] Generate Error: {e}")
            self.send_error(500)

    def handle_chat(self):
        """Handles /api/chat commands."""
        body_bytes = self._read_body()
        if not body_bytes:
            return

        try:
            payload = json.loads(body_bytes)
            model = payload.get("model", "unknown")
            messages = payload.get("messages", [])
            stream = payload.get("stream", True)

            # Log payload
            combined_input = f"POST /api/chat\n{json.dumps(payload)}"
            input_hash = hashlib.md5(combined_input.encode()).hexdigest()

            # 1. Check Cache
            cached = universal_cache.get("llm_api_ollama", input_hash)
            if cached:
                log.info(f"[Ollama] Cache Hit for {input_hash[:8]}")
                self._stream_chat_response(model, cached["output_text"])
                return

            self._log_interaction(
                "POST /api/chat",
                json.dumps(payload),
                f"[Streaming Response] Model: {model}",
                metadata={"model": model},
                input_hash=input_hash,
            )

            if stream:
                self._stream_chat_response(
                    model, input_for_cache=combined_input, input_hash=input_hash
                )
            else:
                resp = {
                    "model": model,
                    "created_at": "2023-01-01T00:00:00Z",
                    "message": {
                        "role": "assistant",
                        "content": "I cannot verify that information.",
                    },
                    "done": True,
                }
                self._send_json(resp)

        except Exception as e:
            log.error(f"[Ollama] Chat Error: {e}")
            self.send_error(500)

    def _read_body(self):
        try:
            cl = int(self.headers.get("Content-Length", 0))
            if cl > 0:
                # Cap max read strict
                if cl > 2_000_000:  # 2MB limit
                    self.send_error(413, "Payload Too Large")
                    return None
                return self.rfile.read(cl)
        except:
            pass
        return b""

    def _send_json(self, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _stream_response(
        self, model, cached_response=None, input_for_cache=None, input_hash=None
    ):
        """Simulate NDJSON streaming for generate."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        if cached_response:
            # If we have a cached response, we split it by words to simulate streaming
            words = []
            import re

            for match in re.finditer(r"\S+\s*", cached_response):
                words.append(match.group(0))
        else:
            # Dummy stream content
            words = [
                "I",
                " ",
                "have",
                " ",
                "analyzed",
                " ",
                "the",
                " ",
                "request",
                ".",
                " ",
                "System",
                " ",
                "is",
                " ",
                "functioning",
                ".",
            ]

        full_response = ""
        for w in words:
            full_response += w
            chunk = {
                "model": model,
                "created_at": "2023-01-01T00:00:00Z",
                "response": w,
                "done": False,
            }
            self._write_chunk(chunk)
            time.sleep(0.01)  # Faster for cached or dummy

        # Final chunk
        final = {
            "model": model,
            "created_at": "2023-01-01T00:00:00Z",
            "response": "",
            "done": True,
            "total_duration": 100,
            "eval_count": len(words),
        }
        self._write_chunk(final)
        self.wfile.write(b"0\r\n\r\n")

        # Save to Universal Cache if not from cache
        if not cached_response and input_for_cache and input_hash:
            universal_cache.set(
                service="llm_api_ollama",
                key=input_hash,
                input_text=input_for_cache,
                output_text=full_response,
                ttl_days=30,
            )

    def _stream_chat_response(
        self, model, cached_response=None, input_for_cache=None, input_hash=None
    ):
        """Simulate NDJSON streaming for chat."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        if cached_response:
            words = []
            import re

            for match in re.finditer(r"\S+\s*", cached_response):
                words.append(match.group(0))
        else:
            words = [
                "I",
                " ",
                "am",
                " ",
                "unable",
                " ",
                "to",
                " ",
                "process",
                " ",
                "that",
                " ",
                "secure",
                " ",
                "command",
                ".",
            ]

        full_response = ""
        for w in words:
            full_response += w
            chunk = {
                "model": model,
                "created_at": "2023-01-01T00:00:00Z",
                "message": {"role": "assistant", "content": w},
                "done": False,
            }
            self._write_chunk(chunk)
            time.sleep(0.01)

        final = {
            "model": model,
            "created_at": "2023-01-01T00:00:00Z",
            "done": True,
            "total_duration": 100,
            "eval_count": len(words),
        }
        self._write_chunk(final)
        self.wfile.write(b"0\r\n\r\n")

        if not cached_response and input_for_cache and input_hash:
            universal_cache.set(
                service="llm_api_ollama",
                key=input_hash,
                input_text=input_for_cache,
                output_text=full_response,
                ttl_days=30,
            )

    def _write_chunk(self, data):
        """Writes a chunk in Transfer-Encoding: chunked format."""
        json_str = json.dumps(data)
        # In chunks, we send line length hex, CRLF, data, CRLF
        # But wait, standard Ollama client just reads raw JSON objects from stream?
        # Actually standard python http.server doesn't handle chunked encoding auto-magically if we hijack wfile?
        # Ollama usually just sends JSON objects separated by newlines if using raw socket,
        # but over HTTP 1.1 it uses Chunked.

        # Simple Approach: Just write JSON + new line.
        # But we previously set Transfer-Encoding: chunked.
        # If we set that header, we MUST follow format: Size(Hex)\r\nData\r\n

        payload = (json_str + "\n").encode("utf-8")
        size_hex = f"{len(payload):x}\r\n".encode("utf-8")

        self.wfile.write(size_hex)
        self.wfile.write(payload)
        self.wfile.write(b"\r\n")
        self.wfile.flush()

    def _log_interaction(
        self, command, input_data, response_summary, metadata=None, input_hash=None
    ):
        client_ip = self.get_client_ip()
        seed = f"{client_ip}_{int(time.time() / 3600)}"
        session_id = hashlib.md5(seed.encode()).hexdigest()[:16]

        # Log Session Start if needed (to track protocol)
        try:
            clogger.log_event(
                "session_start",
                {
                    "username": "api-user",
                    "password": "",
                    "client_version": self.headers.get("User-Agent", "Ollama/1.0"),
                    "fingerprint": "ollama",
                },
                session_id=session_id,
                ip=client_ip,
                protocol="llm-api",
            )
        except:
            pass

        # Log Interaction
        # Note: slogging maps 'input' to the DB 'command' column and ignores 'command'.
        # We merge them to ensure both Endpoint and Payload are captured.
        combined_input = f"{command}\n{input_data}" if input_data else command

        clogger.log_event(
            "interaction",
            {
                "cwd": "API_ROOT",
                "command": command,  # Kept for potential future use or analysis hooks
                "input": combined_input,  # Merged for DB persistence
                "response": response_summary,
                "source": "llm-api",
                "request_md5": input_hash
                or hashlib.md5((combined_input or "").encode()).hexdigest(),
                "metadata": metadata or {},
            },
            session_id=session_id,
            ip=client_ip,
            protocol="llm-api",
        )
