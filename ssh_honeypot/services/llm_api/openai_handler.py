import http.server
import json
import time
import hashlib
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from ssh_honeypot.core.clogging import clogger
from ssh_honeypot.core.universal_cache import universal_cache


class OpenAIHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def get_client_ip(self):
        headers = getattr(self, "headers", None)
        if headers:
            x_fwd = headers.get("X-Forwarded-For")
            if x_fwd:
                return x_fwd.split(",")[0].strip()
        return self.client_address[0]

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        if self.path == "/v1/chat/completions":
            self.handle_chat_completions()
        else:
            self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        # CORS support for browser-based tools
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def handle_chat_completions(self):
        body_bytes = self._read_body()
        if not body_bytes:
            return

        try:
            payload = json.loads(body_bytes)
            model = payload.get("model", "unknown")
            stream = payload.get("stream", False)

            # Log full payload
            combined_input = f"POST /v1/chat/completions\n{json.dumps(payload)}"
            input_hash = hashlib.md5(combined_input.encode()).hexdigest()

            # 1. Check Cache
            cached = universal_cache.get("llm_api_openai", input_hash)
            if cached:
                log.info(f"[OpenAI] Cache Hit for {input_hash[:8]}")
                if stream:
                    self._stream_sse_response(model, cached["output_text"])
                else:
                    # Parse the cached output_text which should be the final response message
                    self._send_json(json.loads(cached["output_text"]))
                return

            self._log_interaction(
                "POST /v1/chat/completions",
                json.dumps(payload),
                f"[OpenAI Stream] Model: {model}",
                metadata={"model": model},
                input_hash=input_hash,
            )

            if stream:
                self._stream_sse_response(
                    model, input_for_cache=combined_input, input_hash=input_hash
                )
            else:
                # Accumulate non-streamed response
                resp = {
                    "id": "chatcmpl-123",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "I cannot verify that information.",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 10,
                        "total_tokens": 20,
                    },
                }
                self._send_json(resp)
                # Cache full JSON response
                universal_cache.set(
                    service="llm_api_openai",
                    key=input_hash,
                    input_text=combined_input,
                    output_text=json.dumps(resp),
                    ttl_days=30,
                )

        except Exception as e:
            log.error(f"[OpenAI] Error: {e}")
            self.send_error(500)

    def _read_body(self):
        try:
            cl = int(self.headers.get("Content-Length", 0))
            if cl > 0:
                if cl > 2_000_000:
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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _stream_sse_response(
        self, model, cached_response=None, input_for_cache=None, input_hash=None
    ):
        """Simulate SSE (Server-Sent Events) for OpenAI."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.close_connection = True

        if cached_response:
            # If cached, we expect it to be a JSON object (the non-streamed response)
            # but for streaming we need the content.
            try:
                data = json.loads(cached_response)
                full_text = (
                    data.get("choices", [{}])[0].get("message", {}).get("content", "")
                )
            except:
                full_text = cached_response

            words = []
            import re

            for match in re.finditer(r"\S+\s*", full_text):
                words.append(match.group(0))
        else:
            words = [
                "I",
                " ",
                "have",
                " ",
                "processed",
                " ",
                "your",
                " ",
                "request",
                ".",
            ]

        full_content = ""
        for w in words:
            full_content += w
            chunk_data = {
                "id": "chatcmpl-123",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {"index": 0, "delta": {"content": w}, "finish_reason": None}
                ],
            }
            Event = f"data: {json.dumps(chunk_data)}\n\n"
            self.wfile.write(Event.encode("utf-8"))
            self.wfile.flush()
            time.sleep(0.01)

        # End
        end_data = {
            "id": "chatcmpl-123",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
        self.wfile.write(f"data: {json.dumps(end_data)}\n\n".encode("utf-8"))
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

        # Save to Universal Cache if not from cache
        if not cached_response and input_for_cache and input_hash:
            # For OpenAI, we store the simulated full response structure
            # so it's consistent if requested without stream later
            full_resp_struct = {
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": full_content,
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
            universal_cache.set(
                service="llm_api_openai",
                key=input_hash,
                input_text=input_for_cache,
                output_text=json.dumps(full_resp_struct),
                ttl_days=30,
            )

    def _log_interaction(
        self, command, input_data, response_summary, metadata=None, input_hash=None
    ):
        client_ip = self.get_client_ip()
        seed = f"{client_ip}_{int(time.time() / 3600)}"
        session_id = hashlib.md5(seed.encode()).hexdigest()[:16]

        # Use fixed merged logging logic
        combined_input = f"{command}\n{input_data}" if input_data else command

        # Log Session Start if needed
        try:
            # Basic deduplication logic handled by DB constraints usually, but clogging spam is low risk
            pass
        except:
            pass

        clogger.log_event(
            "interaction",
            {
                "cwd": "API_ROOT",
                "command": command,
                "input": combined_input,
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
