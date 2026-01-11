import http.server
import socketserver
import threading
import time
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from ssh_honeypot.core.dos_protection import dos_protector


class HoneyHTTPHandler(http.server.BaseHTTPRequestHandler):
    def version_string(self):
        # Mimic Apache/Nginx based on config
        return config.get("http", "server_header") or "Apache/2.4.52 (Ubuntu)"

    def log_message(self, format, *args):
        # Override to use our central logger instead of stderr
        log.info(f"[HTTP] {self.address_string()} - {format%args}")

    def do_GET(self):
        self.handle_honey_request("GET")

    def do_POST(self):
        self.handle_honey_request("POST")

    def do_HEAD(self):
        self.handle_honey_request("HEAD")

    def do_PUT(self):
        self.handle_honey_request("PUT")

    def do_DELETE(self):
        self.handle_honey_request("DELETE")

    def do_CONNECT(self):
        self.handle_honey_request("CONNECT")

    def do_OPTIONS(self):
        self.handle_honey_request("OPTIONS")

    def do_TRACE(self):
        self.handle_honey_request("TRACE")

    def do_PATCH(self):
        self.handle_honey_request("PATCH")

    def handle_honey_request(self, method):
        # 0. DoS Protection (Silent Drop)
        if not dos_protector.is_allowed(self.client_address[0], "HTTP"):
            self.close_connection = True
            return

        # 1. Caching Key
        # 1. Caching Key
        # We treat "HTTP <METHOD> <PATH>" as the unique command key
        # Cwd is constant "HTTP_ROOT" to share cache globally for the site
        cache_key = f"HTTP {method} {self.path}"

        # Access DB/LLM from server instance
        db = self.server.honey_db
        llm = self.server.llm_interface

        content = ""
        cached = db.get_cached_response(cache_key, "HTTP_ROOT")

        if cached:
            content = cached
            log.debug(f"[HTTP] Served Cached: {cache_key}")
        else:
            # 2. LLM Generation
            log.info(f"[HTTP] Generating Content: {cache_key}")

            # Check Rate Limit
            allowed, reason = db.check_llm_rate_limit(
                self.client_address[0],
                rpm_limit=config.get("http", "llm_rpm"),
                rpd_limit=config.get("http", "llm_rpd"),
            )

            if not allowed:
                log.warning(
                    f"[HTTP] Rate Limit Exceeded for {self.client_address[0]}: {reason}"
                )
                # Return 429 Too Many Requests
                self.send_response(429)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
                return  # Stop processing

            # Record Usage
            db.record_llm_usage(self.client_address[0], source="http")

            try:
                # We need a dedicated method or a generic prompt for this
                # Let's use a specialized prompt wrapper
                prompt = (
                    f"You are simulating a web server ({self.version_string()}). "
                    f"The user sent a {method} request to '{self.path}'. "
                    "Generate the realistic HTTP Response Body (HTML/JSON/Text). "
                    "Do NOT include HTTP headers in the output, only the body. "
                    "If it's a login page, make it look realistic. "
                    "If it's a 404, make it a realistic standard 404 page for this server software."
                )

                content = llm.generate_response(
                    command="", cwd="HTTP_ROOT", override_prompt=prompt
                )

                # Cache it
                db.cache_response(cache_key, "HTTP_ROOT", content)
            except Exception as e:
                log.error(f"[HTTP] LLM Error: {e}")
                content = "<html><body><h1>500 Internal Server Error</h1></body></html>"

        # 3. Serve Response
        try:
            self.send_response(200)
            # Default Headers
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content.encode("utf-8"))))
            self.send_header("Connection", "close")
            self.end_headers()

            self.wfile.write(content.encode("utf-8"))

            # Log Interaction
            # We treat session_id as "http_<ip>_<hour>" or just generic "http_session"?
            # For analytics, maybe we create a specialized session ID per request?
            # Or reuse IP-based tracking?
            # Let's generate a quick session ID based on IP + Date to group them?
            session_id = f"http_{self.client_address[0]}_{int(time.time() / 3600)}"

            # Ensure session is valid in DB (might be overkill to create session row for every request)
            # But 'log_interaction' requires a valid FK session_id usually?
            # Check schema: session_id is FK.
            # So we MUST create a session if not exists.

            # Quick check/create session
            # This is slightly expensive but correct.
            try:
                # We can't easily check if exists without query.
                # Just try insert, ignore if fails (on Unique constraint)?
                # Session ID is unique.
                # But start_session expects unique session ID usually.
                # Let's keep it simple: Use a persistent "HTTP_Service" session per hour?
                # Or just let log_interaction handle it if we relax FK? FKs are enforced in SQLite usually.
                # Let's try to register it cleanly:
                db.start_session(
                    session_id,
                    self.client_address[0],
                    "www-data",
                    "none",
                    self.headers.get("User-Agent", "Unknown"),
                    protocol="http",
                )
            except:
                pass  # Already exists

            db.log_interaction(
                session_id, "HTTP_ROOT", cache_key, content, source="http"
            )

        except Exception as e:
            log.error(f"[HTTP] Error sending response: {e}")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def start_http_server(port, db, llm):
    try:
        server = ThreadingHTTPServer(("0.0.0.0", port), HoneyHTTPHandler)
        server.honey_db = db
        server.llm_interface = llm

        log.info(
            f"[*] Starting HTTP Honeypot on 0.0.0.0:{port} ({config.get('http', 'server_header')})"
        )
        server.serve_forever()
    except Exception as e:
        log.error(f"[!] Failed to start HTTP server: {e}")
