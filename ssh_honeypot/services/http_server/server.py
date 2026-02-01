import http.server
import socketserver
import threading
import time
import socket
import mimetypes
import os
import json
import hashlib
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from ssh_honeypot.core.dos_protection import dos_protector
from ssh_honeypot.core.clogging import clogger
from ssh_honeypot.core.universal_cache import universal_cache

# Non-logged management paths
MANAGEMENT_PATHS = {
    "/stats_request.html",
    "/stats_request",
    "/status_request.html",
    "/status_request",
    "/status_data.json",
}


class HoneyHTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self):
        # Mimic Apache/Nginx based on config
        return config.get("http", "server_header") or "Apache/2.4.52 (Ubuntu)"

    def get_client_ip(self):
        # Respect X-Forwarded-For from Reverse Proxy
        # self.headers might not be set if log_message is called early (e.g. request parse error)
        headers = getattr(self, "headers", None)
        if headers:
            x_fwd = headers.get("X-Forwarded-For")
            if x_fwd:
                # Standard format: client, proxy1, proxy2
                # We want the first one
                return x_fwd.split(",")[0].strip()
        return self.client_address[0]

    def log_message(self, format, *args):
        # Silence management APIs from access logs
        if self.path in MANAGEMENT_PATHS:
            return

        try:
            # Sanitize args to prevent binary data from messing up logs
            cleaned_args = []
            for arg in args:
                if isinstance(arg, str):
                    # Replace non-printable characters or high-bytes
                    cleaned_args.append(
                        "".join(
                            c if (32 <= ord(c) <= 126) else f"\\x{ord(c):02x}"
                            for c in arg
                        )
                    )
                else:
                    cleaned_args.append(arg)
            log.info(f"[HTTP] {self.get_client_ip()} - {format % tuple(cleaned_args)}")
        except Exception:
            # Fallback if formatting fails (e.g. malformed format string from http.server)
            try:
                log.info(f"[HTTP] {self.get_client_ip()} - {format} {args}")
            except:
                pass

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

    def _get_fallback_404(self):
        """Returns a realistic 404 HTML body based on server type."""
        server_header = self.version_string().lower()

        if "nginx" in server_header:
            return (
                "<html>\r\n"
                "<head><title>404 Not Found</title></head>\r\n"
                "<body>\r\n"
                "<center><h1>404 Not Found</h1></center>\r\n"
                f"<hr><center>{self.version_string()}</center>\r\n"
                "</body>\r\n"
                "</html>\r\n"
            )
        else:  # Default Apache style
            return (
                '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
                "<html><head>\n"
                "<title>404 Not Found</title>\n"
                "</head><body>\n"
                "<h1>Not Found</h1>\n"
                "<p>The requested URL was not found on this server.</p>\n"
                f"<hr>\n<address>{self.version_string()} Server at {self.headers.get('Host', 'localhost')} Port 80</address>\n"
                "</body></html>\n"
            )

    def handle_honey_request(self, method):
        self.close_connection = True
        client_ip = self.get_client_ip()

        # 0. Management & Stats (Bypass logging and DoS)
        is_mgmt = self.path in MANAGEMENT_PATHS or self.path.startswith("/api/")
        if config.get("http", "showstats") and is_mgmt:
            if self.path in [
                "/stats_request.html",
                "/stats_request",
                "/status_request.html",
                "/status_request",
            ]:
                try:
                    asset_path = os.path.join(
                        os.path.dirname(__file__), "assets", "stats_request.html"
                    )
                    if os.path.exists(asset_path):
                        with open(asset_path, "r") as f:
                            content = f.read()
                        encoded_content = content.encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(encoded_content)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(encoded_content)
                        return
                except Exception as e:
                    log.error(f"[HTTP] Error serving stats dashboard: {e}")

            if self.path == "/status_data.json":
                try:
                    from ssh_honeypot.core.utils import PROJECT_ROOT

                    data_path = os.path.join(PROJECT_ROOT, "data", "status_data.json")
                    if os.path.exists(data_path):
                        with open(data_path, "r") as f:
                            content = f.read()
                        encoded_content = content.encode("utf-8")
                        self.send_response(200)
                        self.send_header(
                            "Content-Type", "application/json; charset=utf-8"
                        )
                        self.send_header("Content-Length", str(len(encoded_content)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(encoded_content)
                        return
                    else:
                        # Fallback if job hasn't run yet
                        err_body = b'{"error": "Data not generated yet"}'
                        self.send_response(404)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(err_body)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(err_body)
                        return
                except Exception as e:
                    log.error(f"[HTTP] Error serving stats data: {e}")

            if self.path.startswith("/api/session_details"):
                try:
                    from urllib.parse import parse_qs, urlparse

                    query = parse_qs(urlparse(self.path).query)
                    sess_id = query.get("id", [None])[0]
                    if sess_id:
                        data = self.server.honey_db.get_session_details(sess_id)
                        if data:
                            resp = json.dumps(data).encode("utf-8")
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(resp)))
                            self.end_headers()
                            self.wfile.write(resp)
                            return

                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b'{"error": "Session not found"}')
                    return
                except Exception as e:
                    log.error(f"[HTTP] Error in session_details api: {e}")
                    self.send_response(500)
                    self.end_headers()
                    return

        # 1. DoS Protection (Honeypot requests only)
        if not dos_protector.is_allowed(client_ip, "HTTP"):
            try:
                self.send_response(429)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
            except Exception:
                pass
            return
        # 1. Caching Key
        # We treat "HTTP <METHOD> <PATH>" as the unique command key
        # Cwd is constant "HTTP_ROOT" to share cache globally for the site
        cache_key = f"HTTP {method} {self.path}"

        # 1.5 Read Body for Context (POST/PUT)
        body_context = ""
        if method in ["POST", "PUT", "PATCH"]:
            try:
                cl_header = self.headers.get("Content-Length")
                if cl_header:
                    content_len = int(cl_header)
                    if content_len > 0:
                        # Cap at 4KB for LLM context to avoid DOS/Cost
                        read_len = min(content_len, 4096)
                        start_bytes = self.rfile.read(read_len)
                        body_context = start_bytes.decode("utf-8", errors="replace")
                        if content_len > 4096:
                            body_context += "...[truncated]"
            except Exception as be:
                log.warning(f"[HTTP] Failed to read body: {be}")

        # Calculate Request MD5 for linking analysis
        request_md5 = hashlib.md5(cache_key.encode()).hexdigest()

        # Access DB/LLM from server instance
        db = self.server.honey_db
        llm = self.server.llm_interface

        # 1.9 Try to Serve from VFS (Simulated File System)
        web_root = config.get("http", "web_root") or "/var/www/html"
        try:
            # Normalize path (strip query params, leading slash for join)
            clean_path = self.path.split("?")[0]
            if clean_path.startswith("/"):
                v_path = os.path.normpath(web_root + clean_path)
            else:
                v_path = os.path.normpath(os.path.join(web_root, clean_path))

            # Check DB for this node
            node = db.get_fs_node(v_path)

            # Directory Handling (Index resolution)
            if node and node.get("type") == "directory":
                # Look for index files
                for idx in ["index.html", "index.php", "index.htm"]:
                    idx_path = os.path.join(v_path, idx)
                    idx_node = db.get_fs_node(idx_path)
                    if idx_node and idx_node.get("type") == "file":
                        node = idx_node
                        v_path = idx_path
                        break

            # File Serving
            if node and node.get("type") == "file":
                vfs_content = node.get("content", "")
                ctype, _ = mimetypes.guess_type(v_path)
                if not ctype:
                    ctype = "text/html" if v_path.endswith(".php") else "text/plain"

                self.send_response(200)
                self.send_header("Content-Type", f"{ctype}; charset=utf-8")
                custom_headers = config.get("http", "headers") or {}
                for k, v in custom_headers.items():
                    self.send_header(k, v)
                self.send_header(
                    "Content-Length", str(len(vfs_content.encode("utf-8")))
                )
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(vfs_content.encode("utf-8"))

                # Log Interaction
                seed = f"{client_ip}_{int(time.time() / 3600)}"
                session_id = hashlib.md5(seed.encode()).hexdigest()[:16]

                interaction_data = {
                    "cwd": "HTTP_ROOT",
                    "input": f"{method} {self.path}",
                    "response": f"[Served VFS File: {v_path}]",
                    "source": "handler",
                    "request_md5": request_md5,
                    "user_agent": self.headers.get("User-Agent", "-"),
                }
                clogger.log_event(
                    "interaction",
                    interaction_data,
                    session_id=session_id,
                    ip=client_ip,
                    protocol="http",
                )

                try:
                    session_data = {
                        "username": "www-data",
                        "password": "none",
                        "client_version": self.headers.get("User-Agent", "Unknown"),
                        "fingerprint": "http",
                    }
                    clogger.log_event(
                        "session_start",
                        session_data,
                        session_id=session_id,
                        ip=client_ip,
                        protocol="http",
                    )
                except:
                    pass
                return  # DONE VFS
        except Exception as vfse:
            log.error(f"[HTTP] VFS Lookup Error: {vfse}")

        # 2. Universal Caching Check (Only if not in VFS)
        content = ""
        cache_key_hash = hashlib.md5(cache_key.encode()).hexdigest()
        cached_item = universal_cache.get("http_cache", cache_key_hash)
        source_type = "llm"

        if cached_item:
            content = cached_item["output_text"]
            source_type = "cache"
            log.debug(f"[HTTP] Served Cached: {cache_key}")
        else:
            # 3. LLM Generation
            log.info(f"[HTTP] Generating Content: {cache_key}")

            # Check Rate Limit
            rpm = config.get_rate_limit("http", "llm", "rpm")
            rph = config.get_rate_limit("http", "llm", "rph")
            rpd = config.get_rate_limit("http", "llm", "rpd")

            allowed, reason = db.check_llm_rate_limit(
                client_ip,
                rpm_limit=rpm,
                rph_limit=rph,
                rpd_limit=rpd,
            )

            if not allowed:
                log.warning(f"[HTTP] Rate Limit Exceeded for {client_ip}: {reason}")
                # Return 429 Too Many Requests
                err_body = b"Too Many Requests"
                self.send_response(429)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(err_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(err_body)
                return  # Stop processing

            # Record Usage
            db.record_llm_usage(client_ip, source="http")
            source_type = "llm"

            try:
                # We need a dedicated method or a generic prompt for this
                # Let's use a specialized prompt wrapper
                prompt = (
                    f"You are simulating a web server ({self.version_string()}).\n"
                    f"Request: {method} {self.path}\n"
                    f"Request Body: {body_context}\n\n"
                    "Task: Generate a REALISTIC HTTP Response Body for this request.\n"
                    "1. Analyze the file extension (.js, .php, .css, etc.) and generate valid code/content for it.\n"
                    "2. If it is a script (e.g., logon_forms.js), write plausible Javascript code.\n"
                    "3. If it looks like a Login, simulate a response (success or failure based on body).\n"
                    "4. Do NOT generate a 404 error unless the path is complete gibberish (e.g. random hex).\n"
                    "5. Even for unknown paths, try to improvise something believable (e.g. a default index page or correct file format).\n"
                    "6. If the request looks like an exploit attempt (e.g. PHP input wrappers, SQL injection, RCE), act as if there is a BUG and the attack SUCCEEDED.\n"
                    "7. For successful exploits, return believable output (e.g. /etc/passwd content, command execution results, or database dumps).\n"
                    "8. Just generate the body content. Do NOT include HTTP headers."
                )

                content = llm.generate_response(
                    command="",
                    cwd="HTTP_ROOT",
                    override_prompt=prompt,
                    analyze_risk=True,
                    request_md5=request_md5,
                    db=db,
                )

                # Strip markdown just in case the LLM ignored instructions
                if content.startswith("```"):
                    import re

                    # Simple strip if main stripper didn't catch it logic (LLMInterface does it, but V1/V2 varies)
                    # Actually LLMInterface internal clean should handle it.
                    pass

                # Cache it
                universal_cache.set(
                    service="http_cache",
                    key=cache_key_hash,
                    input_text=cache_key,
                    output_text=content,
                    ttl_days=30,
                )
            except Exception as e:
                log.error(f"[HTTP] LLM Error: {e}")
                content = self._get_fallback_404()
                encoded_content = content.encode("utf-8")
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded_content)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(encoded_content)
                return  # Exit early

        # 3. Serve Response
        try:
            self.send_response(200)
            # Default Headers
            self.send_header("Content-Type", "text/html; charset=utf-8")

            # Custom Headers from Config/Persona
            custom_headers = config.get("http", "headers") or {}
            for k, v in custom_headers.items():
                self.send_header(k, v)

            self.send_header("Content-Length", str(len(content.encode("utf-8"))))
            self.send_header("Connection", "close")
            self.end_headers()

            self.wfile.write(content.encode("utf-8"))

            # Structured Log
            seed = f"{client_ip}_{int(time.time() / 3600)}"
            session_id = hashlib.md5(seed.encode()).hexdigest()[:16]

            # Register session if needed
            try:
                session_data = {
                    "username": "www-data",
                    "password": "none",
                    "client_version": self.headers.get("User-Agent", "Unknown"),
                    "fingerprint": "http",
                }
                clogger.log_event(
                    "session_start",
                    session_data,
                    session_id=session_id,
                    ip=client_ip,
                    protocol="http",
                )
            except:
                pass  # Already exists

            interaction_data = {
                "cwd": "HTTP_ROOT",
                "input": f"{method} {self.path}",
                "response": content,
                "source": source_type,
                "request_md5": request_md5,
                "user_agent": self.headers.get("User-Agent", "-"),
            }
            clogger.log_event(
                "interaction",
                interaction_data,
                session_id=session_id,
                ip=client_ip,
                protocol="http",
            )

        except Exception as e:
            log.error(f"[HTTP] Error sending response: {e}")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_http_server(port, db, llm):
    log.info(f"[HTTP] Initializing HTTP Server on port {port}...")
    try:
        bind_ip = (
            os.getenv("FAUXSSH_BIND_IP") or config.get("server", "bind_ip") or "0.0.0.0"
        )

        # TCPServer uses class attribute address_family.
        # We set it for this call to ensure it matches bind_ip.
        original_family = ThreadingHTTPServer.address_family
        if ":" in bind_ip or bind_ip == "::":
            ThreadingHTTPServer.address_family = socket.AF_INET6
        else:
            ThreadingHTTPServer.address_family = socket.AF_INET

        server = ThreadingHTTPServer(
            (bind_ip, port), HoneyHTTPHandler, bind_and_activate=False
        )

        # Restore original family to avoid polluting global state
        ThreadingHTTPServer.address_family = original_family

        # Enable Dual Stack (IPv4 fallback on IPv6 socket) if binding ::
        if server.address_family == socket.AF_INET6 and bind_ip == "::":
            try:
                # server.socket is the underlying listener socket
                IPPROTO_IPV6 = getattr(socket, "IPPROTO_IPV6", 41)
                IPV6_V6ONLY = getattr(socket, "IPV6_V6ONLY", 26)
                server.socket.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
            except Exception as e:
                log.warning(f"[HTTP] Could not set IPV6_V6ONLY=0: {e}")

        server.server_bind()
        server.server_activate()

        server.honey_db = db
        server.llm_interface = llm

        family_str = "IPv4"
        if server.address_family == socket.AF_INET6:
            family_str = "IPv6"
            # TCPServer binds automatically in __init__.
            # We rely on OS dual stack default for AF_INET6 usually,
            # but standard library doesn't expose V6ONLY easily without overriding server_bind.
            # For now, binding :: usually does dual stack on Linux by default if not strictly disabled.

        log.info(
            f"[HTTP] Starting Honeypot on {bind_ip}:{port} ({config.get('http', 'server_header')}) [{family_str}]"
        )
        # Perform Startup Cache Cleanup (Invalidate VFS overrides)
        # For universal_cache, we might want to just let TTL handle it or implement a clear service method
        # db.cleanup_http_cache(web_root)

        server.serve_forever()
    except Exception as e:
        log.error(f"[!] Failed to start HTTP server: {e}")
