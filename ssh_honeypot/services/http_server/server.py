import http.server
import socketserver
import threading
import time
import mimetypes
import os
import json
import hashlib
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config
from ssh_honeypot.core.dos_protection import dos_protector
from ssh_honeypot.core.event_logger import EventLogger


class HoneyHTTPHandler(http.server.BaseHTTPRequestHandler):
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
        # Override to use our central logger instead of stderr
        log.info(f"[HTTP] {self.get_client_ip()} - {format%args}")

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
        client_ip = self.get_client_ip()

        # 0. DoS Protection (Silent Drop)
        if not dos_protector.is_allowed(client_ip, "HTTP"):
            self.close_connection = True
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
                EventLogger().log_interaction(
                    session_id=session_id,
                    ip=client_ip,
                    input_cmd=f"{method} {self.path}",
                    output_content=f"[Served VFS File: {v_path}]",
                    protocol="http",
                    analysis=None,
                    user_agent=self.headers.get("User-Agent", "-"),
                )

                try:
                    db.start_session(
                        session_id,
                        client_ip,
                        "www-data",
                        "none",
                        self.headers.get("User-Agent", "Unknown"),
                        protocol="http",
                    )
                except:
                    pass

                db.log_interaction(
                    session_id,
                    "HTTP_ROOT",
                    cache_key,
                    vfs_content,
                    source="local",
                    request_md5=request_md5,
                )
                return  # DONE VFS
        except Exception as vfse:
            log.error(f"[HTTP] VFS Lookup Error: {vfse}")

        # 2. Caching Check (Only if not in VFS)
        content = ""
        cached = db.get_cached_response(cache_key, "HTTP_ROOT")
        source_type = "llm"

        if cached:
            content = cached
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
                self.send_response(429)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
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
                db.cache_response(cache_key, "HTTP_ROOT", content)
            except Exception as e:
                log.error(f"[HTTP] LLM Error: {e}")
                content = self._get_fallback_404()
                # Update status code for 404?
                # Ideally we should send 404 header, but logic below sends 200 by default.
                # We need to change the flow to set status code.
                # Let's refactor slightly to separate content vs status.
                # For now, just serve the 404 CONTENT with 404 Status.
                self.send_response(404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
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

            # Ensure session is valid in DB
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
                    client_ip,
                    "www-data",
                    "none",
                    self.headers.get("User-Agent", "Unknown"),
                    protocol="http",
                )
            except:
                pass  # Already exists

            db.log_interaction(
                session_id,
                "HTTP_ROOT",
                cache_key,
                content,
                source=source_type,
                request_md5=request_md5,
            )

            # Structured Log
            # Unified JSON Log
            EventLogger().log_interaction(
                session_id=session_id,
                ip=client_ip,
                input_cmd=f"{method} {self.path}",
                output_content=content,
                protocol="http",
                analysis=None,  # HTTP specific analysis not yet fully integrated in request loop
                user_agent=self.headers.get("User-Agent", "-"),
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
        # Perform Startup Cache Cleanup (Invalidate VFS overrides)
        web_root = config.get("http", "web_root") or "/var/www/html"
        db.cleanup_http_cache(web_root)

        server.serve_forever()
    except Exception as e:
        log.error(f"[!] Failed to start HTTP server: {e}")
