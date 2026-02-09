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

# Globally shared for all handler threads to prevent redundant LLM calls# For thundering herd prevention - REVERTED DUE TO HANGS
# _inflight_requests = {}
# _inflight_lock = threading.Lock()

# Non-logged management paths
MANAGEMENT_PATHS = {
    "/stats_request.html",
    "/stats_request",
    "/stats_request_v2.html",
    "/status_request.html",
    "/status_request",
    "/status_data.json",
    "/favicon.ico",
}


class HoneyHTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def version_string(self):
        # Mimic Apache/Nginx based on config
        val = config.get("http", "server_header") or "Apache/2.4.52 (Ubuntu)"
        return str(val)

    def get_client_ip(self):
        # Respect X-Forwarded-For ONLY if the immediate peer is localhost
        # (Trusted Proxy mode - prevents spoofing from public internet)
        peer_ip = self.client_address[0]
        if peer_ip in ("127.0.0.1", "::1"):
            headers = getattr(self, "headers", None)
            if headers:
                x_fwd = headers.get("X-Forwarded-For")
                if x_fwd:
                    # Standard format: client, proxy1, proxy2
                    # We want the first one
                    return x_fwd.split(",")[0].strip()
        return peer_ip

    def log_message(self, format, *args):
        # Silence management APIs from access logs
        path = getattr(self, "path", "")
        if path in MANAGEMENT_PATHS or path.startswith("/api/"):
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
        clean_path = self.path.split("?")[0]
        query = {}
        if "?" in self.path:
            try:
                from urllib.parse import parse_qs, urlparse

                query = parse_qs(urlparse(self.path).query)
            except:
                pass

        is_mgmt = clean_path in MANAGEMENT_PATHS or clean_path.startswith("/api/")
        if config.get("http", "showstats") and is_mgmt:
            if clean_path in [
                "/stats_request.html",
                "/stats_request",
                "/stats_request_v2.html",
                "/status_request.html",
                "/status_request",
            ]:
                try:
                    filename = "stats_request.html"
                    if "v2" in clean_path:
                        filename = "stats_request_v2.html"

                    asset_path = os.path.join(
                        os.path.dirname(__file__), "assets", filename
                    )
                    if os.path.exists(asset_path):
                        with open(asset_path, "r") as f:
                            content = f.read()
                        encoded_content = content.encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html; charset=utf-8")
                        self.send_header("Content-Length", str(len(encoded_content)))
                        self.send_header("Connection", "close")
                        # Strict CSP for Dashboard (prevents XSS while allowing CDNs)
                        self.send_header(
                            "Content-Security-Policy",
                            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:;",
                        )
                        self.send_header(
                            "Cache-Control", "no-cache, no-store, must-revalidate"
                        )
                        self.send_header("Pragma", "no-cache")
                        self.send_header("Expires", "0")
                        self.end_headers()
                        self.wfile.write(encoded_content)
                        return
                except Exception as e:
                    log.error(f"[HTTP] Error serving stats dashboard: {e}")

            if clean_path == "/status_data.json":
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

            if clean_path == "/favicon.ico":
                self.send_response(404)
                self.end_headers()
                return

            if clean_path.startswith("/api/payloads"):
                try:

                    # Check Cache
                    cache_key = hashlib.md5(self.path.encode()).hexdigest()
                    cached = universal_cache.get("api_cache", cache_key)
                    if cached:
                        resp = cached["output_text"].encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(resp)))
                        self.send_header("X-Cache", "HIT")
                        self.end_headers()
                        self.wfile.write(resp)
                        return

                    hours = int(query.get("hours", [24])[0])
                    data = self.server.analytics_engine.get_payload_summary(hours=hours)

                    from ssh_honeypot.core.utils import obfuscate_ip

                    for p in data:
                        if "ip" in p:
                            p["ip"] = obfuscate_ip(p["ip"])
                        if "sample_url" in p:
                            p["sample_url"] = "Hidden"

                    json_data = json.dumps(data, default=str)
                    universal_cache.set(
                        "api_cache", cache_key, json_data, ttl_days=0.02
                    )

                    resp = json_data.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp)))
                    self.send_header("X-Cache", "MISS")
                    self.end_headers()
                    self.wfile.write(resp)
                    return
                except Exception as e:
                    log.error(f"[HTTP] Error in payloads api: {e}")
                    self.send_response(500)
                    self.end_headers()
                    return

            if clean_path.startswith("/api/payload_details"):
                try:
                    from urllib.parse import parse_qs, urlparse

                    # Check Cache
                    cache_key = hashlib.md5(self.path.encode()).hexdigest()
                    cached = universal_cache.get("api_cache", cache_key)
                    if cached:
                        resp = cached["output_text"].encode("utf-8")
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(resp)))
                        self.send_header("X-Cache", "HIT")
                        self.end_headers()
                        self.wfile.write(resp)
                        return

                    query = parse_qs(urlparse(self.path).query)
                    md5 = query.get("md5", [None])[0]
                    if md5:
                        data = self.server.analytics_engine.get_payload_details(md5)
                        if data:
                            # Hide sensitive info
                            from ssh_honeypot.core.utils import obfuscate_ip

                            data["url"] = "Hidden"
                            if "ip" in data:
                                data["ip"] = obfuscate_ip(data["ip"])

                            if "occurrences" in data:
                                for occ in data["occurrences"]:
                                    if "ip" in occ:
                                        occ["ip"] = obfuscate_ip(occ["ip"])

                            json_data = json.dumps(data, default=str)
                            # Cache for 30 mins
                            universal_cache.set(
                                "api_cache", cache_key, json_data, ttl_days=0.02
                            )

                            resp = json_data.encode("utf-8")
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.send_header("Content-Length", str(len(resp)))
                            self.send_header("X-Cache", "MISS")
                            self.end_headers()
                            self.wfile.write(resp)
                            return

                    self.send_response(404)
                    self.end_headers()
                    return
                except Exception as e:
                    log.error(f"[HTTP] Error in payload_details api: {e}")
                    self.send_response(500)
                    self.end_headers()
                    return

            if clean_path.startswith("/api/session_details"):
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

            if clean_path.startswith("/api/v2/"):
                # -------------------------------------------------------------------
                # Rate Limiting Logic (Internal IPs Exempt)
                # -------------------------------------------------------------------
                try:
                    from ipaddress import ip_address

                    ip_obj = ip_address(client_ip)
                    is_internal = (
                        ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_reserved
                    )

                    # Also check config
                    cfg_internal = config.get("internal_ips", [])
                    if client_ip in cfg_internal:
                        is_internal = True

                except:
                    is_internal = False

                if not is_internal:
                    # Apply Rate Limits for Public APIs to prevent scraping abuse
                    # 100 requests per minute per IP for stats API seems generous but safe
                    allowed, reason = self.server.honey_db.check_api_rate_limit(
                        service="stats_api",
                        identifier=client_ip,
                        rpm_limit=100,
                        rph_limit=2000,
                        rpd_limit=10000,
                    )

                    # Also record usage
                    self.server.honey_db.record_api_usage("stats_api", client_ip)

                    if not allowed:
                        log.warning(
                            f"[HTTP] API Rate Limit Exceeded for {client_ip}: {reason}"
                        )
                        self.send_response(429)
                        self.end_headers()
                        self.wfile.write(b'{"error": "Too Many Requests"}')
                        return

                # -------------------------------------------------------------------
                # End Rate Limiting
                # -------------------------------------------------------------------

                try:
                    from urllib.parse import parse_qs, urlparse

                    engine = self.server.analytics_engine

                    parsed_path = urlparse(self.path)
                    query = parse_qs(parsed_path.query)
                    hours = int(query.get("hours", [24])[0])

                    if clean_path == "/api/v2/totals":
                        data = engine.get_dashboard_totals(hours=hours)
                        key = "totals"
                    else:
                        # Common Params
                        limit = int(query.get("limit", [50])[0])
                        # REQUIRE anonymity for web dashboard
                        anon = True
                        ip_filter = query.get("ip", [None])[0]

                        # Support multi-protocol (e.g. ?proto=ssh&proto=telnet)
                        raw_protos = query.get("proto", [])
                        if not raw_protos:
                            # Also check 'protocol' alias
                            raw_protos = query.get("protocol", [])

                        protocol_filter = (
                            raw_protos
                            if len(raw_protos) > 1
                            else (raw_protos[0] if raw_protos else None)
                        )

                        risk_min = query.get("risk", [None])[0]
                        if not risk_min:
                            risk_min = query.get("risk_min", [None])[0]
                        if risk_min:
                            risk_min = float(risk_min)

                        if clean_path == "/api/v2/sessions":
                            user_filter = query.get("user", [None])[0]
                            asn_filter = query.get("asn", [None])[0]
                            data = engine.get_recent_sessions(
                                limit=limit,
                                anon=anon,
                                ip_filter=ip_filter,
                                protocol_filter=protocol_filter,
                                risk_min=risk_min,
                                user_filter=user_filter,
                                asn_filter=asn_filter,
                            )
                            key = "sessions"

                        elif clean_path == "/api/v2/stats/top_asns":
                            data = engine.get_top_asns(
                                hours=hours,
                                protocol_filter=protocol_filter,
                            )
                            key = "asns"

                        elif clean_path == "/api/v2/stats/top_ips":
                            data = engine.get_top_ips(hours=hours, anon=anon)
                            key = "ips"

                        elif clean_path == "/api/v2/stats/top_countries":
                            data = engine.get_top_countries(hours=hours)
                            key = "countries"

                        elif clean_path == "/api/v2/commands":
                            session_filter = query.get("session", [None])[0]
                            data = engine.get_recent_commands(
                                limit=limit,
                                anon=anon,
                                ip_filter=ip_filter,
                                session_filter=session_filter,
                                protocol_filter=protocol_filter,
                                risk_min=risk_min,
                            )
                            key = "commands"

                        elif clean_path == "/api/v2/top/commands":
                            duration = int(query.get("duration", [3600])[0])
                            data = engine.get_top_commands(
                                limit=limit,
                                duration_seconds=duration,
                                protocol_filter=protocol_filter,
                            )
                            key = "top_commands"

                        elif clean_path == "/api/v2/top/ips":
                            data = engine.get_top_ips(limit=limit, anon=anon)
                            key = "top_ips"

                        else:
                            self.send_response(404)
                            self.end_headers()
                            return

                    # Return JSON
                    resp = json.dumps({key: data}, default=str).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(resp)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(resp)
                    return

                except Exception as e:
                    log.error(f"[HTTP] API V2 Error: {e}")
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b'{"error": "Internal Server Error"}')
                    return

        if method == "CONNECT":
            try:
                # Send 200 Connection Established (Fake)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"")

                # Log Interaction
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
                    pass

                interaction_data = {
                    "cwd": "HTTP_ROOT",
                    "input": f"{method} {self.path}",
                    "response": "[Local Handler: CONNECT]",
                    "source": "handler",
                    "request_md5": hashlib.md5(
                        f"HTTP CONNECT {self.path}".encode()
                    ).hexdigest(),
                    "user_agent": self.headers.get("User-Agent", "-"),
                }
                clogger.log_event(
                    "interaction",
                    interaction_data,
                    session_id=session_id,
                    ip=client_ip,
                    protocol="http",
                )
                return
            except Exception as e:
                log.error(f"[HTTP] CONNECT Handler Error: {e}")
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
                    "source": "vfs",
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
            source_type = "llm-cache"
            log.debug(f"[HTTP] Served Cached: {cache_key}")
        else:
            # 3. LLM Generation and In-flight Check
            # 3. LLM Generation
            log.info(f"[HTTP] Generating Content: {cache_key}")

            # LLM Generation
            try:
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
                    return

                # Record Usage
                db.record_llm_usage(client_ip, source="http")

                # LLM Generation
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

                llm_res = llm.generate_response(
                    "http",
                    "HTTP_ROOT",
                    [],
                    [],
                    [],
                    client_ip=client_ip,
                    override_prompt=prompt,
                    protocol="http",
                    return_source=True,
                )

                if isinstance(llm_res, tuple) and len(llm_res) == 2:
                    content, source_type = llm_res
                else:
                    content = llm_res
                    source_type = "llm"

                # Guard against internal LLM errors
                if '{"output": "INTERNAL_ERROR"' in content:
                    log.warning(
                        f"[HTTP] Received INTERNAL_ERROR from LLM. Falling back to 404."
                    )
                    content = self._get_fallback_404()
                    source_type = "error"

                if content:
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
                source_type = "error"

        # 3. Serve Response
        try:
            status_code = 404 if source_type == "error" else 200
            self.send_response(status_code)
            # Default Headers
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Honeypot-Source", source_type)

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

        from ssh_honeypot.core.analytics_engine import AnalyticsEngine

        server.analytics_engine = AnalyticsEngine(db)

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
