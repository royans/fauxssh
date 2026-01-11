import socket
import threading
import time
from ssh_honeypot.core.logging_setup import log

import os
import hashlib


def handle_redis_client(client_sock, addr, db, llm):
    ip = addr[0]
    log.info(f"[*] New Redis connection from {ip}")

    session_id = os.urandom(8).hex()
    try:
        # Start Session
        # username='redis', password='', client_version='redis', protocol='redis'
        db.start_session(session_id, ip, "redis", "", "redis-client", protocol="redis")
    except Exception as e:
        log.error(f"[!] Redis Session Start Error: {e}")

    # Initialize Handler
    try:
        from .handler import RedisHandler

        handler = RedisHandler(db, llm)
    except Exception as e:
        log.error(f"[!] Failed to init RedisHandler: {e}")
        client_sock.close()
        return

    try:
        while True:
            data = client_sock.recv(1024)
            if not data:
                break

            command = data.decode("utf-8", errors="ignore").strip()
            log.info(f"[Redis] {ip}: {command}")

            response = handler.handle_command(command, ip)
            client_sock.send(response)

            # Log Interaction
            try:
                # We interpret CWD as "/" for Redis
                cmd_hash = hashlib.md5(command.encode("utf-8")).hexdigest()
                db.log_interaction(
                    session_id,
                    "/",
                    command,
                    response.decode(
                        "utf-8", errors="ignore"
                    ),  # Store response as string for log
                    source="redis_honeypot",
                    request_md5=cmd_hash,
                )
            except Exception as log_e:
                log.error(f"[!] Redis Logging Error: {log_e}")

    except Exception as e:
        log.error(f"[!] Redis Error {ip}: {e}")
    finally:
        client_sock.close()
        try:
            db.end_session(session_id)
        except:
            pass


def start_redis_server(port, db, llm):
    """
    Start Redis Honeypot
    """
    host = "0.0.0.0"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
        server.listen(5)
        log.info(f"[*] Redis Honeypot listening on {host}:{port}")

        while True:
            client, addr = server.accept()
            client_handler = threading.Thread(
                target=handle_redis_client, args=(client, addr, db, llm)
            )
            client_handler.start()

    except Exception as e:
        log.error(f"[!] Redis Server Failed: {e}")
