import os
import argparse
import threading
import time
import socket

# Imports from Core
from ssh_honeypot.core.database import HoneyDB
from ssh_honeypot.core.llm import LLMInterface
from ssh_honeypot.core.config import config
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.persona_validator import validate_active_persona
from ssh_honeypot.core.background_tasks import cleanup_loop, analysis_loop
from ssh_honeypot.core import fs_seeder

# Imports from Services
from ssh_honeypot.services.ssh.server import start_ssh_server
from ssh_honeypot.services.telnet.server import start_telnet_server

def main(argv=None):
    parser = argparse.ArgumentParser(description="SSH/Telnet Honeypot Server")
    parser.add_argument("--persona", type=str, help="Name (in data/personas) or Path to persona directory")
    parser.add_argument("--test-analysis", action="store_true", help="Run a single pass of the analysis loop and exit")
    args = parser.parse_args(argv)

    # Reload Persona if Argument Provided
    if args.persona:
        config.load_persona(args.persona)

    # Validate Persona
    is_valid_persona, p_errors = validate_active_persona(config)
    p_name = config.get('persona', 'name') or "Unknown"

    if is_valid_persona:
        log.info(f"Persona '{p_name}' loaded and validated successfully.")
    else:
        log.critical(f"Persona '{p_name}' validation FAILED:")
        for e in p_errors:
            log.critical(f"  - {e}")
        log.critical("Exiting due to invalid configuration.")
        exit(1)

    # Initialize DB and Core
    db = HoneyDB()
    db.sanitize_artifacts()
    
    # Initialize LLM
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        try:
            from dotenv import load_dotenv, find_dotenv
            load_dotenv(find_dotenv())
            api_key = os.getenv("GOOGLE_API_KEY")
        except: pass
    
    llm = LLMInterface(api_key)

    # Seed Filesystem
    fs_seeder.seed_filesystem(db)

    # TEST MODE
    if args.test_analysis:
        log.info("[*] Running in Analysis Test Mode (Foreground)")
        analysis_loop(db, llm, run_once=True)
        return

    # Start Background Tasks
    cleanup_thread = threading.Thread(target=cleanup_loop, args=(db,), daemon=True)
    cleanup_thread.start()
    
    analysis_thread = threading.Thread(target=analysis_loop, args=(db, llm), daemon=True)
    analysis_thread.start()

    # Determine Ports
    ssh_port = int(os.getenv('SSHPOT_PORT', config.get('server', 'port') or 2222))
    
    # Start SSH Server (Main Service)
    # We run SSH in a thread so we can start others too, or keep main thread for healthchecks
    ssh_thread = threading.Thread(target=start_ssh_server, args=(ssh_port, db, llm))
    ssh_thread.daemon = True
    ssh_thread.start()

    # Start Telnet Server (Optional)
    if str(os.getenv('SSHPOT_ENABLE_TELNET', 'true')).lower() == 'true':
        t_port = int(os.getenv('SSHPOT_TELNET_PORT', 2323))
        start_telnet_server(t_port, db, llm)

    # Start Redis Server (Optional)
    if str(os.getenv('SSHPOT_ENABLE_REDIS', 'true')).lower() == 'true':
        r_port = int(os.getenv('SSHPOT_REDIS_PORT', 6379))
        from ssh_honeypot.services.redis.server import start_redis_server
        redis_thread = threading.Thread(target=start_redis_server, args=(r_port, db, llm))
        redis_thread.daemon = True
        redis_thread.start()

    # Start MCP Server (Optional)
    if str(os.getenv('SSHPOT_ENABLE_MCP', 'true')).lower() == 'true':
        mcp_port = int(os.getenv('SSHPOT_MCP_PORT', 8000))
        try:
            from ssh_honeypot.services.mcp.server import start_mcp_server
            # MCP uses asyncio/uvicorn which is blocking or complex to thread?
            # start_mcp_server calls uvicorn.run which blocks.
            # We must run it in a thread.
            mcp_thread = threading.Thread(target=start_mcp_server, args=(mcp_port, db, llm))
            mcp_thread.daemon = True
            mcp_thread.start()
        except ImportError:
            log.error("[!] MCP Service Dependencies missing (mcp, starlette, uvicorn). Skipping.")
        except Exception as e:
            log.error(f"[!] MCP Service Failed to Start: {e}")

    # Start HTTP Server (Optional, Enabled by default)
    if str(os.getenv('SSHPOT_ENABLE_HTTP', 'true')).lower() == 'true':
        h_port = int(os.getenv('SSHPOT_HTTP_PORT', config.get('http', 'port') or 8080))
        try:
            from ssh_honeypot.services.http_server.server import start_http_server
            http_thread = threading.Thread(target=start_http_server, args=(h_port, db, llm))
            http_thread.daemon = True
            http_thread.start()
        except ImportError:
            log.error("[!] HTTP Service module missing.")
        except Exception as e:
            log.error(f"[!] HTTP Service Failed to Start: {e}")

    log.info(f"[*] Honeypot services started. SSH: {ssh_port}")

    # Keep Main Thread Alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Stopping honeypot...")

if __name__ == "__main__":
    main()
