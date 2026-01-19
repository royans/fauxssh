import os
import argparse
import threading
import time
import socket
import sys
import asyncio

# Imports from Core
from ssh_honeypot.core.database import HoneyDB, get_db_backend
from ssh_honeypot.core.llm import LLMInterface
from ssh_honeypot.core.config import config
from ssh_honeypot.core.utils import get_data_dir
from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.persona_validator import validate_active_persona
from ssh_honeypot.core.background_tasks import (
    cleanup_loop,
    analysis_loop,
    ip_enrichment_loop,
    analysis_loop,
    ip_enrichment_loop,
    payload_download_loop,
    payload_analysis_loop,
)
from ssh_honeypot.core import fs_seeder

# Imports from Services
from ssh_honeypot.services.ssh.server import start_ssh_server
from ssh_honeypot.services.telnet.server import start_telnet_server


def main(argv=None):
    parser = argparse.ArgumentParser(description="SSH/Telnet Honeypot Server")
    parser.add_argument(
        "--create-persona",
        type=str,
        help="Generate a new dynamic persona from description",
    )
    parser.add_argument(
        "--persona",
        type=str,
        help="Name (in data/personas) or Path to persona directory",
    )
    parser.add_argument(
        "--test-analysis",
        action="store_true",
        help="Run a single pass of the analysis loop and exit",
    )
    args = parser.parse_args(argv)

    # Initialize LLM early if needed for generation
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        try:
            from dotenv import load_dotenv, find_dotenv

            load_dotenv(find_dotenv())
            api_key = os.getenv("GOOGLE_API_KEY")
        except:
            pass

    llm_version = os.getenv("FAUXSSH_LLM_VERSION", "v1").lower()
    if llm_version == "v2":
        from ssh_honeypot.core.llm_v2 import LLMInterfaceV2

        llm = LLMInterfaceV2(api_key)
    else:
        llm = LLMInterface(api_key)

    # Handle Persona Generation
    if args.create_persona:
        log.info(f"[*] Generating new persona: '{args.create_persona}'")
        try:
            from ssh_honeypot.core.persona_generator import PersonaGenerator

            generator = PersonaGenerator(llm)
            new_persona = generator.generate_persona(args.create_persona)
            # Load the newly created persona
            config.load_persona(new_persona)
            # State is saved inside generate_persona
        except Exception as e:
            log.critical(f"Failed to generate persona: {e}")
            exit(1)

    # Handle Logical Persona Loading (Order matters)
    elif args.persona:
        config.load_persona(args.persona)
        # Save explicit selection
        from ssh_honeypot.core.state_manager import StateManager

        StateManager.save_last_persona(args.persona)
    else:
        # Just ensure config logic runs (it ran on import, but we can double check or rely on default)
        # Actually config.py __init__ already ran load_persona().
        # If no args provided, it used Env/State/Default.
        pass
    # Prompts for Cache Clearing
    should_prompt_clear = False

    # If we created a persona or explicitly switched, we should check status
    if args.create_persona or args.persona:
        should_prompt_clear = True

    # Only Prompt if Interactive
    if should_prompt_clear and sys.stdin.isatty():
        try:
            # We need to initialize DB temp to check if it has valuable data?
            # Or just assume if file exists.
            db_path = os.path.join(get_data_dir(), "honeypot.sqlite")
            if os.path.exists(db_path):
                print(
                    "\n[?] Persona change detected. Do you want to clear previous session/filesystem cache?"
                )
                print("    (y) Yes, clear cache (Recommended for new personas)")
                print("    (n) No, keep existing sessions")
                choice = input("    choice [y/N]: ").strip().lower()
                if choice == "y":
                    # We need to init DB to clear it properly
                    temp_db = HoneyDB()
                    temp_db.clear_cache()
                    print("[*] Cache cleared.")
        except Exception as e:
            log.error(f"Failed to prompt for cache clear: {e}")

    # Validate Persona
    is_valid_persona, p_errors = validate_active_persona(config)
    p_name = config.get("persona", "name") or "Unknown"

    if is_valid_persona:
        log.info(f"Persona '{p_name}' loaded and validated successfully.")
    else:
        log.critical(f"Persona '{p_name}' validation FAILED:")
        for e in p_errors:
            log.critical(f"  - {e}")
        log.critical("Exiting due to invalid configuration.")
        exit(1)

    # Initialize DB and Core
    db = get_db_backend()
    log.info(f"[*] Database: {db.get_connection_info()}")
    # db.sanitize_artifacts() - REMOVED: This wipes the DB on every restart!

    # Initialize LLM
    api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("LLM_API_KEY")
    if not api_key:
        try:
            from dotenv import load_dotenv, find_dotenv

            load_dotenv(find_dotenv())
            api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("LLM_API_KEY")
        except:
            pass

    if not api_key:
        # High Visibility Warning
        print("\033[1;31m" + "=" * 60 + "\033[0m")
        print("\033[1;31mCRITICAL WARNING: GOOGLE_API_KEY IS MISSING!\033[0m")
        print(
            "\033[1;31mAI-powered content generation and analysis will be disabled.\033[0m"
        )
        print("\033[1;31m" + "=" * 60 + "\033[0m")
        log.error("GOOGLE_API_KEY not found. AI Core is OFFLINE.")

    # Clear any previously "poisoned" cache entries in background
    # This ensures "AI Core Offline" doesn't stick around without blocking startup
    def background_purge():
        try:
            db.purge_poisoned_cache()
        except Exception as e:
            log.warning(f"Failed to purge poisoned cache: {e}")

    threading.Thread(target=background_purge, daemon=True).start()

    llm_version = os.getenv("FAUXSSH_LLM_VERSION", "v1").lower()
    if llm_version == "v2":
        from ssh_honeypot.core.llm_v2 import LLMInterfaceV2

        log.info("[LLM] Using V2 Interface (Google GenAI SDK)")
        llm = LLMInterfaceV2(api_key)
    else:
        log.info("[LLM] Using V1 Interface (Requests)")
        llm = LLMInterface(api_key)

    # Seed Filesystem
    fs_seeder.seed_filesystem(db)

    # Backfill Malicious Payloads in background
    def background_backfill():
        try:
            from ssh_honeypot.core.payload_manager import PayloadManager

            log.info("[PayloadManager] Triggering startup backfill scan...")
            PayloadManager(db).backfill_from_interactions()
        except Exception as e:
            log.error(f"[PayloadManager] Startup backfill failed: {e}")

    threading.Thread(target=background_backfill, daemon=True).start()

    # TEST MODE
    if args.test_analysis:
        log.info("[*] Running in Analysis Test Mode (Foreground)")
        analysis_loop(db, llm, run_once=True)
        return

    # Start Background Tasks
    cleanup_thread = threading.Thread(target=cleanup_loop, args=(db,), daemon=True)
    cleanup_thread.start()

    analysis_thread = threading.Thread(
        target=analysis_loop, args=(db, llm), daemon=True
    )
    analysis_thread.start()

    ip_enrich_thread = threading.Thread(
        target=ip_enrichment_loop, args=(db,), daemon=True
    )
    ip_enrich_thread.start()

    payload_thread = threading.Thread(
        target=payload_download_loop, args=(db,), daemon=True
    )
    payload_thread.start()

    payload_analysis_thread = threading.Thread(
        target=payload_analysis_loop, args=(db,), daemon=True
    )
    payload_analysis_thread.start()

    # Determine Ports
    ssh_port = int(os.getenv("FAUXSSH_PORT", config.get("server", "port") or 2222))

    # Start SSH Server (Main Service)
    # We run SSH in a thread so we can start others too, or keep main thread for healthchecks
    ssh_thread = threading.Thread(target=start_ssh_server, args=(ssh_port, db, llm))
    ssh_thread.daemon = True
    ssh_thread.start()

    # Start Telnet Server (Optional)
    if str(os.getenv("FAUXSSH_ENABLE_TELNET", "true")).lower() == "true":
        t_port = int(os.getenv("FAUXSSH_TELNET_PORT", 2323))
        start_telnet_server(t_port, db, llm)

    # Start Redis Server (Optional)
    if str(os.getenv("FAUXSSH_ENABLE_REDIS", "true")).lower() == "true":
        r_port = int(os.getenv("FAUXSSH_REDIS_PORT", 6379))
        from ssh_honeypot.services.redis.server import start_redis_server

        redis_thread = threading.Thread(
            target=start_redis_server, args=(r_port, db, llm)
        )
        redis_thread.daemon = True
        redis_thread.start()

    # Start MySQL Server (Optional, Enabled by default)
    if str(os.getenv("FAUXSSH_ENABLE_MYSQL", "true")).lower() == "true":
        # Check config first, then env default
        m_port = int(
            os.getenv("FAUXSSH_MYSQL_PORT", config.get("mysql", "port") or 3306)
        )
        try:
            from ssh_honeypot.services.mysql.server import HoneyMySQLHandler

            # MySQL handler is an asyncio server, needs a wrapper for threading
            def start_mysql_wrapper(port, db, llm, cfg):
                # Creating new loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                handler = HoneyMySQLHandler(db, llm, cfg)
                # We need to run the Start logic
                loop.run_until_complete(handler.serve(port=port))
                log.info(f"[*] MySQL Service running on port {port}")
                loop.run_forever()

            mysql_thread = threading.Thread(
                target=start_mysql_wrapper, args=(m_port, db, llm, config)
            )
            mysql_thread.daemon = True
            mysql_thread.start()
        except ImportError:
            log.error("[!] MySQL Service Dependencies missing (mysql-mimic). Skipping.")
        except OSError as e:
            if "Address already in use" in str(e) or e.errno == 98:
                log.warning(f"[!] MySQL Port {m_port} is busy. MySQL service DISABLED.")
            else:
                log.error(f"[!] MySQL Service Failed to Start (OSError): {e}")
        except Exception as e:
            log.error(f"[!] MySQL Service Failed to Start: {e}")

    # Start MCP Server (Optional)
    if str(os.getenv("FAUXSSH_ENABLE_MCP", "true")).lower() == "true":
        mcp_port = int(os.getenv("FAUXSSH_MCP_PORT", 8000))
        try:
            from ssh_honeypot.services.mcp.server import start_mcp_server

            # MCP uses asyncio/uvicorn which is blocking or complex to thread?
            # start_mcp_server calls uvicorn.run which blocks.
            # We must run it in a thread.
            mcp_thread = threading.Thread(
                target=start_mcp_server, args=(mcp_port, db, llm)
            )
            mcp_thread.daemon = True
            mcp_thread.start()
        except ImportError:
            log.error(
                "[!] MCP Service Dependencies missing (mcp, starlette, uvicorn). Skipping."
            )
        except Exception as e:
            log.error(f"[!] MCP Service Failed to Start: {e}")

    # Start HTTP Server (Optional, Enabled by default)
    if str(os.getenv("FAUXSSH_ENABLE_HTTP", "true")).lower() == "true":
        h_port = int(os.getenv("FAUXSSH_HTTP_PORT", config.get("http", "port") or 8080))
        try:
            from ssh_honeypot.services.http_server.server import start_http_server

            http_thread = threading.Thread(
                target=start_http_server, args=(h_port, db, llm)
            )
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
