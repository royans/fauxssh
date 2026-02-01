import requests
import json
import os
import re
import time

import hashlib

try:
    from .config import config
except ImportError:
    from config_manager import config

try:
    from .logging_setup import log
except ImportError:
    from ssh_honeypot.core.logging_setup import log

try:
    from .database import get_db_backend
    from .universal_cache import universal_cache
except ImportError:
    from ssh_honeypot.core.database import get_db_backend
    from ssh_honeypot.core.universal_cache import universal_cache


class LLMInterface:
    def __init__(self, api_key=None):
        # Fetch API KEY lazily, prioritizing config which handles .env loading
        self.provider = config.get("llm", "provider") or "google"

        # --- IPv4 Enforcement ---
        if config.get("llm", "force_ipv4"):
            try:
                import socket
                import urllib3.util.connection as connection

                def allowed_gai_family():
                    """Force IPv4 (AF_INET) for all requests."""
                    return socket.AF_INET

                connection.allowed_gai_family = allowed_gai_family
                log.info("[LLM] Forced IPv4 for API calls (via urllib3 patch)")
            except Exception as e:
                log.error(f"[LLM] Failed to force IPv4: {e}")
        # ------------------------

        raw_key = (
            api_key
            or config.get("llm", "api_key")
            or os.getenv("LLM_API_KEY")
            or os.getenv("GOOGLE_API_KEY")
            or ""
        )
        self.api_key = raw_key.strip()
        log.debug(
            f"LLMInterface Init - Provider: {self.provider}, Key set: {bool(self.api_key)}"
        )

        if not self.api_key and self.provider != "ollama":
            log.warning(
                f"[WARN] No API KEY provided for {self.provider}. LLM calls will fail."
            )

        # Load Prompt Template
        self.prompt_template = ""
        try:
            prompt_path = os.path.join(
                os.path.dirname(__file__), "prompts", "default_prompt.txt"
            )
            with open(prompt_path, "r") as f:
                self.prompt_template = f.read()
        except Exception as e:
            log.error(f"[!] Error loading prompt template: {e}")
            self.prompt_template = "Error: Prompt template missing."

    def query(self, prompt, protocol="generic", **kwargs):
        """
        Generic query method for arbitary prompts (used by MySQL/Redis layers).
        """
        return self._call_api(prompt, protocol=protocol)

    def generate_response(
        self,
        command,
        cwd,
        user="root",
        history_context=[],
        file_list=[],
        known_paths=[],
        client_ip="Unknown",
        honeypot_ip="192.168.1.55",
        override_prompt=None,
        persona_config=None,
        protocol="ssh",
        **kwargs,
    ):
        """
        Generates a terminal response for the given command.
        history_context: List of tuples (cmd, response) for context.
        file_list: List of filenames in current directory (for realism).
        known_paths: List of directory paths that definitely exist in the VFS.
        override_prompt: If set, ignores the template and sends this string directly to LLM.
        persona_config: Optional config dict to override global persona settings (e.g. prompt).
        """
        log.debug(
            f"generate_response called for '{command}'. Key Len: {len(self.api_key) if self.api_key else 0}"
        )
        if not self.api_key and self.provider != "ollama":
            return self._get_bash_fallback(command, protocol=protocol)

        # If raw prompt override is provided, skip template logic
        if override_prompt:
            res = self._call_api(override_prompt)
            if "INTERNAL_ERROR" in res:
                return self._get_bash_fallback(command, protocol=protocol)
            return res

        # Construct Context String
        history_str = ""
        for item in history_context[-5:]:  # Last 5 commands
            # Unpack safely (handle 2 or 3 items)
            if len(item) >= 2:
                cmd = item[0]
                resp = item[1]
            else:
                continue

            # Parse previous JSON responses if they exist in history, otherwise treat as text
            try:
                if resp and resp.strip().startswith("{"):
                    r_json = json.loads(resp)
                    resp_text = (r_json or {}).get("output", "")
                else:
                    resp_text = resp or ""
            except:
                resp_text = resp or ""

            # Filter out "command not found" errors from context to prevent LLM repetition loops
            if "command not found" in resp_text:
                continue

            # Remove ANSI codes for LLM context clarity
            resp_clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", resp_text)
            resp_short = (
                resp_clean[:150].replace("\n", " ") + "..."
                if len(resp_clean) > 150
                else resp_clean.replace("\n", " ")
            )
            history_str += f"User: {cmd}\nOutput: {resp_short}\n---\n"

        file_list_str = ", ".join(file_list) if file_list else "(Empty)"
        paths_str = ", ".join(known_paths) if known_paths else "/home/alabaster /tmp"

        # Fill Template
        try:
            # 1. Try Persona Prompt (Local Context Override -> Global Config)
            template = None
            if persona_config:
                # Check nested keys strictly
                if "prompts" in persona_config and persona_config["prompts"]:
                    template = persona_config["prompts"].get("system_prompt")

            if not template:
                template = config.get("persona", "prompts", "system_prompt")

            # 2. Fallback to File
            if not template:
                template = self.prompt_template

            # Ensure user is valid (fallback to root if somehow None)
            current_user = user if user else "root"

            # Determine hostname from persona or config
            host_val = None
            if (
                persona_config
                and "system" in persona_config
                and persona_config["system"]
            ):
                host_val = persona_config["system"].get("hostname")
            if not host_val:
                host_val = config.get("server", "hostname") or "npc-main-server-01"

            # Load Extra Instructions based on command (Modular Prompts)
            extra_instructions = ""
            try:
                if command and command.strip():
                    base_cmd = command.split()[0].strip()
                    # Basic sanitization to prevent path traversal
                    base_cmd = re.sub(r"[^a-zA-Z0-9_\-]", "", base_cmd).lower()

                    rule_path = os.path.join(
                        os.path.dirname(__file__), "prompts", "rules", f"{base_cmd}.txt"
                    )
                    if os.path.exists(rule_path):
                        with open(rule_path, "r") as f:
                            extra_instructions = f.read()
            except Exception as e:
                log.warning(f"Error loading extra instructions: {e}")

            prompt = template.format(
                hostname=host_val,
                user=current_user,
                honeypot_ip=honeypot_ip,
                client_ip=client_ip,
                cwd=cwd,
                file_list_str=file_list_str,
                paths_str=paths_str,
                history_str=history_str,
                command=command,
                extra_instructions=extra_instructions,
            )
        except Exception as e:
            log.error(f"[!] Prompt Formatting Error: {e}")
            return '{"output": "Error: Internal System Error", "new_cwd": null}'

        res = self._call_api(prompt, protocol=protocol)
        if "INTERNAL_ERROR" in res:
            return self._get_bash_fallback(command, protocol=protocol)
        return res

    def _get_bash_fallback(self, command, protocol="ssh"):
        """Standard bash fallback for missing/failed LLM."""
        if protocol == "http":
            return "<html><body><h1>500 Internal Server Error</h1><p>The server encountered an internal error and was unable to complete your request.</p></body></html>"
        if protocol == "mysql":
            return "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)"
        if protocol == "redis":
            return "-ERR internal error"

        cmd_base = command.split()[0] if command else ""
        if cmd_base in ["curl", "wget", "ssh", "nc", "ping"]:
            return (
                "ssh: connect to host example.com port 22: Connection timed out"
                if cmd_base == "ssh"
                else f"{cmd_base}: unable to resolve host address"
            )
        return f"bash: {cmd_base}: command not found"

    def generate_content(self, command, url, persona_summary):
        """
        Generates dynamic content (HTML/JSON) for wget/curl emulation.
        """
        try:
            template = config.get("persona", "prompts", "generate_content")
            if not template:
                return "Error: Content generation not configured."

            prompt = template.format(
                command=command, url=url, persona_summary=persona_summary
            )
            return self._call_api(
                prompt, command=command, is_command=False, protocol="http"
            )
        except Exception as e:
            log.error(f"[!] Content Generation Error: {e}")
            return "Error: Content generation failed."

    def _call_api(self, prompt, command=None, is_command=True, protocol="ssh"):
        # 1. Check Cache
        prompt_hash = hashlib.md5(prompt.encode()).hexdigest()

        cached_item = universal_cache.get("llm", prompt_hash)
        if cached_item:
            log.debug(f"[LLM] Cache Hit for hash {prompt_hash[:8]}")
            return cached_item["output_text"]

        log.debug(f"[LLM] Cache Miss for hash {prompt_hash[:8]}")

        # Global Rate Limit Check
        db_backend = get_db_backend()
        l_rpm = config.get("throttling", "global", "google_llm", "rpm") or 10
        l_rph = config.get("throttling", "global", "google_llm", "rph") or 400
        l_rpd = config.get("throttling", "global", "google_llm", "rpd") or 10000

        allowed, reason = db_backend.check_api_rate_limit(
            "google_llm", "GLOBAL", l_rpm, l_rph, l_rpd
        )
        if not allowed:
            # SHHH: Silent return for rate limit blocks to prevent debug file spam
            log.warning(f"[LLM] Global Rate Limit Block: {reason}")
            return '{"output": "Error: System resources exhausted. Please try again later.", "new_cwd": null}'

        db_backend.record_api_usage("google_llm", "GLOBAL")

        # Route to provider
        if self.provider == "openai":
            return self._call_openai(prompt, prompt_hash, command, is_command, protocol)
        elif self.provider == "ollama":
            return self._call_ollama(prompt, prompt_hash, command, is_command, protocol)
        else:
            return self._call_google(prompt, prompt_hash, command, is_command, protocol)

    def _call_google(
        self, prompt, prompt_hash, command=None, is_command=True, protocol="ssh"
    ):
        headers = {"Content-Type": "application/json"}
        data = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 1.0,
                "maxOutputTokens": 2048,
                "responseMimeType": "text/plain",
            },
        }

        model_name = config.get("llm", "model_name") or "gemini-pro"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={self.api_key}"

        try:
            timeout_val = config.get("llm", "timeout") or 60
            resp = requests.post(url, headers=headers, json=data, timeout=timeout_val)
            return self._handle_provider_response(
                resp,
                prompt,
                prompt_hash,
                command,
                is_command,
                provider="google",
                protocol=protocol,
            )
        except Exception as e:
            return self._handle_provider_exception(e, "google_request")

    def _call_openai(
        self, prompt, prompt_hash, command=None, is_command=True, protocol="ssh"
    ):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        data = {
            "model": config.get("llm", "model_name") or "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 1.0,
        }
        url = "https://api.openai.com/v1/chat/completions"
        try:
            timeout_val = config.get("llm", "timeout") or 60
            resp = requests.post(url, headers=headers, json=data, timeout=timeout_val)
            return self._handle_provider_response(
                resp,
                prompt,
                prompt_hash,
                command,
                is_command,
                provider="openai",
                protocol=protocol,
            )
        except Exception as e:
            return self._handle_provider_exception(e, "openai_request")

    def _call_ollama(
        self, prompt, prompt_hash, command=None, is_command=True, protocol="ssh"
    ):
        url = config.get("llm", "ollama_url") or "http://localhost:11434/api/generate"
        data = {
            "model": config.get("llm", "model_name") or "llama3",
            "prompt": prompt,
            "stream": False,
        }
        try:
            timeout_val = config.get("llm", "timeout") or 60
            resp = requests.post(url, json=data, timeout=timeout_val)
            return self._handle_provider_response(
                resp,
                prompt,
                prompt_hash,
                command,
                is_command,
                provider="ollama",
                protocol=protocol,
            )
        except Exception as e:
            return self._handle_provider_exception(e, "ollama_request")

    def _handle_provider_response(
        self,
        resp,
        prompt,
        prompt_hash,
        command,
        is_command,
        provider="google",
        protocol="ssh",
    ):
        if resp.status_code != 200:
            err_msg = f"[!] LLM API Error ({provider}) {resp.status_code}: {resp.text}"
            log.error(err_msg)

        # One-line status log for API calls (as requested)
        summary = "Generic"
        if command:
            if is_command:
                summary = f"CMD: {command}"
            elif "cybersecurity" in prompt.lower() or "risk" in prompt.lower():
                summary = f"Risk: {command}"
            elif "Threat Intelligence Analyst" in prompt:
                summary = f"Sess: {command}"
            elif "persona_summary" in prompt:  # Heuristic for generate_content
                summary = f"Page: {command}"
            else:
                summary = f"Query: {command}"
        elif "Reply with exactly" in prompt:
            summary = "API Verify"

        if len(summary) > 40:
            summary = summary[:37] + "..."

        log.info(
            f"[LLM] {provider.capitalize()} API ({protocol.upper()}): {summary} -> {resp.status_code} ({len(resp.content)} bytes)"
        )

        if resp.status_code != 200:

            # Save error info for debug
            try:
                debug_dir = "/tmp/llm_debug"
                if os.path.exists(debug_dir):
                    err_file = os.path.join(
                        debug_dir, f"error_{provider}_{int(time.time()*1000)}.txt"
                    )
                    with open(err_file, "w") as f:
                        f.write(
                            f"Status: {resp.status_code}\nResponse: {resp.text}\nPrompt Hash: {prompt_hash}"
                        )
            except:
                pass
            return '{"output": "INTERNAL_ERROR", "new_cwd": null}'

        resp_json = resp.json()
        try:
            if provider == "google":
                text = resp_json["candidates"][0]["content"]["parts"][0]["text"]
            elif provider == "openai":
                text = resp_json["choices"][0]["message"]["content"]
            elif provider == "ollama":
                text = resp_json["response"]

            text = text.strip()
            # Strip Markdown
            text = re.sub(r"^```[a-zA-Z0-9+-]*\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
            final_text = text.strip()

            # Perform Risk Analysis if it's a command response
            risk_score = 0
            attack_stage = "Unknown"
            explanation = None

            if is_command and command:
                try:
                    analysis = self.analyze_command(command)
                    risk_score = analysis.get("risk", 0)
                    attack_stage = f"{analysis.get('type', 'Unknown')} ({analysis.get('stage', 'Unknown')})"
                    explanation = analysis.get("explanation")
                except Exception as e:
                    log.warning(f"[LLM] Risk analysis failed: {e}")

            # 2. Save to Universal Cache
            universal_cache.set(
                service="llm",
                key=prompt_hash,
                input_text=prompt,
                output_text=final_text,
                risk_score=risk_score,
                attack_stage=attack_stage,
                explanation=explanation,
                ttl_days=30,
            )
            return final_text
        except Exception as e:
            log.error(f"[!] LLM Response Parsing Error ({provider}): {e}")
            return '{"output": "Error: Parsing Failure.", "new_cwd": null}'

    def _handle_provider_exception(self, e, tag):
        log.error(f"[!] LLM Request Exception ({tag}): {e}")
        try:
            debug_dir = "/tmp/llm_debug"
            if os.path.exists(debug_dir):
                err_file = os.path.join(
                    debug_dir, f"exception_{tag}_{int(time.time()*1000)}.txt"
                )
                with open(err_file, "w") as f:
                    f.write(f"Exception: {e}\n")
        except:
            pass
        return '{"output": "Error: Network Failure.", "new_cwd": null}'

    def verify_api(self):
        """Simple check to see if API Key works."""
        val = self._call_api("Reply with exactly the word 'OK'.", is_command=False)
        return "OK" in val

    def analyze_command(self, command):
        """
        Analyzes a command for security context.
        Returns dict: {type, stage, risk, explanation}
        """
        try:
            # 1. Try Persona Prompt
            template = config.get("persona", "prompts", "analysis")

            # 2. Fallback
            if not template:
                prompt_path = os.path.join(
                    os.path.dirname(__file__), "prompts", "analysis_prompt.txt"
                )
                with open(prompt_path, "r") as f:
                    template = f.read()

        except:
            # Fallback prompt if file missing
            template = """
             You are a cybersecurity expert analyzing attacker commands in a honeypot.
             Analyze the following command: '{command}'
             
             Return ONLY a JSON object with these keys:
             - type: (Reconnaissance, Execution, Persistence, etc.)
             - stage: (Recon, Weaponization, Delivery, Exploitation, Installation, C2, Actions)
             - risk: (Integer 0-100)
             - explanation: (Brief 1 sentence)
             - mitre_technique_id: (Optional String, e.g. "T1059.004")
             """

        prompt = template.replace("{command}", command)

        raw_json = self._call_api(
            prompt, command=command, is_command=False, protocol="analytics"
        )
        try:
            data = json.loads(raw_json)
            return {
                "type": data.get("type", "Unknown"),
                "stage": data.get("stage", "Unknown"),
                "risk": int(data.get("risk", 0)),
                "explanation": data.get(
                    "explanation", "Analysis Failed: Invalid Response"
                ),
            }
        except Exception as e:
            return {
                "type": "Unknown",
                "stage": "Unknown",
                "risk": 0,
                "explanation": f"Analysis Failed: {e}",
            }

    def analyze_batch(self, commands):
        """
        Analyzes a batch of commands.
        commands: list of (hash, text) tuples
        Returns: dict mapping hash -> {type, stage, risk, explanation}
        """
        if not commands:
            return {}

        # Prepare Input JSON
        # Deduplicate commands by hash to save tokens
        unique_map = {h: t for h, t in commands}
        input_list = [{"hash": h, "text": t} for h, t in unique_map.items()]
        input_json = json.dumps(input_list, indent=2)

        try:
            prompt_path = os.path.join(
                os.path.dirname(__file__), "prompts", "batch_analysis_prompt.txt"
            )
            with open(prompt_path, "r") as f:
                template = f.read()
        except:
            # Fallback
            template = """
             Analyze these commands for cybersecurity risk. Return JSON list with hash and analysis object (type, stage, risk, explanation).
             Input: {commands_json}
             """

        prompt = template.replace("{commands_json}", input_json)

        # --- DEBUG LOGGING START ---
        try:
            debug_dir = "/tmp/llm_debug"
            if not os.path.exists(debug_dir):
                os.makedirs(debug_dir)

            # Simple rotation logic: check files, find max ID or timestamp
            # Actually easier: use timestamp-based names, list all, sort, delete old
            timestamp = int(time.time() * 1000)
            prompt_file = os.path.join(debug_dir, f"prompt_{timestamp}.txt")
            with open(prompt_file, "w") as f:
                f.write(prompt)

            # Cleanup older files (Keep last 20 prompts)
            all_files = sorted(
                [
                    os.path.join(debug_dir, f)
                    for f in os.listdir(debug_dir)
                    if f.startswith("prompt_")
                ]
            )
            if len(all_files) > 20:
                for f in all_files[:-20]:
                    try:
                        os.remove(f)
                    except:
                        pass
        except Exception as e:
            log.warning(f"[LLM] Debug logging failed (prompt): {e}")
        # --- DEBUG LOGGING END ---

        raw_json = self._call_api(
            prompt, command="BATCH", is_command=False, protocol="analytics"
        )

        # --- DEBUG LOGGING START (RESPONSE) ---
        try:
            resp_file = os.path.join(debug_dir, f"response_{timestamp}.txt")
            with open(resp_file, "w") as f:
                f.write(raw_json)

            # Cleanup older files (Keep last 20 responses)
            all_files = sorted(
                [
                    os.path.join(debug_dir, f)
                    for f in os.listdir(debug_dir)
                    if f.startswith("response_")
                ]
            )
            if len(all_files) > 20:
                for f in all_files[:-20]:
                    try:
                        os.remove(f)
                    except:
                        pass
        except Exception as e:
            log.warning(f"[LLM] Debug logging failed (response): {e}")
        # --- DEBUG LOGGING END ---

        results = {}

        try:
            # Parse List
            data = json.loads(raw_json)
            if isinstance(data, list):
                for item in data:
                    h = item.get("hash")
                    an = item.get("analysis", {})
                    if h:
                        results[h] = {
                            "type": an.get("type", "Unknown"),
                            "stage": an.get("stage", "Unknown"),
                            "risk": int(an.get("risk", 0)),
                            "explanation": an.get("explanation", "Batch Analysis"),
                        }
        except Exception as e:
            log.error(
                f"[LLM] Batch Analysis Parsing Error: {e} | Raw Response: {raw_json[:200]}"
            )

        return results

    def generate_session_summary(self, session_history):
        """
        Generates a narrative summary and risk score for a full session.
        session_history: List of strings (command inputs).
        """
        if not session_history:
            return None

        # Heuristic for common discovery-only sessions to save LLM tokens
        common_discovery = {"ls", "whoami", "uname", "id", "pwd", "cat /etc/passwd"}
        if len(session_history) <= 3 and all(
            c.strip() in common_discovery for c in session_history
        ):
            return {
                "summary": f"Attacker performed basic discovery: {', '.join(session_history)}",
                "risk_score": 10,
                "mitre_codes": ["T1592"],
            }

        history_text = "\n".join([f"Cmd: {c}" for c in session_history])

        prompt = f"""
        You are a Threat Intelligence Analyst.
        Review this SSH session transcript:
        ---
        {history_text}
        ---
        
        Task:
        1. Provide a brief 1-sentence narrative summary of the attacker's intent and tools used.
        2. Assign a Risk Score (0-100) based on these heuristics:
            - 0-30: Reconnaissance, basic discovery (ls, whoami, uname).
            - 30-60: Probing specific vulnerabilities, non-standard commands.
            - 60-80: Attempts to write files, modify config, known exploitation attempts.
            - 80-100: Critical Risk. POST requests with payloads, downloading payloads (wget/curl/scp), execution of downloaded payloads, persistence mechanisms.
        3. Identify any relevant MITRE ATT&CK Technique IDs (e.g. T1059.004).
        
        Return ONLY a JSON object:
        {{
            "summary": "Attacker probed to...",
            "risk_score": 85,
            "mitre_codes": ["T1059", "T1003"]
        }}
        """

        raw_json = self._call_api(
            prompt, command="SESSION", is_command=False, protocol="analytics"
        )
        try:
            return json.loads(raw_json)
        except Exception as e:
            log.error(f"[LLM] Session Summary Parse Error: {e} | Raw: {raw_json[:100]}")
            return None
