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
        if "client_ip" not in kwargs:
            kwargs["client_ip"] = "Unknown"
        return self._call_api(prompt, protocol=protocol, **kwargs)

    def _get_coarse_cache_key(self, command, cwd, user):
        """
        Generates a coarse cache key for repetitive commands, independent of
        Client IP and Session History.
        """
        if not command:
            return None

        # Sanitize command for key (norm whitespace, lower)
        clean_cmd = " ".join(command.lower().split())

        # We include CWD and User to stay realistic, but skip IP and History
        data = f"cmd:{clean_cmd}|cwd:{cwd}|user:{user}"
        return hashlib.md5(data.encode()).hexdigest()

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
        return_source=False,
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
            res, source = self._call_api(override_prompt, return_source=True)
            if "INTERNAL_ERROR" in res:
                fallback = self._get_bash_fallback(command, protocol=protocol)
                if return_source:
                    return fallback, "error"
                return fallback
            if return_source:
                return res, source
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
            resp = '{"output": "Error: Internal System Error", "new_cwd": null}'
            if return_source:
                return resp, "error"
            return resp

        # 3. Generate Coarse Cache Key (Optimization for Redundancy)
        coarse_key = self._get_coarse_cache_key(command, cwd, user)

        res, source = self._call_api(
            prompt,
            command=command,
            protocol=protocol,
            return_source=True,
            client_ip=client_ip,
            coarse_key=coarse_key,
            **kwargs,
        )
        if "INTERNAL_ERROR" in res:
            fallback = self._get_bash_fallback(command, protocol=protocol)
            if return_source:
                return fallback, "error"
            return fallback

        if return_source:
            return res, source
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

    def generate_content(
        self, command, url, persona_summary, return_source=False, **kwargs
    ):
        """
        Generates dynamic content (HTML/JSON) for wget/curl emulation.
        """
        try:
            template = config.get("persona", "prompts", "generate_content")
            if not template:
                resp = "Error: Content generation not configured."
                if return_source:
                    return resp, "error"
                return resp

            prompt = template.format(
                command=command, url=url, persona_summary=persona_summary
            )
            res, source = self._call_api(
                prompt,
                command=command,
                is_command=False,
                protocol="http",
                return_source=True,
                client_ip=kwargs.get("client_ip", "Unknown"),
                **kwargs,
            )
            if return_source:
                return res, source
            return res
        except Exception as e:
            log.error(f"[!] Content Generation Error: {e}")
            resp = "Error: Content generation failed."
            if return_source:
                return resp, "error"
            return resp

    def _call_api(
        self,
        prompt,
        command=None,
        is_command=True,
        protocol="ssh",
        return_source=False,
        client_ip="Unknown",
        coarse_key=None,
        **kwargs,
    ):
        # 1. Check Global Cache (Specific Prompt)
        prompt_hash = hashlib.md5(prompt.encode()).hexdigest()

        cached_item = universal_cache.get("llm", prompt_hash)
        if not cached_item and coarse_key:
            # Try Coarse Cache (Generic Command)
            cached_item = universal_cache.get("llm-coarse", coarse_key)
            if cached_item:
                log.debug(f"[LLM] Coarse Cache Hit for {command} ({coarse_key[:8]})")

        if cached_item:
            output = cached_item["output_text"]

            # Validation: Check for "Thinking" artifacts
            if self._is_thinking_artifact(output):
                log.warning(
                    f"[LLM] Detected 'Thinking' artifact in cache. Invalidating key {prompt_hash}."
                )
                universal_cache.delete("llm", prompt_hash)
                # Return it anyway as per user request ("ok to present for now")
                if return_source:
                    return output, "llm-cache (tainted)"
                return output

            # Validation: Check for cached resource errors (TAINTED CACHE)
            if "system resources exhausted" in str(output).lower():
                log.warning(
                    f"[LLM] Detected Resource Exhaustion error in cache. Invalidating key {prompt_hash} and retrying."
                )
                universal_cache.delete("llm", prompt_hash)
                # Proceed to Cache Miss logic (fall through) to retry generation
            else:
                log.debug(f"[LLM] Cache Hit for hash {prompt_hash[:8]}")
                if return_source:
                    return output, "llm-cache"
                return output

        log.debug(f"[LLM] Cache Miss for hash {prompt_hash[:8]}")

        # Rate Limit Logic
        if os.getenv("FAUXSSH_TEST_MODE") == "1":
            log.debug("[LLM] Bypassing rate limit check in Test Mode")
            allowed_global = True
            allowed_ip = True
        else:
            db_backend = get_db_backend()
            # client_ip is now an explicit argument

            # Global Rate Limit
            l_rpm = config.get("throttling", "global", "google_llm", "rpm") or 10
            l_rph = config.get("throttling", "global", "google_llm", "rph") or 400
            l_rpd = config.get("throttling", "global", "google_llm", "rpd") or 10000
            allowed_global, reason_global = db_backend.check_api_rate_limit(
                "google_llm", "GLOBAL", l_rpm, l_rph, l_rpd
            )

            # Per-IP Rate Limit (Stricter)
            ip_rpm = config.get("throttling", "per_ip", "google_llm", "rpm") or 5
            ip_rph = config.get("throttling", "per_ip", "google_llm", "rph") or 50
            ip_rpd = config.get("throttling", "per_ip", "google_llm", "rpd") or 200
            allowed_ip, reason_ip = db_backend.check_api_rate_limit(
                "google_llm", client_ip, ip_rpm, ip_rph, ip_rpd
            )

        if not allowed_global or not allowed_ip:
            source = "ratelimit-global" if not allowed_global else "ratelimit-ip"
            reason = reason_global if not allowed_global else reason_ip
            log.warning(f"[LLM] Rate Limit Block ({source}): {reason}")

            # Realistic Responses
            if protocol == "http":
                resp = '{"output": "Error: 404 Not Found", "status": 404}'
            elif protocol == "mysql":
                resp = "{\"output\": \"ERROR 1045 (28000): Access denied for user 'root'@'localhost'\"}"
            else:
                resp = (
                    '{"output": "bash: fork: retry: Resource temporarily unavailable"}'
                )

            if return_source:
                return resp, source
            return resp

        if os.getenv("FAUXSSH_TEST_MODE") != "1":
            db_backend = get_db_backend()
            db_backend.record_api_usage("google_llm", "GLOBAL")
            if client_ip and client_ip != "Unknown":
                db_backend.record_api_usage("google_llm", client_ip)

        # Route to provider
        if self.provider == "openai":
            res = self._call_openai(prompt, prompt_hash, command, is_command, protocol)
        elif self.provider == "ollama":
            res = self._call_ollama(prompt, prompt_hash, command, is_command, protocol)
        else:
            res = self._call_google(prompt, prompt_hash, command, is_command, protocol)

        # Final Guard: Check for Resource Exhaustion in result (double check)
        if res and "system resources exhausted" in str(res).lower():
            log.warning(
                f"[LLM] Detected Resource Exhaustion in API result. Returning error state."
            )
            return '{"output": "INTERNAL_ERROR", "new_cwd": null}'

        # 4. Save to Cache
        try:
            # Save to specific prompt cache
            universal_cache.set("llm", prompt_hash, res)

            # Save to coarse cache if applicable
            if coarse_key:
                universal_cache.set("llm-coarse", coarse_key, res)
        except Exception as e:
            log.error(f"[LLM] Failed to save to cache: {e}")

        if return_source:
            return res, "llm"
        return res

    def _is_thinking_artifact(self, text):
        """
        Checks if the text contains LLM 'thinking' or meta-commentary artifacts.
        """
        if not text:
            return False

        # Common starter phrases for refusal/explanation
        patterns = [
            r"^Okay, here is",
            r"^Here is a (realistic|simulated)",
            r"^Sure, I can",
            r"^I cannot",
            r"^As an AI",
            r"^\*\*Response:\*\*",
            r"^Response:",
            r"I will prioritize",
            r"I'll allow this",
        ]

        for p in patterns:
            if re.search(p, text, re.IGNORECASE | re.MULTILINE):
                return True

        return False

    def _call_google(
        self, prompt, prompt_hash, command=None, is_command=True, protocol="ssh"
    ):
        headers = {"Content-Type": "application/json"}
        model_name = config.get("llm", "model_name") or "gemini-pro"
        generation_config = {
            "temperature": 1.0,
            "maxOutputTokens": 8192,
        }
        if "gemini" in model_name.lower():
            generation_config["responseMimeType"] = "application/json"

        data = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": generation_config,
        }
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
                    # Try to extract bundled analysis first (optimization)
                    bundled_analysis = None
                    try:
                        bundled_json = json.loads(final_text)
                        if (
                            isinstance(bundled_json, dict)
                            and "analysis" in bundled_json
                        ):
                            bundled_analysis = bundled_json["analysis"]
                    except:
                        pass

                    if bundled_analysis:
                        risk_score = int(bundled_analysis.get("risk", 0))
                        attack_stage = f"{bundled_analysis.get('type', 'Unknown')} ({bundled_analysis.get('stage', 'Unknown')})"
                        explanation = bundled_analysis.get("explanation")
                        log.debug(
                            f"[LLM] Using bundled 'free' analysis for '{command}'"
                        )
                    else:
                        # Fallback to separate call if not bundled or failed parsing
                        analysis = self.analyze_command(command)
                        risk_score = analysis.get("risk", 0)
                        attack_stage = f"{analysis.get('type', 'Unknown')} ({analysis.get('stage', 'Unknown')})"
                        explanation = analysis.get("explanation")
                except Exception as e:
                    log.warning(f"[LLM] Risk analysis failed: {e}")

            # 2. Save to Universal Cache
            # Guard: If error detected (and not already caught by universal_cache which returns False),
            # we should return an error state so server.py sends 404/500 instead of JSON.
            if "System resources exhausted" in final_text:
                log.warning(
                    f"[LLM] Detected Resource Exhaustion in response. Returning error state."
                )
                return '{"output": "INTERNAL_ERROR", "new_cwd": null}'

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

        raw_json, _ = self._call_api(
            prompt,
            command=command,
            is_command=False,
            protocol="analytics",
            return_source=True,
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
            # Attempt to repair truncated JSON (common with batch limits)
            try:
                repaired_json = self._repair_json_list(raw_json)
                data = json.loads(repaired_json)
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
                    log.warning(
                        f"[LLM] Successfully repaired truncated JSON response. Recovered {len(results)} items."
                    )
            except Exception as repair_error:
                log.error(
                    f"[LLM] Batch Analysis Parsing Error: {e} | Repair Failed: {repair_error} | Raw Response: {raw_json[:200]}"
                )

        return results

    def _repair_json_list(self, raw_json):
        """
        Attempts to repair a truncated JSON list of objects.
        Strategies:
        1. Find last closing brace '}', truncate there, append ']'.
        """
        raw_json = raw_json.strip()
        if not raw_json.startswith("["):
            raise ValueError("Not a JSON list")

        # Find last valid object closure
        last_brace = raw_json.rfind("}")
        if last_brace == -1:
            raise ValueError("No valid objects found")

        # Truncate and close
        repaired = raw_json[: last_brace + 1] + "]"
        return repaired

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
