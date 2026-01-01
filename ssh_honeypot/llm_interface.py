import requests
import json
import os
import re

try:
    from .config_manager import config
except ImportError:
    from config_manager import config

# Configuration loaded from config_manager


class LLMInterface:
    def __init__(self, api_key=None):
        # Fetch API KEY lazily to ensure environment is loaded
        raw_key = api_key or os.getenv("GOOGLE_API_KEY") or ""
        self.api_key = raw_key.strip()
        print(f"[DEBUG] LLMInterface Init - api_key arg: {bool(api_key)}, self.api_key set: {bool(self.api_key)} (Len: {len(self.api_key)})")
        
        if not self.api_key:
            print("[WARN] No GOOGLE_API_KEY provided. LLM calls will fail.")

        # Load Prompt Template
        self.prompt_template = ""
        try:
            prompt_path = os.path.join(os.path.dirname(__file__), 'prompts', 'default_prompt.txt')
            with open(prompt_path, 'r') as f:
                self.prompt_template = f.read()
        except Exception as e:
            print(f"[!] Error loading prompt template: {e}")
            self.prompt_template = "Error: Prompt template missing."


    def generate_response(self, command, cwd, history_context=[], file_list=[], known_paths=[], client_ip="Unknown", honeypot_ip="192.168.1.55", override_prompt=None):
        """
        Generates a terminal response for the given command.
        history_context: List of tuples (cmd, response) for context.
        file_list: List of filenames in current directory (for realism).
        known_paths: List of directory paths that definitely exist in the VFS.
        override_prompt: If set, ignores the template and sends this string directly to LLM.
        """
        print(f"[DEBUG] generate_response called for '{command}'. Key Len: {len(self.api_key) if self.api_key else 0}", flush=True)
        if not self.api_key:
            return '{"output": "Error: AI Core Offline.", "cwd_update": null}'

        # If raw prompt override is provided, skip template logic
        if override_prompt:
             return self._call_api(override_prompt)

        # Construct Context String
        history_str = ""
        for cmd, resp in history_context[-5:]: # Last 5 commands
            # Parse previous JSON responses if they exist in history, otherwise treat as text
            try:
                if resp.strip().startswith('{'):
                    r_json = json.loads(resp)
                    resp_text = r_json.get('output', '')
                else:
                    resp_text = resp
            except:
                resp_text = resp
            
            # Filter out "command not found" errors from context to prevent LLM repetition loops
            if "command not found" in resp_text:
                continue

            # Remove ANSI codes for LLM context clarity
            resp_clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', resp_text)
            resp_short = resp_clean[:150].replace('\n', ' ') + "..." if len(resp_clean) > 150 else resp_clean.replace('\n', ' ')
            history_str += f"User: {cmd}\nOutput: {resp_short}\n---\n"

        file_list_str = ", ".join(file_list) if file_list else "(Empty)"
        paths_str = ", ".join(known_paths) if known_paths else "/home/alabaster /tmp"

        # Fill Template
        try:
            prompt = self.prompt_template.format(
                hostname=config.get('server', 'hostname') or 'npc-main-server-01',
                user="alabaster", # TODO: pass user from context
                honeypot_ip=honeypot_ip,
                client_ip=client_ip,
                cwd=cwd,
                file_list_str=file_list_str,
                paths_str=paths_str,
                history_str=history_str,
                command=command
            )
        except Exception as e:
            print(f"[!] Prompt Formatting Error: {e}")
            return '{"output": "Error: Internal System Error", "new_cwd": null}'

        
        return self._call_api(prompt)

    def _call_api(self, prompt):
        headers = {'Content-Type': 'application/json'}
        data = {
            "contents": [{
                "role": "user",
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 1.0,
                "maxOutputTokens": 2048,
                "responseMimeType": "text/plain"
            }
        }

        try:
            model_name = config.get('llm', 'model_name') or "gemma-3-27b-it"
            resp = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={self.api_key}",
                headers=headers,
                data=json.dumps(data),
                timeout=60
            )
            resp.raise_for_status()
            
            result = resp.json()
            # Parse Gemini Response
            if 'candidates' in result and result['candidates']:
                text = result['candidates'][0]['content']['parts'][0]['text']
                # Cleanup markdown blocks if LLM ignores instruction
                # Remove ```json or ```bash or just ``` lines
                text = re.sub(r'^```\w*\n?', '', text)
                text = re.sub(r'\n?```$', '', text)
                text = text.strip()
                return text
            else:
                return "" # Empty response or blocked
                
        except Exception as e:
            print(f"[LLM Error] {e}")
            return "bash: fork: retry: Resource temporarily unavailable"
