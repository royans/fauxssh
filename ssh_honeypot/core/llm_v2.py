import google.generativeai as genai
import json
import os
import re
import logging
from .config import config

# Use existing logging setup
try:
    from .logging_setup import log
except ImportError:
    from ssh_honeypot.core.logging_setup import log

class BaseLLMProvider:
    """Abstract Base Class for LLM Providers"""
    def generate(self, prompt, context=None):
        raise NotImplementedError

class GeminiProvider(BaseLLMProvider):
    """Google Gemini Implementation"""
    def __init__(self, api_key, model_name="gemini-pro"):
        self.api_key = api_key
        if not self.api_key:
            log.warning("[WARN] No GOOGLE_API_KEY provided. Gemini calls will fail.")
            self.model = None
            return

        try:
            genai.configure(api_key=self.api_key)
            if not model_name.startswith("models/") and not model_name.startswith("gemini"):
                    model_name = f"models/{model_name}"
            self.model = genai.GenerativeModel(model_name)
        except Exception as e:
            log.error(f"Failed to initialize Gemini Model: {e}")
            self.model = None

    def generate(self, prompt, context=None):
        if not self.model:
            return '{"output": "Error: AI Core Offline (No Model).", "new_cwd": null}'
        
        try:
            generation_config = genai.types.GenerationConfig(
                temperature=1.0,
                max_output_tokens=2048,
                candidate_count=1
            )
            response = self.model.generate_content(prompt, generation_config=generation_config)
            
            if response.text:
                text = response.text
                text = text.replace('```json', '').replace('```', '').strip()
                return text
            else:
                 return '{"output": "Error: No response text.", "new_cwd": null}'
        except Exception as e:
             log.error(f"[GeminiProvider] Generate Error: {e}")
             return '{"output": "Error: AI Provider Failure.", "new_cwd": null}'

class LLMInterfaceV2:
    """
    LLM Interface V2 - Extensible Provider Architecture.
    """
    def __init__(self, api_key=None):
        # Determine Provider from config or env
        # Future: os.getenv("FAUXSSH_LLM_PROVIDER", "gemini")
        self.provider_name = "gemini" 
        
        # Load Prompt Template (Shared)
        self.prompt_template = ""
        try:
            prompt_path = os.path.join(os.path.dirname(__file__), 'prompts', 'default_prompt.txt')
            with open(prompt_path, 'r') as f:
                self.prompt_template = f.read()
        except Exception as e:
            log.error(f"[!] Error loading prompt template: {e}")
            self.prompt_template = "Error: Prompt template missing."
            
        # Initialize Provider
        if self.provider_name == "gemini":
            # Fetch API KEY lazily
            raw_key = api_key or os.getenv("GOOGLE_API_KEY") or ""
            key = raw_key.strip()
            model = config.get('llm', 'model_name') or "gemini-pro"
            self.provider = GeminiProvider(key, model)
        else:
            log.error(f"Unknown LLM Provider: {self.provider_name}")
            self.provider = None

    def generate_response(self, command, cwd, user="root", history_context=[], file_list=[], known_paths=[], client_ip="Unknown", honeypot_ip="192.168.1.55", override_prompt=None, persona_config=None):
        """
        Generates a terminal response for the given command.
        """
        if not self.provider:
             return '{"output": "Error: No LLM Provider Configured.", "cwd_update": null}'

        # If raw prompt override is provided
        if override_prompt:
             return self.provider.generate(override_prompt)

        # Construct Context String (Same as V1/V2-Beta)
        history_str = ""
        for item in history_context[-5:]:
            if len(item) >= 2:
                cmd, resp = item[0], item[1]
            else: continue

            try:
                if hasattr(resp, 'strip') and resp.strip().startswith('{'):
                    r_json = json.loads(resp)
                    resp_text = r_json.get('output', '')
                else:
                    resp_text = str(resp)
            except:
                resp_text = str(resp)
            
            if "command not found" in resp_text: continue

            # Clean ANSI
            resp_clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', resp_text)
            resp_short = resp_clean[:150].replace('\n', ' ') + "..." if len(resp_clean) > 150 else resp_clean.replace('\n', ' ')
            history_str += f"User: {cmd}\nOutput: {resp_short}\n---\n"

        file_list_str = ", ".join(file_list) if file_list else "(Empty)"
        paths_str = ", ".join(known_paths) if known_paths else "/home/user /tmp"

        # Fill Template
        try:
            template = None
            if persona_config and 'prompts' in persona_config:
                 template = persona_config['prompts'].get('system_prompt')
            
            if not template:
                 template = config.get('persona', 'prompts', 'system_prompt')
            
            if not template:
                 template = self.prompt_template
            
            current_user = user if user else "root"
            
            host_val = None
            if persona_config and 'system' in persona_config:
                host_val = persona_config['system'].get('hostname')
            if not host_val:
                host_val = config.get('server', 'hostname') or 'npc-main-server-01'

            extra_instructions = ""
            try:
                if command and command.strip():
                    base_cmd = command.split()[0].strip()
                    base_cmd = re.sub(r'[^a-zA-Z0-9_\-]', '', base_cmd).lower()
                    rule_path = os.path.join(os.path.dirname(__file__), 'prompts', 'rules', f'{base_cmd}.txt')
                    if os.path.exists(rule_path):
                         with open(rule_path, 'r') as f:
                             extra_instructions = f.read()
            except: pass

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
                extra_instructions=extra_instructions
            )
        except Exception as e:
            log.error(f"[!] Prompt Formatting Error: {e}")
            return '{"output": "Error: Internal System Error", "new_cwd": null}'

        return self.provider.generate(prompt)

    def generate_content(self, command, url, persona_summary):
        try:
            template = config.get('persona', 'prompts', 'generate_content')
            if not template:
                return "Error: Content generation not configured."
            
            prompt = template.format(
                command=command,
                url=url,
                persona_summary=persona_summary
            )
            return self.provider.generate(prompt)
        except Exception as e:
            log.error(f"[!] Content Generation Error: {e}")
            return "Error: Content generation failed."

    def verify_api(self):
        try:
            val = self.provider.generate("Reply with exactly the word 'OK'.")
            return "OK" in val
        except:
            return False

    def analyze_command(self, command):
        if not self.provider: return {'type': 'Unknown', 'risk': 0}
        try:
            template = config.get('persona', 'prompts', 'analysis')
            if not template:
                 template = "Analyze command: {command}. Return JSON {type, stage, risk, explanation}."
            
            prompt = template.replace('{command}', command)
            raw_json = self.provider.generate(prompt)
            data = json.loads(raw_json)
            return data
        except:
             return {'type': 'Unknown', 'risk': 0}

    def analyze_batch(self, commands):
        if not commands or not self.provider: return {}
        
        input_list = [{"hash": h, "text": t} for h, t in commands]
        input_json = json.dumps(input_list, indent=2)

        try:
            prompt_path = os.path.join(os.path.dirname(__file__), 'prompts', 'batch_analysis_prompt.txt')
            with open(prompt_path, 'r') as f:
                template = f.read()
        except:
             template = "Analyze input: {commands_json}"
        
        prompt = template.replace('{commands_json}', input_json)
        raw_json = self.provider.generate(prompt)
        results = {}
        
        try:
            data = json.loads(raw_json)
            if isinstance(data, list):
                for item in data:
                    h = item.get('hash')
                    an = item.get('analysis', {})
                    if h:
                        results[h] = {
                            'type': an.get('type', 'Unknown'),
                            'stage': an.get('stage', 'Unknown'),
                            'risk': an.get('risk', 0),
                            'explanation': an.get('explanation', 'Batch Analysis')
                        }
        except: pass
        return results
    
    def generate_session_summary(self, session_history):
         if not session_history or not self.provider: return None
         history_text = "\n".join([f"Cmd: {c}" for c in session_history])
         prompt = f"Analyze session:\n{history_text}\nReturn JSON {{summary, risk_score, mitre_codes}}"
         
         raw_json = self.provider.generate(prompt)
         try:
             return json.loads(raw_json)
         except: return None
