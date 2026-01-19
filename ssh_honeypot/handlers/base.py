import os
import hashlib
import json
import logging
from ssh_honeypot.core.filesystem import resolve_path

log = logging.getLogger("sshpot")


class BaseHandler:
    """
    Abstract base class for all command handlers.
    """

    def __init__(self, db, llm, system_handler=None):
        self.db = db
        self.llm = llm
        self.system_handler = system_handler

    def handle(self, cmd, context):
        """
        Process the command.
        Returns: (output_text, updates_dict, metadata) or None if not handled.
        """
        raise NotImplementedError

    def _generate_or_get_content(self, cmd_name, target_path, context):
        """
        Helper to get content of a file.
        1. Checks User DB (persisted files).
        2. Checks Static/Dynamic Persona Files (if system handler available).
        3. Checks Global FS.
        4. Hardcoded Secrets.
        5. Falls back to LLM generation (and persists it to User DB).
        """
        session_id = context.get("session_id", "unknown")
        cwd = context.get("cwd")

        # 0. Check DB (User FS overrides Global FS)
        abs_path = resolve_path(cwd, target_path)
        client_ip = context.get("client_ip")
        user = context.get("user")

        # Check User Uploads first
        user_node = self.db.get_user_node(client_ip, user, abs_path)
        if user_node and (user_node.get("content") is not None):
            return user_node["content"], "local"

        # Check Global FS
        node = self.db.get_fs_node(abs_path)
        if node and (node.get("content") is not None):
            return node["content"], "local"

        # Check Static/Dynamic Persona Files (if system_handler injected)
        if hasattr(self, "system_handler") and self.system_handler:
            dyn_content = self.system_handler.get_dynamic_file(abs_path)
            if dyn_content:
                return dyn_content, "local"

            static_content = self.system_handler.get_static_file(abs_path)
            if static_content:
                return static_content, "local"

        # 1. Hardcoded Secret (Legacy Easter Egg)
        if "notes.txt" in target_path:
            return "Hint: RudolphsRedNose2025!", "local"

        # print(f"[Session: {session_id}] [{cmd_name}] DB MISS for {abs_path}. Calling LLM.")

        # 2. LLM Call
        lookup_files = context.get("file_list", [])
        if "/" in target_path:
            lookup_files = []

        prompt = f"{cmd_name} {abs_path} (INSTRUCTION: Return a JSON object with key 'output' containing realistic file content for '{abs_path}'. Be creative.)"

        # Use LLM interface
        # We need generic access to generate_response.
        # BaseHandler has self.llm.

        resp = self.llm.generate_response(
            cmd_name,
            cwd,
            context.get("history"),
            lookup_files,
            context.get("known_paths", []),
            client_ip=context.get("client_ip"),
            honeypot_ip=context.get("honeypot_ip"),
            override_prompt=prompt,
        )

        j, t = self._extract_json_or_text(resp)
        if j and "output" in j:
            content_str = j["output"]
            if isinstance(content_str, (dict, list)):
                content_str = str(content_str)

            # Use TempFS (User DB) for persistence
            self.db.update_user_file(
                client_ip,
                user,
                abs_path,
                os.path.dirname(abs_path),
                "file",
                {},
                content_str,
            )
            return content_str, "llm"

        return t, "llm"

    def _extract_json_or_text(self, text):
        """
        Parses LLM output for JSON.
        """
        try:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1:
                json_str = text[start : end + 1]
                return json.loads(json_str), ""
            return None, text
        except:
            return None, text

    def _process_llm_json(self, r_json, r_text, vfs=None, cwd=None, user=None):
        """
        Standardizes return format.
        Output: (text_output, updates)
        """
        output_text = ""
        updates = {}

        if r_json:
            output_text = r_json.get("output", "")
            updates["new_cwd"] = r_json.get("new_cwd")
            updates["file_modifications"] = r_json.get("file_modifications")
        else:
            output_text = r_text

        # Post-Processing: Replace 'alabaster' artifact with actual user
        if user and output_text:
            output_text = output_text.replace("alabaster", user)
            output_text = output_text.replace("Alabaster", user.capitalize())

        return output_text, updates
