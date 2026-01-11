import os
import logging

from ssh_honeypot.core.utils import get_data_dir

log = logging.getLogger("sshpot")


class StateManager:
    """
    Manages persistent state for the honeypot, such as the last used persona.
    """

    @property
    def STATE_FILE(self):
        return os.path.join(get_data_dir(), ".last_persona")

    @classmethod
    def get_state_file_path(cls):
        return os.path.join(get_data_dir(), ".last_persona")

    @classmethod
    def save_last_persona(cls, persona_name: str):
        """Save the persona name to the state file."""
        try:
            path = cls.get_state_file_path()
            with open(path, "w") as f:
                f.write(persona_name.strip())
            log.info(f"Saved last used persona: {persona_name}")
        except Exception as e:
            log.error(f"Failed to save last persona: {e}")

    @classmethod
    def get_last_persona(cls) -> str:
        """Retrieve the last used persona name, or None if not found."""
        try:
            path = cls.get_state_file_path()
            if os.path.exists(path):
                with open(path, "r") as f:
                    name = f.read().strip()
                    if name:
                        return name
            return None
        except Exception as e:
            log.error(f"Failed to read last persona: {e}")
            return None
