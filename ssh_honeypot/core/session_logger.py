
import os
import json
import time
from .config import get_data_dir

class SessionLogger:
    """
    Logs session input/output to asciinema v2 format (.cast files).
    """
    def __init__(self, session_id, user, ip, width=80, height=24):
        self.session_id = session_id
        self.start_time = time.time()
        
        # Setup directories
        data_dir = get_data_dir()
        self.sessions_dir = os.path.join(data_dir, 'sessions')
        os.makedirs(self.sessions_dir, exist_ok=True)
        
        self.filepath = os.path.join(self.sessions_dir, f"{session_id}.cast")
        self.file = open(self.filepath, 'w', encoding='utf-8')
        
        # Write Header
        header = {
            "version": 2,
            "width": width,
            "height": height,
            "timestamp": int(self.start_time),
            "env": {
                "SHELL": "/bin/bash",
                "TERM": "xterm",
                "USER": user
            },
            "title": f"Session {session_id} from {ip}"
        }
        self.file.write(json.dumps(header) + "\n")
        self.file.flush()

    def log_event(self, event_type, data):
        """
        Log an event.
        event_type: 'o' (output/stdout) or 'i' (input/stdin)
        data: string data
        """
        if not self.file or self.file.closed:
            return
            
        try:
            # Calculate relative time
            rel_time = time.time() - self.start_time
            
            # Format: [time, type, data]
            # Ensure data is string (decode bytes if needed)
            if isinstance(data, bytes):
                try:
                    data = data.decode('utf-8', errors='replace')
                except:
                    data = str(data)
            
            line = json.dumps([round(rel_time, 6), event_type, data])
            self.file.write(line + "\n")
            self.file.flush()
        except Exception as e:
            # Don't crash session on log error
            print(f"[SessionLogger] Error writing event: {e}")

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()

