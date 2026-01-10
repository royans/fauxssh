from abc import ABC, abstractmethod

class DatabaseBackend(ABC):
    """
    Abstract Base Class for Honeypot Database Backends.
    All database implementations (SQLite, MySQL, Postgres, etc.) must inherit from this.
    """

    @abstractmethod
    def start_session(self, session_id, ip, username, password, client_version):
        """Log the start of a new SSH session."""
        pass

    @abstractmethod
    def end_session(self, session_id):
        """Log the end of a session."""
        pass

    @abstractmethod
    def log_interaction(self, session_id, cwd, command, response):
        """Log a command and its response."""
        pass

    @abstractmethod
    def get_cached_response(self, command, cwd):
        """Retrieve a cached response for a command in a specific CWD."""
        pass

    @abstractmethod
    def cache_response(self, command, cwd, response):
        """Cache a response for future use."""
        pass

    @abstractmethod
    def get_fs_node(self, path):
        """Retrieve a filesystem node (file/dir) metadata and content."""
        pass

    @abstractmethod
    def list_fs_dir(self, parent_path):
        """List all children of a directory."""
        pass

    @abstractmethod
    def update_fs_node(self, path, parent_path, type, metadata, content=None):
        """Create or update a filesystem node."""
        pass
