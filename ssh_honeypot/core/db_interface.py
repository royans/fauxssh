from abc import ABC, abstractmethod


class DatabaseBackend(ABC):
    """
    Abstract Base Class for Honeypot Database Backends.
    All database implementations (SQLite, MySQL, Postgres, etc.) must inherit from this.
    """

    @abstractmethod
    def get_connection_info(self):
        """Return a string describing the current connection."""
        pass

    @abstractmethod
    def start_session(
        self,
        session_id,
        ip,
        username,
        password,
        client_version,
        fingerprint=None,
        protocol="ssh",
        start_time=None,
    ):
        """Log the start of a new SSH session."""
        pass

    @abstractmethod
    def end_session(self, session_id):
        """Log the end of a session."""
        pass

    @abstractmethod
    def log_interaction(
        self,
        session_id,
        cwd,
        command,
        response,
        source="unknown",
        was_cached=False,
        duration_ms=0,
        request_md5=None,
        response_md5=None,
        response_head=None,
        response_size=None,
    ):
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

    @abstractmethod
    def batch_update_fs_nodes(self, nodes):
        """Batch update or insert filesystem nodes."""
        pass

    @abstractmethod
    def log_url_request(
        self, session_id, url, method="GET", user_agent=None, command_text=None
    ):
        pass

    @abstractmethod
    def log_auth_event(
        self,
        client_ip,
        username,
        auth_method,
        auth_data,
        success,
        client_version,
        fingerprint=None,
        protocol="ssh",
    ):
        pass

    @abstractmethod
    def save_command_analysis(
        self, command_hash, command_text, activity_type, stage, risk_score, explanation
    ):
        pass

    @abstractmethod
    def update_user_file(
        self, ip, username, path, parent_path, type, metadata, content=None
    ):
        pass

    @abstractmethod
    def record_llm_usage(self, ip, source="http"):
        pass

    @abstractmethod
    def check_llm_rate_limit(self, ip, rpm_limit, rph_limit, rpd_limit):
        pass

    @abstractmethod
    def get_user_node(self, ip, username, path):
        pass

    @abstractmethod
    def list_user_dir(self, ip, username, parent_path):
        pass

    @abstractmethod
    def is_managed_directory(self, ip, username, path):
        pass

    @abstractmethod
    def get_ip_upload_usage(self, ip):
        pass

    @abstractmethod
    def cleanup_http_cache(self, web_root="/var/www/html"):
        pass

    @abstractmethod
    def prune_uploads(self, days=30):
        pass

    @abstractmethod
    def touch_user_file(self, ip, username, path):
        pass

    @abstractmethod
    def delete_user_file(self, ip, username, path):
        pass

    @abstractmethod
    def log_ip_visit(self, ip):
        pass

    @abstractmethod
    def get_unenriched_ips(self, limit=10):
        pass

    @abstractmethod
    def save_ip_intelligence(self, ip, intel_data):
        pass

    @abstractmethod
    def add_ip_abuse_tag(self, ip, tag):
        pass

    @abstractmethod
    def scan_and_repair_corruption(self, ip, username):
        pass

    @abstractmethod
    def get_global_stats(self):
        pass

    @abstractmethod
    def get_active_sessions(self):
        pass

    @abstractmethod
    def get_unique_creds_last_24h(self, ip):
        pass

    @abstractmethod
    def validate_anti_harvesting(self, ip, username, password):
        pass

    @abstractmethod
    def check_root_desperation(self, ip):
        pass

    @abstractmethod
    def get_recent_sessions(self, limit=20, protocol=None):
        pass

    @abstractmethod
    def get_session_interactions(self, session_id):
        pass

    @abstractmethod
    def get_cached_session_summary(self, chain_hash):
        pass

    @abstractmethod
    def save_session_summary_cache(self, chain_hash, summary, risk_score):
        pass

    @abstractmethod
    def update_session_summary(self, session_id, summary, risk_score):
        pass

    @abstractmethod
    def sanitize_artifacts(self):
        pass

    @abstractmethod
    def is_path_deleted(self, ip, username, path):
        pass

    @abstractmethod
    def get_unanalyzed_commands(self, limit=10):
        pass

    @abstractmethod
    def get_unanalyzed_sessions(self, limit=10):
        pass

    @abstractmethod
    def save_analysis(self, cmd_hash, cmd_text, analysis):
        pass

    @abstractmethod
    def get_analysis(self, cmd_hash):
        pass

    @abstractmethod
    def inspect_path(self, ip, username, path):
        pass

    @abstractmethod
    def inspect_dir(self, ip, username, directory):
        pass

    @abstractmethod
    def cleanup_malicious_payloads(self):
        """Removes duplicate URLs from the malicious_payloads table, keeping only the oldest."""
        pass

    @abstractmethod
    def add_malicious_payload(
        self, url, url_hash, session_id, ip, timestamp=None, status="pending"
    ):
        pass

    @abstractmethod
    def batch_add_malicious_payloads(self, payload_list):
        """Batch adds multiple malicious payloads and their requests."""
        pass

    @abstractmethod
    def get_payload_by_hash(self, url_hash):
        pass

    @abstractmethod
    def get_pending_payloads(self, limit=5):
        pass

    @abstractmethod
    def update_payload_status(
        self,
        payload_id,
        status,
        file_path=None,
        error_message=None,
        payload_md5=None,
        payload_size=None,
    ):
        pass

    @abstractmethod
    def is_payload_host_rate_limited(self, hostname):
        pass

    @abstractmethod
    def get_interactions_with_http(self):
        pass

    @abstractmethod
    def clear_cache(self):
        pass

    @abstractmethod
    def get_session(self, session_id):
        pass

    @abstractmethod
    def get_session_protocol(self, session_id):
        pass

    @abstractmethod
    def get_next_payload_for_analysis(self):
        pass

    @abstractmethod
    def get_next_payload_for_analysis(self):
        pass

    @abstractmethod
    def update_payload_vt_status(self, payload_id, result, scan_id=None):
        pass

    @abstractmethod
    def iter_interactions(self, batch_size=1000):
        """Yields all interactions from the database for export."""
        pass

    @abstractmethod
    def get_infographic_stats(self, hours=24, ignore_ips=None):
        """Returns a dictionary of statistics for the infographic dashboard."""
        pass

    @abstractmethod
    def purge_poisoned_cache(self):
        """Purges any cached responses containing AI Core error messages."""
        pass

    @abstractmethod
    def get_llm_response(self, prompt_hash):
        """Retrieves a cached LLM response by prompt hash if it exists and is fresh."""
        pass

    @abstractmethod
    def save_llm_response(self, prompt_hash, prompt_text, response):
        """Caches an LLM response."""
        pass
