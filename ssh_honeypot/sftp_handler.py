import os
import paramiko
import time
import logging
import zlib

try:
    from .config_manager import get_data_dir
except ImportError:
    from config_manager import get_data_dir

UPLOAD_DIR = os.path.join(get_data_dir(), "uploaded_files")

class HoneySFTPHandle(paramiko.SFTPHandle):
    def __init__(self, flags=0):
        super(HoneySFTPHandle, self).__init__(flags)
        self.upload_fp = None
        self.path = None
        self.vfs_ref = None
        self.vfs_dir_key = None
        self.filename_only = None

    def close(self):
        if self.upload_fp:
            try:
                self.upload_fp.close()
                print(f"[SFTP] Upload Completed: {self.path}")
                
                # Update VFS
                if self.vfs_ref is not None and self.vfs_dir_key is not None:
                     if self.vfs_dir_key in self.vfs_ref:
                         if self.filename_only not in self.vfs_ref[self.vfs_dir_key]:
                             self.vfs_ref[self.vfs_dir_key].append(self.filename_only)
                     else:
                         self.vfs_ref[self.vfs_dir_key] = [self.filename_only]
                         
                # Save content to DB
                if hasattr(self, 'real_path') and os.path.exists(self.real_path):
                    size = os.path.getsize(self.real_path)
                    print(f"[SFTP] Persisting content for {self.path} ({size} bytes)")
                    
                    if size < 1024 * 1024:
                        try:
                            with open(self.real_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                            if hasattr(self, 'server_obj') and hasattr(self.server_obj, 'db'):
                                meta = {
                                    'permissions': '-rwxr-xr-x' if content.startswith('#!') else '-rw-r--r--',
                                    'size': size,
                                    'owner': 'root', 
                                    'modified': time.strftime("%b %d %H:%M")
                                }
                                self.server_obj.db.update_user_file(
                                    self.server_obj.client_ip,
                                    self.server_obj.username,
                                    self.path, 
                                    self.vfs_dir_key, 
                                    'file', 
                                    meta, 
                                    content
                                )
                                print(f"[SFTP] User-DB Updated for {self.path} ({self.server_obj.username}@{self.server_obj.client_ip})")
                        except Exception as db_e:
                            print(f"[SFTP] DB Persist Error: {db_e}")
                            
            except Exception as e:
                print(f"[SFTP] Close Error: {e}")
                
        super(HoneySFTPHandle, self).close()

    def write(self, offset, data):
        if self.upload_fp:
            try:
                # Enforce Size Limit
                if hasattr(self, 'max_file_size'):
                    cur_pos = self.upload_fp.tell()
                    if cur_pos + len(data) > self.max_file_size:
                        print(f"[!] SFTP Write blocked: Exceeds size limit ({self.max_file_size})")
                        return paramiko.SFTP_PERMISSION_DENIED
                        
                self.upload_fp.seek(offset)
                self.upload_fp.write(data)
            except Exception as e:
                # with open('/tmp/write_debug.log', 'a') as f: f.write(f"Write Error: {e}\n")
                return paramiko.SFTP_PERMISSION_DENIED
        return paramiko.SFTP_OK

    def read(self, offset, length):
        return b""

    def stat(self):
        attr = paramiko.SFTPAttributes()
        attr.st_size = 0
        attr.st_mode = 0o100644
        return attr

    def chattr(self, attr):
        return paramiko.SFTP_OK

class HoneySFTPServer(paramiko.SFTPServerInterface):
    def __init__(self, server, *largs, **kwargs):
        super(HoneySFTPServer, self).__init__(server, *largs, **kwargs)
        self.server_obj = server
        self.vfs = getattr(server, 'vfs', {})
        self.cwd = getattr(server, 'cwd', '/root')
        self.username = getattr(server, 'username', 'unknown')
        self.session_id = getattr(server, 'session_id', 'unknown')
        
        if not os.path.exists(UPLOAD_DIR):
            try: os.makedirs(UPLOAD_DIR)
            except: pass

    def _get_file_size(self, virtual_path):
        """
        Determines the size of a file.
        1. Checks if it's a real uploaded file for this session.
        2. If not, generates a deterministic fake size based on the filename/path.
        """
        # Check Real Upload
        fname = os.path.basename(virtual_path)
        real_path = os.path.join(UPLOAD_DIR, self.session_id, fname)
        if os.path.exists(real_path):
            try:
                return os.path.getsize(real_path)
            except: pass
            
        # Deterministic Fake Size
        # Use CRC32 of path to get a stable random integer
        seed = zlib.crc32(virtual_path.encode('utf-8'))
        # Size range: 100 bytes to 20KB
        return (seed % 20000) + 100
            
    def _resolve(self, path):
        # print(f"[DEBUG] Resolve {path}") 
        if path == '.' or path == '':
            return self.cwd
        if not path.startswith('/'):
            return os.path.normpath(os.path.join(self.cwd, path))
        return os.path.normpath(path)

    def list_folder(self, path):
        path = self._resolve(path)
        print(f"[SFTP] List: {path}")
        files = self.vfs.get(path)
        if files is None:
             return paramiko.SFTP_NO_SUCH_FILE
        out = []
        for f in files:
            attr = paramiko.SFTPAttributes()
            attr.filename = f
            full_child = os.path.join(path, f)
            attr.st_size = self._get_file_size(full_child)
            attr.st_mode = 0o100644
            if full_child in self.vfs:
                attr.st_mode = 0o40755
            attr.st_uid = 0 if self.username == 'root' else 1000
            attr.st_gid = 0 if self.username == 'root' else 1000
            attr.st_atime = int(time.time())
            attr.st_mtime = int(time.time())
            out.append(attr)
        return out

    def stat(self, path):
        path = self._resolve(path)
        if path in self.vfs:
            attr = paramiko.SFTPAttributes()
            attr.st_size = 4096
            attr.st_mode = 0o40755
            return attr
        dirname, basename = os.path.split(path)
        if dirname in self.vfs and basename in self.vfs[dirname]:
             attr = paramiko.SFTPAttributes()
             attr.st_size = self._get_file_size(path)
             attr.st_mode = 0o100644
             return attr
        return paramiko.SFTP_NO_SUCH_FILE

    def lstat(self, path):
        return self.stat(path)

    def chattr(self, path, attr):
        return paramiko.SFTP_OK

    def open(self, path, flags, attr):
        path = self._resolve(path)
        print(f"[SFTP] Open: {path} Flags: {flags}")
        if (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)):
            # Load Limits from Config
            try:
                from .config_manager import config
            except ImportError:
                from config_manager import config
                
            MAX_FILE_SIZE = config.get('upload', 'max_file_size') or 1048576
            MAX_QUOTA = config.get('upload', 'max_quota_per_ip') or 1048576

            sess_dir = os.path.join(UPLOAD_DIR, self.session_id)
            if not os.path.exists(sess_dir):
                try: os.makedirs(sess_dir)
                except: pass
            # SECURITY CRITICAL: We MUST use os.path.basename to strip any path info
            # to prevent directory traversal attacks (e.g. uploading to ../../../etc/passwd)
            fname = os.path.basename(path) 
            real_path = os.path.join(sess_dir, fname)
            
            # CHECK 1: Existing Quota
            if hasattr(self.server_obj, 'db') and self.server_obj.db:
                 current_usage = self.server_obj.db.get_ip_upload_usage(self.server_obj.client_ip)
                 if current_usage >= MAX_QUOTA:
                     print(f"[!] SFTP Limit: Quota Exceeded for {self.server_obj.client_ip} ({current_usage}/{MAX_QUOTA})")
                     return paramiko.SFTP_PERMISSION_DENIED
            
            handle = HoneySFTPHandle(flags)
            handle.path = path
            handle.vfs_ref = self.vfs
            handle.vfs_dir_key = os.path.dirname(path)
            handle.filename_only = fname
            handle.server_obj = self.server_obj # Access to DB
            handle.real_path = real_path # Access to content on disk
            handle.max_file_size = MAX_FILE_SIZE # Pass limit to handle
            
            try:
                handle.upload_fp = open(real_path, "wb")
                print(f"[*] Started Upload to: {real_path}")
                if hasattr(self.server_obj, 'db') and self.server_obj.db:
                     try: self.server_obj.db.log_interaction(self.session_id, f"SFTP Upload: {path}", f"Saved to {real_path}")
                     except: pass
            except Exception as e:
                print(f"[!] Upload Error: {e}")
                return paramiko.SFTP_PERMISSION_DENIED
            return handle
        return HoneySFTPHandle(flags)
        
    def remove(self, path):
        path = self._resolve(path)
        dirname, basename = os.path.split(path)
        if dirname in self.vfs and basename in self.vfs[dirname]:
            self.vfs[dirname].remove(basename)
        return paramiko.SFTP_OK
        
    def rename(self, old, new):
        return paramiko.SFTP_OK
        
    def mkdir(self, path, attr):
        path = self._resolve(path)
        if path not in self.vfs: self.vfs[path] = []
        return paramiko.SFTP_OK
        
    def rmdir(self, path):
        path = self._resolve(path)
        if path in self.vfs: del self.vfs[path]
        return paramiko.SFTP_OK
