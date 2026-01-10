
import pytest
import os
import json
import time
from unittest.mock import patch, MagicMock
from ssh_honeypot.core.session_logger import SessionLogger

class TestSessionLogger:
    def test_logger_creates_file_and_header(self, tmp_path):
        # Mock get_data_dir to use tmp_path
        with patch('ssh_honeypot.core.session_logger.get_data_dir', return_value=str(tmp_path)):
            logger = SessionLogger("test_sess_1", "root", "1.2.3.4")
            
            # Check file created
            cast_file = tmp_path / "sessions" / "test_sess_1.cast"
            assert cast_file.exists()
            
            # Check Header
            lines = cast_file.read_text().splitlines()
            header = json.loads(lines[0])
            assert header['version'] == 2
            assert header['env']['USER'] == "root"
            
            logger.close()

    def test_logger_events(self, tmp_path):
        with patch('ssh_honeypot.core.session_logger.get_data_dir', return_value=str(tmp_path)):
            logger = SessionLogger("test_sess_2", "user", "1.2.3.4")
            
            # Log some events
            logger.log_event('i', "ls")
            time.sleep(0.01)
            logger.log_event('o', "file1 file2")
            
            logger.close()
            
            # Verify Content
            cast_file = tmp_path / "sessions" / "test_sess_2.cast"
            lines = cast_file.read_text().splitlines()
            
            # Line 0 is header
            # Line 1 is input
            event1 = json.loads(lines[1])
            assert event1[1] == 'i'
            assert event1[2] == "ls"
            
            # Line 2 is output
            event2 = json.loads(lines[2])
            assert event2[1] == 'o'
            assert event2[2] == "file1 file2"
            
            # Check timing
            assert event2[0] > event1[0]
