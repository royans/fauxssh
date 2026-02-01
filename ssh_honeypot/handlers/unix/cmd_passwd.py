from ssh_honeypot.handlers.base import BaseHandler
import os
import logging

log = logging.getLogger("sshpot")


class PasswdCommand(BaseHandler):
    def handle(self, cmd, context):
        """
        Handles 'passwd' command.
        Simulates password change and captures input from stdin.
        """
        user = context.get("user", "root")
        stdin = context.get("stdin", "")
        parts = cmd.split()

        # Target user
        target_user = user
        if len(parts) > 1:
            # If passwd user
            if not parts[1].startswith("-"):
                target_user = parts[1]

        # Determine prompts based on user
        # Root doesn't need to provide current password
        is_root = user == "root"

        output = []
        if is_root:
            output.append(f"Changing password for {target_user}.")
            # Prompts:
            # Enter new UNIX password:
            # Retype new UNIX password:
        else:
            output.append(f"Changing password for {user}.")
            # Prompts:
            # (current) UNIX password:
            # Enter new UNIX password:
            # Retype new UNIX password:

        # Capture passwords from stdin
        passwords = [p.strip() for p in stdin.split("\n") if p.strip()]

        if passwords:
            # Log the captured passwords for the researcher
            log.info(
                f"[Credential Capture] passwd attempt for {target_user} by {user}. Input: {passwords}"
            )
            # Success simulation
            return (
                self._generate_success_output(user, target_user, is_root),
                {},
                {"source": "handler", "cached": False},
            )

        # If no stdin, we are in an interactive mode which we don't fully support TTY for yet.
        # But we can simulate the prompts being shown before it "fails" or just give a generic failure.
        # However, to be helpful to the user's specific request (piped input),
        # we've handled the piped case above.

        return (
            self._generate_interactive_failure(user),
            {},
            {"source": "handler", "cached": False},
        )

    def _generate_success_output(self, user, target, is_root):
        if is_root:
            return (
                f"Changing password for {target}.\n"
                "Enter new UNIX password: \n"
                "Retype new UNIX password: \n"
                "passwd: password updated successfully\n"
            )
        else:
            return (
                f"Changing password for {user}.\n"
                "(current) UNIX password: \n"
                "Enter new UNIX password: \n"
                "Retype new UNIX password: \n"
                "passwd: password updated successfully\n"
            )

    def _generate_interactive_failure(self, user):
        # Realistic failure when no TTY is available or input is missing
        return f"Changing password for {user}.\n" "passwd: password unchanged\n"
