class NohupCommand:
    def __init__(self, db, llm_interface):
        self.db = db
        self.llm = llm_interface

    def handle(self, cmd, context, executor):
        """
        Handles nohup command by stripping 'nohup' prefix and trailing '&',
        then recursively executing the command.

        Args:
            cmd (str): The full command string (e.g. "nohup bash ... &")
            context (dict): Execution context
            executor (callable): Callback to process_command(cmd, context)

        Returns:
            tuple: (output, updates, metadata)
        """
        parts = cmd.split()
        if len(parts) > 1:
            # Remove 'nohup'
            cmd_stripped = " ".join(parts[1:])

            # Check for trailing '&' (background operator)
            # We need to re-split to safely check the last token
            new_parts = cmd_stripped.split()
            if new_parts and new_parts[-1] == "&":
                # Strip trailing '&'
                cmd_stripped = " ".join(new_parts[:-1]).strip()
            elif cmd_stripped.endswith(" &"):
                # Fallback
                cmd_stripped = cmd_stripped[:-2].strip()

            # Recursively process the command
            return executor(cmd_stripped, context)
        else:
            return (
                "nohup: missing operand\n",
                {},
                {"source": "handler", "cached": False},
            )
