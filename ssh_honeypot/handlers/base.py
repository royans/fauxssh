class BaseHandler:
    """
    Abstract base class for all command handlers.
    """
    def __init__(self, db, llm):
        self.db = db
        self.llm = llm

    def handle(self, cmd, context):
        """
        Process the command.
        Returns: (output_text, updates_dict) or None if not handled.
        """
        raise NotImplementedError
