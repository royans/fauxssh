
import re
import logging

class SecurityFilter:
    """
    detects and blocks prompt injection attacks and malicious inputs 
    before they reach the LLM.
    """
    
    def __init__(self):
        # Compiled patterns for efficiency
        self.injection_patterns = [
            re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instruction", re.IGNORECASE),
            re.compile(r"forget\s+(all\s+)?(previous|prior)\s+instruction", re.IGNORECASE),
            re.compile(r"you\s+are\s+now", re.IGNORECASE),
            re.compile(r"act\s+as\s+a", re.IGNORECASE),
            re.compile(r"system\s+prompt", re.IGNORECASE),
            re.compile(r"override\s+(the\s+)?system", re.IGNORECASE),
            re.compile(r"jailbreak", re.IGNORECASE),
            re.compile(r"developer\s+mode", re.IGNORECASE),
            re.compile(r"unfiltered", re.IGNORECASE),
            re.compile(r"DAN\s+mode", re.IGNORECASE),
            # Attempts to close potential prompt tags (xml/html injection)
            re.compile(r"</?user>", re.IGNORECASE),
            re.compile(r"</?system>", re.IGNORECASE),
            re.compile(r"</?model>", re.IGNORECASE)
        ]
        
        # Length limit to prevent token exhaustion DoS before it hits LLM
        self.MAX_INPUT_LENGTH = 1000 

    def validate_input(self, user_input):
        """
        Validates the user input.
        Returns: (is_safe: bool, reason: str)
        """
        if not user_input:
            return True, "Empty"

        if len(user_input) > self.MAX_INPUT_LENGTH:
            return False, f"Input length exceeded ({len(user_input)} > {self.MAX_INPUT_LENGTH})"

        # Check against patterns
        for pattern in self.injection_patterns:
            if pattern.search(user_input):
                return False, f"Prompt Injection detected: {pattern.pattern}"

        return True, "Safe"

    def sanitize_output(self, llm_output):
        """
        Sanitizes output from LLM to ensure no leakage of sensitive tokens.
        (Future implementation)
        """
        return llm_output
