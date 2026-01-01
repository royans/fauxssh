
import time
import random

def random_response_delay(min_delay=0.5, max_delay=1.5):
    """
    Introduces a random delay to simulate network latency or LLM processing time.
    This helps mitigate timing side-channel attacks where an attacker can 
    distinguish between internal commands (fast) and LLM commands (slow).
    
    Args:
        min_delay (float): Minimum delay in seconds.
        max_delay (float): Maximum delay in seconds.
    """
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)
