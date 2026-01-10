#!/usr/bin/env python3
import warnings
# Suppress SyntaxWarnings from external libs if any
warnings.simplefilter("ignore", category=SyntaxWarning)

import os
import sys
import yaml
import argparse
import logging

# Add parent dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from ssh_honeypot.core.config import config
from ssh_honeypot.persona_validator import validate_active_persona

def validate_persona(name_or_path):
    print(f"[*] Validating Persona: {name_or_path}")
    
    # Reload config with this persona
    config.load_persona(name_or_path)
    
    persona = config.get('persona')
    if not persona:
        print("[!] Failed to load persona (Does it exist?)")
        return False
        
    print(f"[*] Loaded Persona: {persona.get('name', 'Unknown')}")
    
    is_valid, errors = validate_active_persona(config)
    
    if not is_valid:
        print("[!] Validation Failed:")
        for e in errors:
            print(f"  - {e}")
        return False
        
    print("[+] Persona Configuration Valid (Schema Check Passed)")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate a SSH Persona configuration")
    parser.add_argument("persona", help="Name or Path of persona to validate")
    args = parser.parse_args()
    
    if validate_persona(args.persona):
        sys.exit(0)
    else:
        sys.exit(1)
