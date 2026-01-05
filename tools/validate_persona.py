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

from ssh_honeypot.config_manager import config

def validate_persona(name_or_path):
    print(f"[*] Validating Persona: {name_or_path}")
    
    # Reload config with this persona
    config.load_persona(name_or_path)
    
    persona = config.get('persona')
    if not persona:
        print("[!] Failed to load persona (Does it exist?)")
        return False
        
    print(f"[*] Loaded Persona: {persona.get('name', 'Unknown')}")
    
    errors = []
    
    # 1. Structural Checks
    required_sections = ['system', 'network', 'prompts', 'access_control']
    for sec in required_sections:
        if sec not in persona:
            errors.append(f"Missing section: '{sec}'")
            
    # 2. Field Checks
    if 'system' in persona:
        if not persona['system'].get('hostname'): errors.append("Missing system.hostname")
        
    if 'prompts' in persona:
        if not persona['prompts'].get('system_prompt'): errors.append("Missing prompts.system_prompt")
        
    # 3. Access Control checks
    if 'access_control' in persona:
        ac = persona['access_control']
        if 'allow_root' not in ac: errors.append("Missing access_control.allow_root")
        
    if errors:
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
