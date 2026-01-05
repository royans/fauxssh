
import logging

def validate_active_persona(config):
    """
    Validates the currently loaded persona configuration in the global config object.
    Returns (is_valid, errors_list)
    """
    persona = config.get('persona')
    if not persona:
        return False, ["No 'persona' block found in configuration."]
        
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
        
    return (len(errors) == 0), errors
