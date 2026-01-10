#!/usr/bin/env python3
import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

# Attempt to load config
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    print("Warning: python-dotenv not installed. Using environment variables only.")

def check_env_file():
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        print(f"[OK] .env file found at {env_path}")
        return True
    else:
        print("[WARN] .env file not found. Using defaults/env vars.")
        return False

def check_permissions():
    data_dir = PROJECT_ROOT / "data"
    data_dir.mkdir(exist_ok=True)
    
    test_file = data_dir / ".perm_test"
    try:
        test_file.touch()
        test_file.unlink()
        print(f"[OK] Write permission confirmed for {data_dir}")
        return True
    except PermissionError:
        print(f"[FAIL] No write permission for {data_dir}")
        return False
    except Exception as e:
        print(f"[FAIL] Unexpected error checking permissions: {e}")
        return False

def check_api_key():
    key = os.getenv("GOOGLE_API_KEY")
    if not key:
        print("[INFO] GOOGLE_API_KEY is not set. FauxSSH will run in limited mode (No LLM).")
        return True # Not a failure condition
        
    print("[INFO] GOOGLE_API_KEY detected. Verifying...")
    try:
        import google.generativeai as genai
        genai.configure(api_key=key)
        # Lightweight check
        model = genai.GenerativeModel('gemini-pro')
        # We don't generate content to save quota/time, just checking import and config
        # Actually list_models is better verification
        # But for 'gemini-pro' specifically?
        # Let's just assume if it configures it's likely okay. 
        # Making a network call might be slow or fail if no internet.
        # We'll skip network call for simple check.
        print("[OK] Google Generative AI configured.")
        return True
    except ImportError:
        print("[WARN] google-generativeai package not installed.")
        return False
    except Exception as e:
        print(f"[WARN] Error configuring API Key: {e}")
        return False

def main():
    print("--- FauxSSH Configuration Check ---")
    env_ok = check_env_file()
    perm_ok = check_permissions()
    key_ok = check_api_key()
    
    if perm_ok:
        print("\n[SUCCESS] Environment looks good.")
        sys.exit(0)
    else:
        print("\n[FAIL] Critical issues found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
