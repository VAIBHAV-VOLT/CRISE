"""
Script to test a Gemini API key and list available models.
Usage:
    python check_gemini_models.py [API_KEY]
If API_KEY is omitted, reads AI_API_KEY from backend/.env.
"""

import sys
import os
import httpx
from dotenv import load_dotenv

# Load .env if present
env_path = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(env_path):
    load_dotenv(env_path, override=True)

def list_gemini_models(api_key: str):
    print(f"Testing Gemini API key ending in ...{api_key[-4:] if len(api_key) > 4 else '****'}")
    
    # 1. Test via Google Native API
    native_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    print(f"\n1. Fetching models from Google Native API ({native_url.split('?')[0]})...")
    try:
        res = httpx.get(native_url, timeout=10.0)
        if res.status_code == 200:
            models_data = res.json().get("models", [])
            print(f"   [SUCCESS] Found {len(models_data)} models via Native API:")
            supported_chat = []
            for m in models_data:
                name = m.get("name", "").replace("models/", "")
                methods = m.get("supportedGenerationMethods", [])
                if "generateContent" in methods:
                    supported_chat.append(name)
                    print(f"   - {name} ({m.get('displayName', '')})")
            
            # Identify recommended model
            recommended = "gemini-2.5-flash" if "gemini-2.5-flash" in supported_chat else (
                "gemini-2.0-flash" if "gemini-2.0-flash" in supported_chat else (
                    "gemini-1.5-flash" if "gemini-1.5-flash" in supported_chat else supported_chat[0] if supported_chat else "gemini-2.5-flash"
                )
            )
            print(f"\n   -> Recommended AI_MODEL: {recommended}")
        else:
            print(f"   [ERROR] HTTP {res.status_code}: {res.text}")
    except Exception as e:
        print(f"   [ERROR] Request failed: {e}")

    # 2. Test via OpenAI Compatibility Endpoint
    openai_url = "https://generativelanguage.googleapis.com/v1beta/openai/models"
    headers = {"Authorization": f"Bearer {api_key}"}
    print(f"\n2. Fetching models from OpenAI Compatibility endpoint ({openai_url})...")
    try:
        res = httpx.get(openai_url, headers=headers, timeout=10.0)
        if res.status_code == 200:
            models = res.json().get("data", [])
            print(f"   [SUCCESS] Endpoint accessible! Found {len(models)} OpenAI-compatible models:")
            for m in models:
                print(f"   - {m.get('id')}")
        else:
            print(f"   [ERROR] HTTP {res.status_code}: {res.text}")
    except Exception as e:
        print(f"   [ERROR] Request failed: {e}")

if __name__ == "__main__":
    key = sys.argv[1] if len(sys.argv) > 1 else os.getenv("AI_API_KEY", "")
    if not key or key == "YOUR_GEMINI_API_KEY_HERE":
        print("Usage: python check_gemini_models.py <YOUR_GEMINI_API_KEY>")
        print("Or set AI_API_KEY in backend/.env file.")
        sys.exit(1)
    list_gemini_models(key)
