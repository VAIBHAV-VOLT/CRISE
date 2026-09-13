"""
CRISE — Configuration Module
============================
Centralized environment configuration management using python-dotenv.
Ensures API keys and credentials remain strictly server-side.
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load .env file from backend directory or project root
load_dotenv()
backend_env = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(backend_env):
    load_dotenv(backend_env, override=True)


class Settings:
    """Centralized application settings loaded once from environment."""

    def __init__(self):
        self.ai_provider: str = os.getenv("AI_PROVIDER", "openai").strip().lower()
        self.ai_api_key: str = os.getenv("AI_API_KEY", "").strip()
        self.ai_model: str = os.getenv("AI_MODEL", "").strip()
        self.ai_base_url: Optional[str] = os.getenv("AI_BASE_URL", "").strip() or None
        
        # Temperature setting
        try:
            self.ai_temperature: float = float(os.getenv("AI_TEMPERATURE", "0.2"))
            if not (0.0 <= self.ai_temperature <= 2.0):
                self.ai_temperature = 0.2
        except (ValueError, TypeError):
            self.ai_temperature = 0.2

        # Max tokens setting
        try:
            self.ai_max_tokens: int = int(os.getenv("AI_MAX_TOKENS", "1200"))
            if self.ai_max_tokens <= 0:
                self.ai_max_tokens = 1200
        except (ValueError, TypeError):
            self.ai_max_tokens = 1200

    def reload(self):
        """Reload settings from environment (useful for testing)."""
        self.__init__()

    @property
    def is_ai_configured(self) -> bool:
        """Returns True if both AI provider and API key are non-empty."""
        return bool(self.ai_api_key and self.ai_model)


settings = Settings()
