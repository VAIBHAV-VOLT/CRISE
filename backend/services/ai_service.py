"""
CRISE — AI Service Provider Abstraction
=======================================
Stateless service handling communications with LLM providers (OpenAI / OpenAI-compatible).
Translates structured CRISE context and natural-language user questions into clear explanations.

CRITICAL SECURITY RULES:
1. API key is read strictly from backend config (`settings.ai_api_key`).
2. API key is NEVER logged, exposed, or returned in status responses.
3. Errors must fail safely without leaking provider secrets or credentials.
"""

import json
import logging
from typing import Dict, Any, Optional, List
import httpx

from config import settings
from services.ai_prompts import SYSTEM_PROMPT

logger = logging.getLogger("crise.ai_service")


class AIService:
    """Abstracted service layer for interacting with LLM providers."""

    def __init__(self):
        pass

    def is_configured(self) -> bool:
        """Return whether the AI provider and API key are configured."""
        return settings.is_ai_configured

    def get_provider_status(self) -> Dict[str, Any]:
        """
        Return public status metadata for UI status indicators.
        NEVER includes secrets, API keys, or fragments.
        """
        configured = settings.is_ai_configured
        return {
            "configured": configured,
            "provider": settings.ai_provider if configured else "none",
            "model": settings.ai_model if configured else "not_configured",
            "available": configured
        }

    def analyze(self, question: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send user question and CRISE structured context to configured LLM provider.
        """
        if not self.is_configured():
            return {
                "error": "AI service is not configured. Set AI_API_KEY and AI_MODEL in backend .env file.",
                "status_code": 503
            }

        # Build endpoint URL
        base_url = (settings.ai_base_url or "https://api.openai.com/v1").rstrip("/")
        if not base_url.endswith("/chat/completions"):
            endpoint_url = f"{base_url}/chat/completions"
        else:
            endpoint_url = base_url

        headers = {
            "Authorization": f"Bearer {settings.ai_api_key}",
            "Content-Type": "application/json"
        }

        user_content = (
            f"CRISE STRUCTURED FINDINGS CONTEXT:\n"
            f"```json\n{json.dumps(context, indent=2)}\n```\n\n"
            f"USER QUESTION:\n{question}"
        )

        payload = {
            "model": settings.ai_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content}
            ],
            "temperature": settings.ai_temperature,
            "max_tokens": settings.ai_max_tokens,
            "response_format": {"type": "json_object"}
        }

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(endpoint_url, headers=headers, json=payload)

            if response.status_code in (400, 401, 403):
                err_msg = ""
                try:
                    res_body = response.json()
                    if isinstance(res_body, list) and len(res_body) > 0:
                        res_body = res_body[0]
                    if isinstance(res_body, dict):
                        err_msg = res_body.get("error", {}).get("message", "")
                except Exception:
                    pass

                logger.error("AI Provider Authentication Failed (HTTP %d): %s", response.status_code, err_msg)
                if "API key" in err_msg or response.status_code in (401, 403):
                    return {
                        "error": "AI provider authentication failed. Please set a valid Gemini AI_API_KEY in backend .env file.",
                        "status_code": 503
                    }
                else:
                    return {
                        "error": f"AI provider request rejected (HTTP {response.status_code}): {err_msg or 'Invalid request'}",
                        "status_code": 503
                    }
            elif response.status_code == 429:
                logger.error("AI Provider Rate Limit Exceeded (HTTP 429)")
                return {
                    "error": "AI provider rate limit exceeded. Please try again in a few moments.",
                    "status_code": 503
                }
            elif response.status_code >= 500:
                logger.error("AI Provider Error (HTTP %d)", response.status_code)
                return {
                    "error": "AI provider server error. Please try again later.",
                    "status_code": 503
                }
            elif response.status_code != 200:
                logger.error("AI Provider Returned HTTP %d", response.status_code)
                return {
                    "error": f"AI provider request failed with status {response.status_code}.",
                    "status_code": 503
                }

            res_json = response.json()
            choices = res_json.get("choices", [])
            if not choices:
                return {
                    "error": "AI provider returned empty choices response.",
                    "status_code": 503
                }

            raw_text = choices[0].get("message", {}).get("content", "").strip()

            # Attempt JSON parsing of LLM response
            try:
                parsed_ai = json.loads(raw_text)
                answer = parsed_ai.get("answer", raw_text)
                sources = parsed_ai.get("sources", [{"type": "CRISE", "reference": "general"}])
                confidence = parsed_ai.get("confidence", "HIGH")
            except Exception:
                answer = raw_text
                sources = [{"type": "CRISE", "reference": "general"}]
                confidence = "MEDIUM"

            if confidence not in ["HIGH", "MEDIUM", "LOW"]:
                confidence = "HIGH"

            return {
                "success": True,
                "answer": answer,
                "sources": sources,
                "confidence": confidence,
                "disclaimer": "AI-generated analysis based on CRISE results. Verify critical security decisions against authoritative security guidance."
            }

        except httpx.TimeoutException:
            logger.error("AI Provider Timeout")
            return {
                "error": "AI provider connection timed out.",
                "status_code": 504
            }
        except Exception as exc:
            logger.error("AI Provider Request Exception: %s", str(exc))
            return {
                "error": "Failed to communicate with AI provider.",
                "status_code": 503
            }


ai_service = AIService()
