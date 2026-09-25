"""Isolated Gemini API Client for SentinelOps AI Investigation Copilot.

Communicates with Google's Gemini REST API (v1beta) using server-side httpx calls.
Enforces timeouts, response size limits, error masking (never leaking API keys or internal
traces), and structured JSON generation mode.
"""

import json
import logging
from typing import Any, Dict, Optional
import httpx

from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class GeminiError(Exception):
    """Base exception for Gemini copilot errors with analyst-safe messages."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class GeminiConfigurationError(GeminiError):
    """Raised when the Gemini API key or required model configuration is missing."""
    def __init__(self, message: str = "Gemini API key is not configured on the server. Please set GEMINI_API_KEY."):
        super().__init__(message, status_code=503)


class GeminiAuthenticationError(GeminiError):
    """Raised when the Gemini API key is rejected by the provider."""
    def __init__(self, message: str = "Authentication with Gemini API failed. Please check the configured API key."):
        super().__init__(message, status_code=502)


class GeminiRateLimitError(GeminiError):
    """Raised when request rate limits or quotas are exceeded."""
    def __init__(self, message: str = "Gemini API rate limit exceeded. Please wait a moment and try again."):
        super().__init__(message, status_code=429)


class GeminiServiceUnavailableError(GeminiError):
    """Raised when the upstream Gemini service returns 5xx errors."""
    def __init__(self, message: str = "Gemini API service is temporarily unavailable. Please try again later."):
        super().__init__(message, status_code=503)


class GeminiTimeoutError(GeminiError):
    """Raised when a Gemini API request exceeds the configured timeout."""
    def __init__(self, message: str = "Gemini API request timed out. Telemetry was too large or service was slow."):
        super().__init__(message, status_code=504)


class GeminiNetworkError(GeminiError):
    """Raised when a network connectivity failure occurs."""
    def __init__(self, message: str = "Network connectivity error connecting to the Gemini API."):
        super().__init__(message, status_code=502)


class GeminiResponseError(GeminiError):
    """Raised when Gemini returns an unparseable or blocked response."""
    def __init__(self, message: str = "Gemini returned an invalid or incomplete response."):
        super().__init__(message, status_code=502)


class GeminiClient:
    """Server-side client for interacting with Gemini models."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        max_output_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ):
        self.api_key = api_key if api_key is not None else settings.gemini_api_key
        self.model = model or settings.gemini_model
        # Strip potential models/ prefix if already provided
        if self.model.startswith("models/"):
            self.model = self.model[len("models/") :]
        self.timeout_seconds = timeout_seconds or settings.gemini_timeout_seconds
        self.max_output_tokens = max_output_tokens or settings.gemini_max_output_tokens
        self.temperature = temperature if temperature is not None else settings.gemini_temperature

    def is_configured(self) -> bool:
        """Returns True if a non-empty API key is present."""
        return bool(self.api_key and self.api_key.strip())

    async def generate_content_async(
        self,
        system_instruction: str,
        user_prompt: str,
    ) -> str:
        """Asynchronously calls Gemini generateContent endpoint."""
        if not self.is_configured():
            raise GeminiConfigurationError()

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        params = {"key": self.api_key}

        payload: Dict[str, Any] = {
            "system_instruction": {
                "parts": [{"text": system_instruction}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}]
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
            },
        }

        timeout = httpx.Timeout(self.timeout_seconds, connect=10.0)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    url,
                    params=params,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

                return self._handle_response(response)

        except httpx.TimeoutException as exc:
            logger.warning("Gemini API request timed out after %.1fs: %s", self.timeout_seconds, exc)
            raise GeminiTimeoutError() from exc
        except httpx.NetworkError as exc:
            logger.error("Gemini API network error: %s", exc)
            raise GeminiNetworkError() from exc
        except GeminiError:
            raise
        except Exception as exc:
            logger.error("Unexpected error invoking Gemini API: %s", exc)
            raise GeminiResponseError(f"Unexpected error communicating with Gemini: {str(exc)}") from exc

    def generate_content(
        self,
        system_instruction: str,
        user_prompt: str,
    ) -> str:
        """Synchronous version of generateContent for blocking execution or scripts."""
        if not self.is_configured():
            raise GeminiConfigurationError()

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        params = {"key": self.api_key}

        payload: Dict[str, Any] = {
            "system_instruction": {
                "parts": [{"text": system_instruction}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}]
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
            },
        }

        timeout = httpx.Timeout(self.timeout_seconds, connect=10.0)

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(
                    url,
                    params=params,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                return self._handle_response(response)

        except httpx.TimeoutException as exc:
            logger.warning("Gemini API request timed out after %.1fs: %s", self.timeout_seconds, exc)
            raise GeminiTimeoutError() from exc
        except httpx.NetworkError as exc:
            logger.error("Gemini API network error: %s", exc)
            raise GeminiNetworkError() from exc
        except GeminiError:
            raise
        except Exception as exc:
            logger.error("Unexpected error invoking Gemini API: %s", exc)
            raise GeminiResponseError(f"Unexpected error communicating with Gemini: {str(exc)}") from exc

    def _handle_response(self, response: httpx.Response) -> str:
        """Evaluates HTTP response status and extracts generated text content."""
        if response.status_code == 200:
            try:
                data = response.json()
            except Exception as e:
                raise GeminiResponseError("Failed to parse Gemini response as JSON.") from e

            candidates = data.get("candidates", [])
            if not candidates:
                prompt_feedback = data.get("promptFeedback", {})
                block_reason = prompt_feedback.get("blockReason")
                if block_reason:
                    raise GeminiResponseError(f"Gemini request was blocked by safety filters: {block_reason}")
                raise GeminiResponseError("Gemini returned no candidates.")

            first_candidate = candidates[0]
            content = first_candidate.get("content", {})
            parts = content.get("parts", [])
            if not parts:
                raise GeminiResponseError("Gemini candidate contained no text parts.")

            raw_text = parts[0].get("text", "")
            return raw_text

        # Error mappings without leaking raw secrets or URL
        if response.status_code in (401, 403):
            raise GeminiAuthenticationError()
        elif response.status_code == 429:
            raise GeminiRateLimitError()
        elif response.status_code in (500, 502, 503, 504):
            raise GeminiServiceUnavailableError()
        else:
            try:
                err_data = response.json()
                err_msg = err_data.get("error", {}).get("message", f"HTTP {response.status_code}")
            except Exception:
                err_msg = f"HTTP {response.status_code}"
            raise GeminiResponseError(f"Gemini request failed: {err_msg}")


# Singleton instance
default_gemini_client = GeminiClient()
