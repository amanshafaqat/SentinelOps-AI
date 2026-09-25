"""Investigation Copilot Package.

Provides evidence-grounded AI security incident analysis, interactive analyst Q&A,
prompt injection defense, and output grounding verification.
"""

from backend.app.investigation.prompts import (
    PROMPT_VERSION,
    INVESTIGATION_SYSTEM_PROMPT,
    build_analysis_user_prompt,
    build_question_user_prompt,
)
from backend.app.investigation.context_builder import (
    InvestigationContextBuilder,
    BuiltInvestigationContext,
    EvidenceCatalogItem,
)
from backend.app.investigation.gemini_client import (
    GeminiClient,
    default_gemini_client,
    GeminiError,
    GeminiConfigurationError,
    GeminiAuthenticationError,
    GeminiRateLimitError,
    GeminiServiceUnavailableError,
    GeminiTimeoutError,
    GeminiNetworkError,
    GeminiResponseError,
)
from backend.app.investigation.validator import (
    InvestigationResponseValidator,
    InvestigationValidationError,
)
from backend.app.investigation.service import (
    InvestigationService,
    default_investigation_service,
    InvestigationServiceError,
    IncidentNotFoundError,
    RateLimitExceededError,
)

__all__ = [
    "PROMPT_VERSION",
    "INVESTIGATION_SYSTEM_PROMPT",
    "build_analysis_user_prompt",
    "build_question_user_prompt",
    "InvestigationContextBuilder",
    "BuiltInvestigationContext",
    "EvidenceCatalogItem",
    "GeminiClient",
    "default_gemini_client",
    "GeminiError",
    "GeminiConfigurationError",
    "GeminiAuthenticationError",
    "GeminiRateLimitError",
    "GeminiServiceUnavailableError",
    "GeminiTimeoutError",
    "GeminiNetworkError",
    "GeminiResponseError",
    "InvestigationResponseValidator",
    "InvestigationValidationError",
    "InvestigationService",
    "default_investigation_service",
    "InvestigationServiceError",
    "IncidentNotFoundError",
    "RateLimitExceededError",
]
