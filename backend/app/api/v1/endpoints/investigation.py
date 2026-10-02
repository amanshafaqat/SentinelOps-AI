"""API Endpoints for Gemini Investigation Copilot.

Provides endpoints for evidence-grounded AI incident analysis, interactive analyst Q&A,
investigation audit history, and copilot readiness status.
"""

import logging
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, Request, status, Path
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.errors import format_error_response
from backend.app.db.session import get_db
from backend.app.schemas.investigation import (
    IncidentInvestigationAnalysis,
    AnalystQuestionRequest,
    AnalystQuestionResponse,
    InvestigationStatusResponse,
)
from backend.app.investigation.service import (
    default_investigation_service,
    IncidentNotFoundError,
    RateLimitExceededError,
)
from backend.app.investigation.gemini_client import (
    GeminiError,
    GeminiConfigurationError,
    GeminiAuthenticationError,
    GeminiRateLimitError,
    GeminiServiceUnavailableError,
    GeminiTimeoutError,
    GeminiNetworkError,
)
from backend.app.investigation.validator import InvestigationValidationError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Investigation Copilot"])


@router.get(
    "/investigation/status",
    response_model=InvestigationStatusResponse,
    summary="Get AI Copilot availability status",
    description="Returns product-facing availability of AI investigation without exposing internal keys or configurations.",
)
def get_copilot_status() -> InvestigationStatusResponse:
    is_configured = default_investigation_service.gemini_client.is_configured()
    return InvestigationStatusResponse(
        status="ready" if is_configured else "unconfigured",
        available=is_configured,
        message="AI Investigation Available" if is_configured else "AI Investigation Unavailable",
    )


@router.post(
    "/incidents/{incident_id}/analyze",
    response_model=IncidentInvestigationAnalysis,
    summary="Run AI evidence-grounded incident analysis",
    description="Invokes Gemini on the selected incident using strictly bounded, sanitized telemetry context.",
)
@router.post(
    "/incidents/{incident_id}/investigate",
    response_model=IncidentInvestigationAnalysis,
    include_in_schema=False,
)
@router.post(
    "/incidents/{incident_id}/analysis",
    response_model=IncidentInvestigationAnalysis,
    include_in_schema=False,
)
async def analyze_incident(
    request: Request,
    incident_id: str = Path(..., description="UUID of the incident to analyze"),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown_client"

    try:
        analysis = await default_investigation_service.analyze_incident(
            db=db,
            incident_id=incident_id,
            actor="soc_analyst",
            client_key=client_ip,
        )
        return analysis

    except IncidentNotFoundError as e:
        return format_error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="INCIDENT_NOT_FOUND",
            message=e.message,
        )
    except RateLimitExceededError as e:
        return format_error_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="RATE_LIMIT_EXCEEDED",
            message=e.message,
        )
    except GeminiConfigurationError as e:
        return format_error_response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="AI_COPILOT_UNCONFIGURED",
            message="AI Investigation Copilot is not configured with an API key on the backend.",
        )
    except GeminiAuthenticationError as e:
        return format_error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            code="AI_PROVIDER_AUTH_ERROR",
            message="AI Copilot authentication failed with the provider. Please verify API key configuration.",
        )
    except GeminiRateLimitError as e:
        return format_error_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="AI_PROVIDER_RATE_LIMIT",
            message="AI Copilot rate limit or quota exceeded with the upstream provider. Please retry in a few moments.",
        )
    except GeminiTimeoutError as e:
        return format_error_response(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            code="AI_PROVIDER_TIMEOUT",
            message="AI Copilot request timed out. Telemetry evidence was too large or provider response was delayed.",
        )
    except (GeminiServiceUnavailableError, GeminiNetworkError) as e:
        return format_error_response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="AI_PROVIDER_UNAVAILABLE",
            message="AI Copilot service is temporarily unreachable. The deterministic security dashboard remains operational.",
        )
    except InvestigationValidationError as e:
        logger.error("AI Investigation output validation failure: %s", e.message)
        return format_error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            code="AI_OUTPUT_VALIDATION_ERROR",
            message="AI Copilot output failed structured validation and could not be safely verified.",
        )
    except GeminiError as e:
        logger.error("Gemini copilot error during incident analysis: %s", e.message)
        return format_error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            code="AI_COPILOT_ERROR",
            message=e.message,
        )
    except Exception as e:
        logger.error("Unexpected error analyzing incident %s: %s", incident_id, str(e))
        return format_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected server error occurred during AI analysis.",
        )


@router.post(
    "/incidents/{incident_id}/ask",
    response_model=AnalystQuestionResponse,
    summary="Ask an evidence-grounded question about an incident",
    description="Submits an analyst investigation question scoped specifically to the incident's telemetry evidence.",
)
async def ask_analyst_question(
    request: Request,
    payload: AnalystQuestionRequest,
    incident_id: str = Path(..., description="UUID of the incident"),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown_client"

    try:
        response = await default_investigation_service.ask_analyst_question(
            db=db,
            incident_id=incident_id,
            question=payload.question,
            actor=payload.actor or "soc_analyst",
            client_key=client_ip,
        )
        return response

    except IncidentNotFoundError as e:
        return format_error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            code="INCIDENT_NOT_FOUND",
            message=e.message,
        )
    except RateLimitExceededError as e:
        return format_error_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="RATE_LIMIT_EXCEEDED",
            message=e.message,
        )
    except GeminiConfigurationError as e:
        return format_error_response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="AI_COPILOT_UNCONFIGURED",
            message="AI Investigation Copilot is not configured with an API key on the backend.",
        )
    except GeminiRateLimitError as e:
        return format_error_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code="AI_PROVIDER_RATE_LIMIT",
            message="AI Copilot rate limit or quota exceeded with the upstream provider. Please retry in a few moments.",
        )
    except GeminiTimeoutError as e:
        return format_error_response(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            code="AI_PROVIDER_TIMEOUT",
            message="AI Copilot request timed out.",
        )
    except (GeminiServiceUnavailableError, GeminiNetworkError) as e:
        return format_error_response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="AI_PROVIDER_UNAVAILABLE",
            message="AI Copilot service is temporarily unreachable.",
        )
    except InvestigationValidationError as e:
        logger.error("AI Investigation output validation failure: %s", e.message)
        return format_error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            code="AI_OUTPUT_VALIDATION_ERROR",
            message="AI Copilot response failed structured validation.",
        )
    except GeminiError as e:
        logger.error("Gemini copilot error answering analyst question: %s", e.message)
        return format_error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            code="AI_COPILOT_ERROR",
            message=e.message,
        )
    except Exception as e:
        logger.error("Unexpected error answering question for incident %s: %s", incident_id, str(e))
        return format_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected server error occurred during question answering.",
        )


@router.get(
    "/incidents/{incident_id}/ai-history",
    response_model=List[Dict[str, Any]],
    summary="Get AI investigation history for an incident",
    description="Retrieves chronological audit log of prior AI incident analyses and analyst Q&A.",
)
def get_incident_ai_history(
    incident_id: str = Path(..., description="UUID of the incident"),
    db: Session = Depends(get_db),
):
    history = default_investigation_service.get_incident_ai_history(db, incident_id)
    return history
