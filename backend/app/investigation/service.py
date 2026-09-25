"""Orchestration Service for Gemini-Powered Incident Investigation.

Coordinates context extraction, prompt injection defense, server-side Gemini execution,
evidence grounding validation, and immutable audit logging.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional
from collections import defaultdict
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.incident import Incident, IncidentAuditLog, IncidentAIAnalysis
from backend.app.schemas.investigation import (
    IncidentInvestigationAnalysis,
    AnalystQuestionResponse,
    EvidenceReferenceItem,
)
from backend.app.investigation.context_builder import InvestigationContextBuilder
from backend.app.investigation.gemini_client import (
    GeminiClient,
    default_gemini_client,
    GeminiError,
    GeminiRateLimitError,
)
from backend.app.investigation.prompts import (
    INVESTIGATION_SYSTEM_PROMPT,
    build_analysis_user_prompt,
    build_question_user_prompt,
)
from backend.app.investigation.validator import InvestigationResponseValidator

logger = logging.getLogger(__name__)


class InvestigationServiceError(Exception):
    """Base exception for investigation service errors."""
    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class IncidentNotFoundError(InvestigationServiceError):
    def __init__(self, incident_id: str):
        super().__init__(f"Incident with ID '{incident_id}' was not found.", status_code=404)


class RateLimitExceededError(InvestigationServiceError):
    def __init__(self, message: str = "Investigation request rate limit exceeded. Please wait a moment."):
        super().__init__(message, status_code=429)


class InvestigationService:
    """Orchestrates secure, evidence-grounded AI investigations for SOC incidents."""

    def __init__(
        self,
        gemini_client: Optional[GeminiClient] = None,
        context_builder: Optional[InvestigationContextBuilder] = None,
    ):
        self.gemini_client = gemini_client or default_gemini_client
        self.context_builder = context_builder or InvestigationContextBuilder()
        # Simple in-memory rate limiting: {client_identifier: [timestamp, ...]}
        self._rate_limits: Dict[str, List[float]] = defaultdict(list)

    def check_rate_limit(self, client_key: str):
        """Enforces sliding-window rate limit per client or incident."""
        now = time.time()
        window = 60.0  # 1 minute window
        max_requests = settings.gemini_rate_limit_per_minute

        timestamps = [t for t in self._rate_limits[client_key] if now - t < window]
        if len(timestamps) >= max_requests:
            raise RateLimitExceededError(
                f"Rate limit exceeded: maximum {max_requests} AI investigation requests per minute."
            )
        timestamps.append(now)
        self._rate_limits[client_key] = timestamps

    async def analyze_incident(
        self,
        db: Session,
        incident_id: str,
        actor: str = "soc_analyst",
        client_key: Optional[str] = None,
    ) -> IncidentInvestigationAnalysis:
        """Executes full evidence-grounded AI investigation analysis for an incident."""
        # 1. Rate limiting check
        self.check_rate_limit(client_key or incident_id)

        # 2. Retrieve Incident
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise IncidentNotFoundError(incident_id)

        # 3. Build bounded, sanitized evidence context
        context = self.context_builder.build_context(db, incident)

        # 4. Construct user prompt with XML evidence & strict schema instruction
        user_prompt = build_analysis_user_prompt(context.evidence_xml)

        # 5. Invoke Gemini with strict system instruction
        raw_output = await self.gemini_client.generate_content_async(
            system_instruction=INVESTIGATION_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        # 6. Validate and Ground evidence references
        analysis = InvestigationResponseValidator.validate_analysis_response(
            raw_output=raw_output,
            incident_id=incident.id,
            model_used=self.gemini_client.model,
            evidence_catalog=context.evidence_catalog,
            evidence_truncated=context.evidence_truncated,
        )

        # 7. Audit Logging & Persistence
        audit_entry = IncidentAuditLog(
            incident_id=incident.id,
            action="ai_investigation_run",
            previous_value=None,
            new_value=f"Analysis completed by {self.gemini_client.model}",
            notes=f"AI Copilot analyzed incident with {len(analysis.observed_facts)} facts and {len(analysis.evidence_references)} evidence citations.",
            actor=actor,
        )
        db.add(audit_entry)

        ai_record = IncidentAIAnalysis(
            incident_id=incident.id,
            analysis_type="incident_summary",
            query=None,
            model=self.gemini_client.model,
            summary=analysis.summary,
            observed_facts=analysis.observed_facts,
            potential_explanations=analysis.potential_explanations,
            evidence_references=[ref.model_dump() for ref in analysis.evidence_references],
            missing_information=analysis.missing_information,
            recommended_next_steps=analysis.recommended_next_steps,
            uncertainty_assessment=analysis.uncertainty_assessment,
            evidence_truncated=analysis.evidence_truncated,
            actor=actor,
        )
        db.add(ai_record)
        db.commit()

        return analysis

    async def ask_analyst_question(
        self,
        db: Session,
        incident_id: str,
        question: str,
        actor: str = "soc_analyst",
        client_key: Optional[str] = None,
    ) -> AnalystQuestionResponse:
        """Answers an analyst question grounded strictly in incident evidence."""
        # 1. Rate limiting check
        self.check_rate_limit(client_key or incident_id)

        # 2. Retrieve Incident
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise IncidentNotFoundError(incident_id)

        # 3. Build bounded, sanitized evidence context
        context = self.context_builder.build_context(db, incident)

        # 4. Construct user prompt for Q&A
        user_prompt = build_question_user_prompt(context.evidence_xml, question)

        # 5. Invoke Gemini
        raw_output = await self.gemini_client.generate_content_async(
            system_instruction=INVESTIGATION_SYSTEM_PROMPT,
            user_prompt=user_prompt,
        )

        # 6. Validate and Ground
        response = InvestigationResponseValidator.validate_question_response(
            raw_output=raw_output,
            incident_id=incident.id,
            question=question,
            model_used=self.gemini_client.model,
            evidence_catalog=context.evidence_catalog,
            evidence_truncated=context.evidence_truncated,
        )

        # 7. Audit Logging & Persistence
        audit_entry = IncidentAuditLog(
            incident_id=incident.id,
            action="ai_analyst_question",
            previous_value=None,
            new_value=f"Question: {question[:100]}...",
            notes=f"Analyst inquiry answered with {len(response.evidence_references)} evidence citations.",
            actor=actor,
        )
        db.add(audit_entry)

        ai_record = IncidentAIAnalysis(
            incident_id=incident.id,
            analysis_type="analyst_query",
            query=question,
            model=self.gemini_client.model,
            summary=response.answer,
            observed_facts=response.observed_facts,
            potential_explanations=[],
            evidence_references=[ref.model_dump() for ref in response.evidence_references],
            missing_information=response.missing_information,
            recommended_next_steps=response.recommended_next_steps,
            uncertainty_assessment=response.uncertainty_assessment,
            evidence_truncated=response.evidence_truncated,
            actor=actor,
        )
        db.add(ai_record)
        db.commit()

        return response

    def get_incident_ai_history(
        self,
        db: Session,
        incident_id: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Retrieves prior AI investigation records and analyst Q&A history."""
        records = (
            db.query(IncidentAIAnalysis)
            .filter(IncidentAIAnalysis.incident_id == incident_id)
            .order_by(IncidentAIAnalysis.created_at.desc())
            .limit(limit)
            .all()
        )
        return [r.to_dict() for r in records]


# Singleton instance
default_investigation_service = InvestigationService()
