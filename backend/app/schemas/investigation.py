"""Pydantic Schemas for Gemini Investigation Copilot.

Defines structured input/output contracts, evidence validation references,
and analyst Q&A payloads with strict typing and advisory disclaimers.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class EvidenceReferenceItem(BaseModel):
    """Grounding reference linking an AI observation directly to deterministic evidence."""
    id: str = Field(description="Unique ID of the cited security event or alert")
    type: str = Field(default="event", description="Evidence type: 'event' or 'alert'")
    description: Optional[str] = Field(default=None, description="Contextual note regarding why this item is cited")
    valid: bool = Field(default=True, description="True if verified against deterministic incident telemetry; False if hallucinated")
    observed_at: Optional[str] = Field(default=None, description="Timestamp of the cited evidence")
    severity: Optional[str] = Field(default=None, description="Severity rating of the evidence item if available")


class IncidentInvestigationAnalysis(BaseModel):
    """Structured AI findings for a correlated security incident."""
    incident_id: str = Field(description="UUID of the analyzed incident")
    analysis_type: str = Field(default="incident_summary", description="Analysis category: incident_summary, analyst_query")
    model_used: str = Field(description="Configured Gemini model identifier used for analysis")
    summary: str = Field(description="Concise forensic summary of observed activity")
    observed_facts: List[str] = Field(default_factory=list, description="Factual events directly corroborated by telemetry")
    potential_explanations: List[str] = Field(default_factory=list, description="Plausible hypotheses (both attack tactics and benign scenarios)")
    evidence_references: List[EvidenceReferenceItem] = Field(default_factory=list, description="Traceable telemetry links")
    missing_information: List[str] = Field(default_factory=list, description="Telemetry gaps, blind spots, or unobserved indicators")
    recommended_next_steps: List[str] = Field(default_factory=list, description="Actionable manual triage and containment steps for the SOC analyst")
    uncertainty_assessment: str = Field(default="", description="Explicit assessment of analytical confidence and limitations")
    evidence_truncated: bool = Field(default=False, description="Flag indicating if the event dataset was capped due to context budget limits")
    disclaimer: str = Field(
        default="AI-generated analysis is advisory and must be reviewed by a human analyst. Deterministic telemetry remains the primary source of truth.",
        description="Mandatory advisory notice"
    )
    created_at: str = Field(description="UTC timestamp of the analysis generation")


class AnalystQuestionRequest(BaseModel):
    """Analyst prompt asking a scoped investigation question about the incident."""
    question: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Analyst question regarding this incident's telemetry",
        examples=["What evidence suggests suspicious activity?", "Could there be a benign explanation for this traffic?"]
    )
    actor: Optional[str] = Field(default="soc_analyst", max_length=128, description="Analyst username or handle")

    @field_validator("question")
    @classmethod
    def sanitize_question(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Investigation question cannot be empty or whitespace only.")
        return cleaned


class AnalystQuestionResponse(BaseModel):
    """Grounded AI answer to an analyst investigation inquiry."""
    incident_id: str = Field(description="UUID of the analyzed incident")
    question: str = Field(description="Original sanitized analyst question")
    answer: str = Field(description="Evidence-grounded response answering the question")
    observed_facts: List[str] = Field(default_factory=list, description="Directly observed facts relevant to the inquiry")
    evidence_references: List[EvidenceReferenceItem] = Field(default_factory=list, description="Verified event/alert references")
    uncertainty_assessment: str = Field(default="", description="Confidence boundaries or missing telemetry relevant to the question")
    recommended_next_steps: List[str] = Field(default_factory=list, description="Suggested analyst verification steps")
    missing_information: List[str] = Field(default_factory=list, description="Gaps in telemetry related to the question")
    model_used: str = Field(description="Model used")
    evidence_truncated: bool = Field(default=False)
    disclaimer: str = Field(
        default="AI-generated analysis is advisory and must be reviewed by a human analyst. Deterministic telemetry remains the primary source of truth."
    )
    created_at: str = Field(description="UTC timestamp")


class InvestigationStatusResponse(BaseModel):
    """Health and status of the server-side Gemini Investigation Copilot."""
    status: str = Field(description="Operational status: 'ready', 'unconfigured', 'degraded'")
    model: str = Field(description="Configured Gemini model identifier")
    api_key_configured: bool = Field(description="Boolean flag indicating whether GEMINI_API_KEY is configured on the backend")
    timeout_seconds: float = Field(description="Configured request timeout in seconds")
    max_context_events: int = Field(description="Max supporting events incorporated into prompt context")
    disclaimer: str = Field(
        default="AI-generated analysis is advisory and must be reviewed by a human analyst. Deterministic telemetry remains the primary source of truth."
    )
