"""AI Response Validator and Evidence Grounding Verifier.

Parses, sanitizes, repairs, and rigorously validates structured Gemini responses.
Performs deterministic evidence cross-referencing against the incident catalog to detect
and mark or eliminate hallucinated event and alert identifiers.
"""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError

from backend.app.schemas.investigation import (
    EvidenceReferenceItem,
    IncidentInvestigationAnalysis,
    AnalystQuestionResponse,
)
from backend.app.investigation.context_builder import EvidenceCatalogItem

logger = logging.getLogger(__name__)


class InvestigationValidationError(Exception):
    """Raised when AI response fails structural or grounding validation."""
    def __init__(self, message: str, raw_output: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.raw_output = raw_output


class InvestigationResponseValidator:
    """Validates and grounds Gemini model output against deterministic incident evidence."""

    @classmethod
    def clean_json_text(cls, raw_text: str) -> str:
        """Strips markdown code blocks, backticks, or trailing commentary."""
        text = raw_text.strip()
        # Remove ```json ... ``` or ``` ... ```
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        # Find first '{' and last '}'
        start_idx = text.find("{")
        end_idx = text.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            text = text[start_idx : end_idx + 1]

        return text

    @classmethod
    def parse_json(cls, raw_text: str) -> Dict[str, Any]:
        """Safely parses JSON with fallback heuristics for minor formatting quirks."""
        cleaned = cls.clean_json_text(raw_text)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as err:
            logger.warning("Initial JSON decode failed: %s. Attempting heuristic repair.", err)
            # Try removing trailing commas before closing braces/brackets
            repaired = re.sub(r",\s*([\]}])", r"\1", cleaned)
            try:
                return json.loads(repaired)
            except json.JSONDecodeError as err2:
                logger.error("JSON repair failed on text: %s", cleaned[:200])
                raise InvestigationValidationError(
                    f"Gemini output could not be parsed as valid JSON: {str(err2)}",
                    raw_output=raw_text,
                ) from err2

    @classmethod
    def validate_analysis_response(
        cls,
        raw_output: str,
        incident_id: str,
        model_used: str,
        evidence_catalog: Dict[str, EvidenceCatalogItem],
        evidence_truncated: bool = False,
    ) -> IncidentInvestigationAnalysis:
        """Validates structured incident analysis and grounds evidence references."""
        data = cls.parse_json(raw_output)

        # Cross-reference evidence references
        raw_evidence_refs = data.get("evidence_references", [])
        grounded_refs = cls._ground_evidence_references(raw_evidence_refs, evidence_catalog)

        try:
            analysis = IncidentInvestigationAnalysis(
                incident_id=incident_id,
                analysis_type="incident_summary",
                model_used=model_used,
                summary=str(data.get("summary") or "Investigation analysis completed."),
                observed_facts=cls._ensure_str_list(data.get("observed_facts")),
                potential_explanations=cls._ensure_str_list(data.get("potential_explanations")),
                evidence_references=grounded_refs,
                missing_information=cls._ensure_str_list(data.get("missing_information")),
                recommended_next_steps=cls._ensure_str_list(data.get("recommended_next_steps")),
                uncertainty_assessment=str(data.get("uncertainty_assessment") or ""),
                evidence_truncated=evidence_truncated,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            return analysis
        except ValidationError as err:
            logger.error("Pydantic validation error for incident analysis: %s", err)
            raise InvestigationValidationError(
                f"Incident analysis structure failed validation: {str(err)}",
                raw_output=raw_output,
            ) from err

    @classmethod
    def validate_question_response(
        cls,
        raw_output: str,
        incident_id: str,
        question: str,
        model_used: str,
        evidence_catalog: Dict[str, EvidenceCatalogItem],
        evidence_truncated: bool = False,
    ) -> AnalystQuestionResponse:
        """Validates structured analyst Q&A response and grounds evidence references."""
        data = cls.parse_json(raw_output)

        raw_evidence_refs = data.get("evidence_references", [])
        grounded_refs = cls._ground_evidence_references(raw_evidence_refs, evidence_catalog)

        try:
            response = AnalystQuestionResponse(
                incident_id=incident_id,
                question=question,
                answer=str(data.get("answer") or "No answer provided by model."),
                observed_facts=cls._ensure_str_list(data.get("observed_facts")),
                evidence_references=grounded_refs,
                uncertainty_assessment=str(data.get("uncertainty_assessment") or ""),
                recommended_next_steps=cls._ensure_str_list(data.get("recommended_next_steps")),
                missing_information=cls._ensure_str_list(data.get("missing_information")),
                model_used=model_used,
                evidence_truncated=evidence_truncated,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            return response
        except ValidationError as err:
            logger.error("Pydantic validation error for analyst question response: %s", err)
            raise InvestigationValidationError(
                f"Analyst response structure failed validation: {str(err)}",
                raw_output=raw_output,
            ) from err

    @classmethod
    def _ground_evidence_references(
        cls,
        raw_refs: Any,
        evidence_catalog: Dict[str, EvidenceCatalogItem],
    ) -> List[EvidenceReferenceItem]:
        """Validates that referenced IDs exist in the incident evidence catalog."""
        grounded: List[EvidenceReferenceItem] = []
        if not isinstance(raw_refs, list):
            return grounded

        for item in raw_refs:
            ref_id: Optional[str] = None
            ref_desc: Optional[str] = None
            ref_type: str = "event"

            if isinstance(item, dict):
                ref_id = str(item.get("id", "")).strip()
                ref_desc = item.get("description")
                ref_type = str(item.get("type", "event")).lower()
            elif isinstance(item, str):
                ref_id = item.strip()

            if not ref_id:
                continue

            # Deterministic grounding check
            if ref_id in evidence_catalog:
                catalog_item = evidence_catalog[ref_id]
                grounded.append(
                    EvidenceReferenceItem(
                        id=ref_id,
                        type=catalog_item.type,
                        description=ref_desc or catalog_item.summary,
                        valid=True,
                        observed_at=catalog_item.timestamp,
                        severity=catalog_item.severity,
                    )
                )
            else:
                # Hallucinated or unknown ID -> Flag as unverified reference
                grounded.append(
                    EvidenceReferenceItem(
                        id=ref_id,
                        type=ref_type if ref_type in ("event", "alert") else "event",
                        description=f"[UNVERIFIED] Refers to ID not found in incident telemetry: {ref_desc or ''}".strip(),
                        valid=False,
                        observed_at=None,
                        severity=None,
                    )
                )

        return grounded

    @classmethod
    def _ensure_str_list(cls, val: Any) -> List[str]:
        """Ensures the parsed value is a list of non-empty strings."""
        if not val:
            return []
        if isinstance(val, list):
            return [str(item).strip() for item in val if item is not None and str(item).strip()]
        if isinstance(val, str):
            cleaned = val.strip()
            return [cleaned] if cleaned else []
        return [str(val)]
