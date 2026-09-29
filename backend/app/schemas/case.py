"""Pydantic schemas for Case Management, Analyst Notes, and Investigation Reports."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class CaseNoteCreate(BaseModel):
    """Payload to add an analyst investigation note to an incident."""
    content: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Analyst investigation observation, triage note, or case commentary",
    )
    author: Optional[str] = Field(
        default="soc_analyst",
        max_length=128,
        description="Analyst username, handle, or role",
    )

    @field_validator("content")
    @classmethod
    def validate_content_not_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Note content cannot be empty or contain only whitespace.")
        return cleaned

    @field_validator("author")
    @classmethod
    def validate_author(cls, v: Optional[str]) -> str:
        if not v or not v.strip():
            return "soc_analyst"
        return v.strip()


class CaseNoteUpdate(BaseModel):
    """Payload to update an existing analyst note."""
    content: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Updated note content",
    )
    author: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Author performing the update",
    )

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Note content cannot be empty.")
        return cleaned


class CaseNoteResponse(BaseModel):
    """Single analyst investigation note."""
    id: str = Field(description="Unique note UUID")
    incident_id: str = Field(description="Associated incident UUID")
    author: str = Field(description="Author identifier")
    content: str = Field(description="Note text")
    created_at: str = Field(description="Creation UTC timestamp")
    updated_at: str = Field(description="Last update UTC timestamp")

    class Config:
        from_attributes = True


class CaseNoteListResponse(BaseModel):
    """List of notes attached to an incident."""
    incident_id: str = Field(description="Associated incident UUID")
    total: int = Field(description="Total note count")
    notes: List[CaseNoteResponse] = Field(default_factory=list)


class InvestigationReportCreate(BaseModel):
    """Request payload to generate a new investigation report."""
    report_type: Optional[str] = Field(
        default="investigation_summary",
        max_length=64,
        description="Report classification: investigation_summary, executive_brief, post_incident_review",
    )
    title: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Custom title (if omitted, generated automatically)",
    )
    generated_by: Optional[str] = Field(
        default="soc_analyst",
        max_length=128,
        description="Analyst username or service identifier",
    )
    include_ai_analysis: bool = Field(
        default=True,
        description="Whether to incorporate latest verified AI findings (clearly labeled as advisory)",
    )


class InvestigationReportListItem(BaseModel):
    """Summary item for investigation report lists."""
    id: str = Field(description="Unique report UUID")
    incident_id: str = Field(description="Associated incident UUID")
    title: str = Field(description="Report title")
    report_type: str = Field(description="Report type")
    generated_by: str = Field(description="Author / Generator")
    summary: str = Field(description="Executive summary")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Report metadata metrics")
    created_at: str = Field(description="UTC generation timestamp")

    class Config:
        from_attributes = True


class InvestigationReportListResponse(BaseModel):
    """List of reports generated for an incident."""
    incident_id: str = Field(description="Associated incident UUID")
    total: int = Field(description="Total report count")
    reports: List[InvestigationReportListItem] = Field(default_factory=list)


class InvestigationReportResponse(BaseModel):
    """Comprehensive investigation report with structured JSON and rendered HTML."""
    id: str = Field(description="Unique report UUID")
    incident_id: str = Field(description="Associated incident UUID")
    title: str = Field(description="Report title")
    report_type: str = Field(description="Report type")
    generated_by: str = Field(description="Author / Generator")
    summary: str = Field(description="Executive summary")
    content: Dict[str, Any] = Field(description="Structured forensic sections")
    rendered_html: str = Field(description="Standalone, print-ready HTML document")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata and metrics")
    created_at: str = Field(description="UTC generation timestamp")

    class Config:
        from_attributes = True
