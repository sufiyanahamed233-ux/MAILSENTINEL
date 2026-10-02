"""Pydantic schemas for Phase 5C — Evidence, Audit Events, and Threat Indicators.

Exposes:
- EvidenceItem: chain-of-custody evidence records
- EvidenceListResponse: paginated collection of evidence
- InvestigationEventItem: sanitized audit-trail events (metadata keys allowlisted)
- EventListResponse: paginated audit trail
- ThreatIndicatorItem: normalized forensic indicators (distinct from external TI enrichments)
- IndicatorListResponse: paginated indicator collection

Security rules enforced by schema:
- Blockchain fields surfaced as-is (no binary payloads stored in these columns)
- event_metadata allowlist excludes any keys that could leak credentials,
  internal file paths, raw email content, or raw provider responses
- No raw_response, body_plain, body_html, or attachment binary
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Allowlisted metadata keys for InvestigationEvent.event_metadata
# Only keys in this set are passed through to the API response.
# ---------------------------------------------------------------------------
_SAFE_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "action",
        "actor",
        "analysis_id",
        "case_id",
        "case_number",
        "case_status",
        "change",
        "classification",
        "confidence",
        "count",
        "created_at",
        "duration_ms",
        "email_id",
        "email_status",
        "enrichment_provider",
        "error",
        "event_type",
        "filename",
        "from_status",
        "indicator_count",
        "indicator_type",
        "indicator_value",
        "message",
        "priority",
        "provider",
        "reason",
        "reputation",
        "result",
        "risk_score",
        "source",
        "status",
        "timestamp",
        "title",
        "to_status",
        "updated_at",
        "user",
        "verdict",
    }
)


def _sanitize_metadata(raw: "dict[str, Any] | None") -> "dict[str, Any] | None":
    """Return only allowlisted top-level metadata keys."""
    if raw is None:
        return None
    sanitized = {k: v for k, v in raw.items() if k in _SAFE_METADATA_KEYS}
    return sanitized or None


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class EvidenceItem(BaseModel):
    """Chain-of-custody forensic evidence record."""

    model_config = {"from_attributes": True}

    id: uuid.UUID = Field(..., description="Unique evidence record identifier")
    case_id: uuid.UUID = Field(..., description="Associated investigation case")
    evidence_type: str = Field(..., description="Type classification of the evidence")
    description: "str | None" = Field(None, description="Human-readable evidence description")
    sha256: str = Field(..., description="SHA-256 hash of the evidential artefact")
    collected_at: datetime = Field(..., description="Timestamp when evidence was collected")
    collected_by: "str | None" = Field(None, description="Actor or system that collected the evidence")
    blockchain_tx_id: "str | None" = Field(None, description="Reference blockchain transaction ID")
    blockchain_verified: bool = Field(..., description="Whether blockchain integrity proof is verified")
    created_at: datetime = Field(..., description="Record creation timestamp")

    @field_validator("sha256")
    @classmethod
    def sha256_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("sha256 must not be empty")
        return v.strip().lower()


class EvidenceListResponse(BaseModel):
    """Paginated response for evidence records scoped to a case."""

    model_config = {"from_attributes": True}

    case_id: uuid.UUID = Field(..., description="Investigation case these records belong to")
    items: "list[EvidenceItem]" = Field(default_factory=list, description="Evidence records")
    total: int = Field(..., ge=0, description="Total count of evidence records in this case")
    limit: int = Field(..., ge=1, description="Maximum records returned")
    offset: int = Field(..., ge=0, description="Pagination offset applied")


# ---------------------------------------------------------------------------
# Investigation Events
# ---------------------------------------------------------------------------


class InvestigationEventItem(BaseModel):
    """Single sanitized audit-trail event."""

    model_config = {"from_attributes": True}

    id: uuid.UUID = Field(..., description="Unique event identifier")
    event_type: str = Field(..., description="Categorisation of the audit event")
    description: str = Field(..., description="Human-readable event description")
    actor: "str | None" = Field(None, description="System or user that generated the event")
    created_at: datetime = Field(..., description="Event creation timestamp")
    metadata: "dict[str, Any] | None" = Field(None, description="Sanitized event metadata")

    @model_validator(mode="before")
    @classmethod
    def sanitize_event_metadata(cls, data: Any) -> Any:
        """Sanitize raw metadata before field validation."""
        if isinstance(data, dict):
            raw_meta = data.get("metadata") or data.get("event_metadata")
            data = dict(data)
            data["metadata"] = _sanitize_metadata(raw_meta)
        else:
            raw_meta = getattr(data, "event_metadata", None)
            return {
                "id": getattr(data, "id", None),
                "event_type": getattr(data, "event_type", None),
                "description": getattr(data, "description", None),
                "actor": getattr(data, "actor", None),
                "created_at": getattr(data, "created_at", None),
                "metadata": _sanitize_metadata(raw_meta),
            }
        return data


class EventListResponse(BaseModel):
    """Paginated response for investigation audit events scoped to a case."""

    model_config = {"from_attributes": True}

    case_id: uuid.UUID = Field(..., description="Investigation case these events belong to")
    items: "list[InvestigationEventItem]" = Field(default_factory=list, description="Chronological audit events")
    total: int = Field(..., ge=0, description="Total count of events in this case")
    limit: int = Field(..., ge=1, description="Maximum records returned")
    offset: int = Field(..., ge=0, description="Pagination offset applied")


# ---------------------------------------------------------------------------
# Threat Indicators
# ---------------------------------------------------------------------------


class ThreatIndicatorItem(BaseModel):
    """Normalized forensic threat indicator observed during investigation."""

    model_config = {"from_attributes": True}

    id: uuid.UUID = Field(..., description="Unique indicator identifier")
    indicator_type: str = Field(..., description="Type of indicator (ip, domain, url, hash)")
    indicator_value: str = Field(..., description="Observed indicator value")
    source: "str | None" = Field(None, description="Detection source or parser")
    reputation: "str | None" = Field(None, description="Reputation classification")
    confidence: "int | None" = Field(None, ge=0, le=100, description="Confidence score (0-100)")
    first_seen: "datetime | None" = Field(None, description="Earliest observed datetime")
    last_seen: "datetime | None" = Field(None, description="Latest observed datetime")
    created_at: datetime = Field(..., description="Record creation timestamp")


class IndicatorListResponse(BaseModel):
    """Paginated response for threat indicators scoped to a case."""

    model_config = {"from_attributes": True}

    case_id: uuid.UUID = Field(..., description="Investigation case these indicators belong to")
    items: "list[ThreatIndicatorItem]" = Field(default_factory=list, description="Threat indicators")
    total: int = Field(..., ge=0, description="Total count of indicators in this case")
    limit: int = Field(..., ge=1, description="Maximum records returned")
    offset: int = Field(..., ge=0, description="Pagination offset applied")
