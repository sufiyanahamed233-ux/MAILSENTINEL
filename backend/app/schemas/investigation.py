"""Pydantic v2 schemas for Investigation Case Workspace and Listing.

These schemas define the structured response for the analyst investigation workspace
and case management. Separation of concerns is strictly preserved:
- Observed forensic evidence (emails, headers, URLs, domains, IPs, attachments)
- External threat intelligence enrichment (with raw provider responses excluded)
- AI threat assessment conclusions
- Chronological investigation event audit trail
- Service-computed investigation summary
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.ai_analysis import AIAnalysisResultResponse


# ---------------------------------------------------------------------------
# Forensic Evidence: Artifact Schemas
# ---------------------------------------------------------------------------

class HeaderItem(BaseModel):
    """Single email header preserving extracted name, value, and order."""

    model_config = ConfigDict(from_attributes=True)

    header_name: str
    header_value: str
    header_order: int | None = None


class UrlItem(BaseModel):
    """URL extracted from email forensic analysis."""

    model_config = ConfigDict(from_attributes=True)

    url: str
    normalized_url: str | None = None
    domain: str | None = None
    scheme: str | None = None
    path: str | None = None
    reputation: str | None = None


class DomainItem(BaseModel):
    """Domain associated with email evidence."""

    model_config = ConfigDict(from_attributes=True)

    domain: str
    registrar: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    reputation: str | None = None


class IpItem(BaseModel):
    """IP address extracted from email headers or infrastructure.

    Note: Geolocation represents approximate infrastructure location,
    not physical attacker location.
    """

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    ip_address: str
    version: int | None = None
    asn: str | None = None
    org: str | None = None
    organization: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    reputation: str | None = None


class AttachmentItem(BaseModel):
    """Attachment forensic metadata (binary contents are never stored or exposed)."""

    model_config = ConfigDict(from_attributes=True)

    file_name: str | None = None
    content_type: str | None = None
    file_size: int | None = None
    sha256: str | None = None
    md5: str | None = None


class EmailWorkspaceItem(BaseModel):
    """Forensic email record within an investigation case.

    Contains observed forensic metadata and extracted indicators.
    Raw body content (plain text / HTML) is strictly excluded.
    """

    model_config = ConfigDict(from_attributes=True)

    email_id: UUID
    message_id: str | None = None
    subject: str | None = None
    sender: str | None = None
    sender_domain: str | None = None
    reply_to: str | None = None
    received_at: datetime | None = None
    analysis_status: str
    raw_file_name: str | None = None
    raw_file_hash: str | None = None
    created_at: datetime
    headers: list[HeaderItem] = Field(default_factory=list)
    urls: list[UrlItem] = Field(default_factory=list)
    domains: list[DomainItem] = Field(default_factory=list)
    ip_addresses: list[IpItem] = Field(default_factory=list)
    attachments: list[AttachmentItem] = Field(default_factory=list)

    @property
    def id(self) -> UUID:
        return self.email_id


# ---------------------------------------------------------------------------
# Threat Intelligence Enrichment Schema
# ---------------------------------------------------------------------------

class ThreatIntelItem(BaseModel):
    """External threat intelligence enrichment record.

    Contains external provider reputation scores and metadata.
    Raw provider API responses (raw_response) and credentials are strictly excluded.
    """

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID | None = None
    indicator_type: str
    indicator_value: str
    provider: str
    status: str
    reputation: str | None = None
    confidence: float | None = None
    malicious_count: int | None = None
    suspicious_count: int | None = None
    harmless_count: int | None = None
    country: str | None = None
    asn: int | str | None = None
    org: str | None = None
    organization: str | None = None
    queried_at: datetime


# ---------------------------------------------------------------------------
# Investigation Audit Trail Schema
# ---------------------------------------------------------------------------

class InvestigationEventItem(BaseModel):
    """Investigation audit trail event."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID | None = None
    event_type: str
    description: str
    actor: str | None = None
    created_at: datetime
    metadata: dict[str, Any] | None = Field(default=None, alias="event_metadata")


# ---------------------------------------------------------------------------
# Investigation Workspace Summary Schema
# ---------------------------------------------------------------------------

class InvestigationSummary(BaseModel):
    """Computed summary statistics for an investigation case."""

    model_config = ConfigDict(from_attributes=True)

    email_count: int = 0
    threat_intel_count: int = 0
    ai_analysis_count: int = 0
    latest_classification: str | None = None
    latest_risk_score: int | None = None
    highest_risk_score: int | None = None


# ---------------------------------------------------------------------------
# Complete Case Workspace Response
# ---------------------------------------------------------------------------

class CaseWorkspaceResponse(BaseModel):
    """Complete investigation case workspace response.

    Combines case metadata, observed forensic evidence across emails,
    external threat intelligence enrichments, AI threat assessments,
    and the chronological investigation event audit trail.
    """

    model_config = ConfigDict(from_attributes=True)

    case_id: UUID
    case_number: str
    title: str
    description: str | None = None
    status: str
    priority: str
    created_at: datetime
    updated_at: datetime
    emails: list[EmailWorkspaceItem] = Field(default_factory=list)
    threat_intelligence: list[ThreatIntelItem] = Field(default_factory=list)
    ai_analyses: list[AIAnalysisResultResponse] = Field(default_factory=list)
    investigation_events: list[InvestigationEventItem] = Field(default_factory=list)
    summary: InvestigationSummary

    @property
    def id(self) -> UUID:
        return self.case_id


# ---------------------------------------------------------------------------
# Case Listing Schemas
# ---------------------------------------------------------------------------

class CaseListItem(BaseModel):
    """Summary item for paginated case listings."""

    model_config = ConfigDict(from_attributes=True)

    case_id: UUID
    case_number: str
    title: str
    description: str | None = None
    status: str
    priority: str
    created_at: datetime
    updated_at: datetime
    email_count: int = 0

    @property
    def id(self) -> UUID:
        return self.case_id


class CaseListResponse(BaseModel):
    """Paginated list of investigation cases."""

    model_config = ConfigDict(from_attributes=True)

    cases: list[CaseListItem] = Field(default_factory=list)
    items: list[CaseListItem] = Field(default_factory=list)
    total: int
    limit: int
    offset: int
