"""Pydantic v2 schema for detailed email forensic evidence and investigation.

Defines the structured EmailDetailResponse returned by:
GET /api/v1/cases/{case_id}/emails/{email_id}

Separation of concerns is strictly preserved:
- Observed forensic metadata and artifacts (headers, URLs, domains, IPs, attachments)
- External threat intelligence results filtered strictly to indicators observed in this email
- AI threat assessments (case-scoped in current data model)
- Raw email body / plain text / HTML / MIME content and attachment binaries are never included.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.ai_analysis import AIAnalysisResultResponse
from app.schemas.investigation import (
    AttachmentItem,
    DomainItem,
    HeaderItem,
    IpItem,
    ThreatIntelItem,
    UrlItem,
)


class EmailDetailResponse(BaseModel):
    """Detailed forensic investigation response for an email within a case.

    Includes extracted headers, network artifacts, attachments metadata,
    threat intelligence results filtered strictly to indicators observed in this email,
    and case-level AI threat analysis assessments.
    """

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    # 1. Email metadata
    id: UUID
    case_id: UUID
    message_id: str | None = None
    subject: str | None = None
    sender: str | None = None
    sender_domain: str | None = None
    reply_to: str | None = None
    received_at: datetime | None = None
    raw_file_name: str | None = None
    raw_file_hash: str | None = None
    analysis_status: str
    created_at: datetime

    # 2. Headers (preserving extraction order)
    headers: list[HeaderItem] = Field(default_factory=list)

    # 3. URLs
    urls: list[UrlItem] = Field(default_factory=list)

    # 4. Domains
    domains: list[DomainItem] = Field(default_factory=list)

    # 5. IP infrastructure
    # Geolocation represents approximate network location, NOT exact physical location.
    ip_addresses: list[IpItem] = Field(default_factory=list)

    # 6. Attachments (metadata only - binary contents are never exposed)
    attachments: list[AttachmentItem] = Field(default_factory=list)

    # 7. Threat Intelligence (filtered strictly to indicators observed in this email; raw_response excluded)
    threat_intelligence: list[ThreatIntelItem] = Field(
        default_factory=list,
        description="External threat intelligence results matching indicators observed in this email.",
    )

    # 8. AI analyses
    # Note: In the current data model, AIAnalysisResult is scoped to the Case level (not individual emails).
    # Therefore, all case-level AI threat assessment conclusions for this investigation are returned here.
    ai_analyses: list[AIAnalysisResultResponse] = Field(
        default_factory=list,
        description="Case-level AI threat assessment conclusions for this investigation.",
    )

    @property
    def email_id(self) -> UUID:
        """Convenience property for consumers using email_id naming."""
        return self.id
