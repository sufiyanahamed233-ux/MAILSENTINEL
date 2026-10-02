from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class ParsedHeader(BaseModel):
    """Extracted email header maintaining original sequence."""

    header_name: str
    header_value: str
    header_order: int


class ParsedURL(BaseModel):
    """Extracted and normalized URL entity."""

    url: str
    normalized_url: str
    domain: str | None = None
    scheme: str | None = None
    path: str | None = None


class ParsedDomain(BaseModel):
    """Extracted domain entity."""

    domain: str


class ParsedIP(BaseModel):
    """Extracted IP infrastructure entity."""

    ip_address: str
    version: int


class ParsedAttachment(BaseModel):
    """Attachment forensic metadata (binary payload not stored)."""

    file_name: str
    content_type: str
    file_size: int
    sha256: str
    md5: str


class ParsedEmailData(BaseModel):
    """Structured internal representation of parsed email forensics."""

    message_id: str | None = None
    subject: str | None = None
    sender: str | None = None
    sender_domain: str | None = None
    reply_to: str | None = None
    received_at: datetime | None = None
    raw_file_name: str
    raw_file_hash: str
    body_plain: str | None = None
    body_html: str | None = None
    headers: list[ParsedHeader] = Field(default_factory=list)
    received_headers: list[str] = Field(default_factory=list)
    urls: list[ParsedURL] = Field(default_factory=list)
    domains: list[ParsedDomain] = Field(default_factory=list)
    ip_addresses: list[ParsedIP] = Field(default_factory=list)
    attachments: list[ParsedAttachment] = Field(default_factory=list)


class EmailAnalysisResponse(BaseModel):
    """Response model for the /api/v1/analyze-email endpoint."""

    model_config = ConfigDict(from_attributes=True)

    case_id: UUID
    case_number: str
    email_id: UUID
    raw_file_name: str
    raw_file_hash: str
    message_id: str | None = None
    subject: str | None = None
    sender: str | None = None
    sender_domain: str | None = None
    reply_to: str | None = None
    received_at: datetime | None = None
    analysis_status: str
    created_at: datetime

    # Summary metrics
    headers_count: int
    urls_count: int
    domains_count: int
    ip_addresses_count: int
    attachments_count: int

    # Forensic artifacts
    urls: list[ParsedURL] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    attachments: list[ParsedAttachment] = Field(default_factory=list)
