"""Pydantic v2 schemas for AI threat-analysis context.

These schemas define the structured, sanitized context that the future AI
analysis engine will receive.  The context is constructed from observed
forensic evidence and external threat-intelligence results — it never
contains AI conclusions, raw email bodies, attachment binaries, API keys,
or raw provider API responses.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# ------------------------------------------------------------------
# Case context
# ------------------------------------------------------------------

class AICaseContext(BaseModel):
    """Top-level case metadata."""

    model_config = ConfigDict(from_attributes=True)

    case_id: UUID
    case_number: str
    case_title: str
    case_status: str
    case_priority: str


# ------------------------------------------------------------------
# Forensic evidence: email-level artefacts
# ------------------------------------------------------------------

class AIHeaderEvidence(BaseModel):
    """Single email header preserving original ordering."""

    model_config = ConfigDict(from_attributes=True)

    header_name: str
    header_value: str
    header_order: int | None = None


class AIURLEvidence(BaseModel):
    """URL extracted from an email."""

    model_config = ConfigDict(from_attributes=True)

    url: str
    normalized_url: str | None = None
    domain: str | None = None
    scheme: str | None = None
    path: str | None = None
    reputation: str | None = None


class AIDomainEvidence(BaseModel):
    """Domain associated with an email."""

    model_config = ConfigDict(from_attributes=True)

    domain: str
    registrar: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    reputation: str | None = None


class AIIPAddressEvidence(BaseModel):
    """IP address extracted from email headers / infrastructure.

    Note:
        Geolocation fields represent approximate network/infrastructure
        geolocation, NOT exact physical attacker location.
    """

    model_config = ConfigDict(from_attributes=True)

    ip_address: str
    version: int | None = None
    asn: str | None = None
    organization: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    reputation: str | None = None


class AIAttachmentEvidence(BaseModel):
    """Attachment forensic metadata (binary content is never included)."""

    model_config = ConfigDict(from_attributes=True)

    file_name: str | None = None
    content_type: str | None = None
    file_size: int | None = None
    sha256: str | None = None
    md5: str | None = None


class AIEmailContext(BaseModel):
    """Structured forensic evidence for a single email.

    Raw email body / HTML body are intentionally excluded.
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

    headers: list[AIHeaderEvidence] = Field(default_factory=list)
    urls: list[AIURLEvidence] = Field(default_factory=list)
    domains: list[AIDomainEvidence] = Field(default_factory=list)
    ip_addresses: list[AIIPAddressEvidence] = Field(default_factory=list)
    attachments: list[AIAttachmentEvidence] = Field(default_factory=list)


# ------------------------------------------------------------------
# Forensic evidence aggregate
# ------------------------------------------------------------------

class AIForensicEvidence(BaseModel):
    """All observed forensic evidence for the case, grouped by email."""

    emails: list[AIEmailContext] = Field(default_factory=list)


# ------------------------------------------------------------------
# Threat intelligence
# ------------------------------------------------------------------

class AIThreatIntelResult(BaseModel):
    """Normalized external threat-intelligence enrichment record.

    The ``raw_response`` field from the database is intentionally excluded
    to avoid leaking unstable provider-specific payloads, PII, or large
    structures into the AI context.
    """

    model_config = ConfigDict(from_attributes=True)

    indicator_type: str
    indicator_value: str
    provider: str
    queried_at: datetime
    status: str
    reputation: str | None = None
    confidence: float | None = None
    malicious_count: int | None = None
    suspicious_count: int | None = None
    harmless_count: int | None = None
    country: str | None = None
    asn: int | None = None
    organization: str | None = None
    error_message: str | None = None


class AIThreatIntelligence(BaseModel):
    """Container for all threat-intelligence results associated with the case."""

    results: list[AIThreatIntelResult] = Field(default_factory=list)


# ------------------------------------------------------------------
# Top-level AI analysis context
# ------------------------------------------------------------------

class AIAnalysisContext(BaseModel):
    """Complete structured context assembled for AI threat analysis.

    Maintains clear separation between:
    - case metadata
    - observed forensic evidence
    - external threat intelligence

    AI conclusions are never included in this context.
    """

    case: AICaseContext
    forensic_evidence: AIForensicEvidence
    threat_intelligence: AIThreatIntelligence


# ------------------------------------------------------------------
# AI Threat Analysis Output Models
# ------------------------------------------------------------------

class AIThreatIndicator(BaseModel):
    """Specific threat indicator identified during AI threat analysis."""

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    indicator_type: str = Field(
        ...,
        description="Type of indicator (e.g. 'header', 'url', 'domain', 'ip', 'attachment', 'behavior').",
    )
    indicator_value: str = Field(
        ...,
        description="Observed forensic value or artefact matching the indicator.",
    )
    threat_type: str = Field(
        default="unknown",
        description="Classification of threat (e.g. 'phishing', 'spoofing', 'malware', 'credential_harvesting', 'anomaly').",
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        default="medium",
        description="Assessed severity level of the indicator.",
    )
    description: str = Field(
        ...,
        description="Detailed explanation of the threat posed by this indicator.",
    )


class AIThreatAssessment(BaseModel):
    """Structured threat-analysis assessment produced by an AI provider.

    Adheres strictly to the schema required for downstream persistence
    into the ``ai_analysis_results`` database table.
    """

    model_config = ConfigDict(from_attributes=True, extra="ignore")

    classification: Literal["clean", "suspicious", "malicious", "unknown"] = Field(
        ...,
        description="Overall threat classification: clean, suspicious, malicious, or unknown.",
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Calculated overall risk score from 0 (benign) to 100 (critical danger).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence level in the assessment from 0.0 (no confidence) to 1.0 (certain).",
    )
    threat_indicators: list[AIThreatIndicator] = Field(
        default_factory=list,
        description="Detailed list of specific threat indicators detected in the evidence.",
    )
    supporting_evidence: list[str] = Field(
        default_factory=list,
        description="Key observed forensic evidence points directly supporting the classification.",
    )
    attack_techniques: list[str] = Field(
        default_factory=list,
        description="Identified attack techniques, vectors, or MITRE ATT&CK patterns.",
    )
    reasoning: str = Field(
        ...,
        description="Analytical rationale and justification explaining the assessment.",
    )
    recommended_actions: list[str] = Field(
        default_factory=list,
        description="Actionable remediation, containment, or follow-up recommendations for analysts.",
    )
