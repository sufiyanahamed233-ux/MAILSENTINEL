"""Deterministic forensic context builder for AI threat analysis.

Loads a case and its associated forensic evidence and threat-intelligence
results from PostgreSQL, then returns a structured, sanitized
``AIAnalysisContext`` suitable for consumption by a future AI provider.

This service is **read-only**.  It does not:
- call any external API
- invoke an AI model
- modify database records
- create AIAnalysisResult rows
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.email import Attachment, Email, EmailHeader
from app.models.network import Domain, IPAddress, URL
from app.models.threat_intel import ThreatIntelligenceResult
from app.schemas.ai_analysis import (
    AIAnalysisContext,
    AIAttachmentEvidence,
    AICaseContext,
    AIDomainEvidence,
    AIEmailContext,
    AIForensicEvidence,
    AIHeaderEvidence,
    AIIPAddressEvidence,
    AIThreatIntelligence,
    AIThreatIntelResult,
    AIURLEvidence,
)


class CaseNotFoundError(Exception):
    """Raised when the requested case does not exist in the database."""

    def __init__(self, case_id: uuid.UUID) -> None:
        self.case_id = case_id
        super().__init__(f"Case with ID '{case_id}' not found.")


# ------------------------------------------------------------------
# Public entry-point
# ------------------------------------------------------------------


def build_ai_context(db: Session, case_id: uuid.UUID) -> AIAnalysisContext:
    """Build a structured AI analysis context for the given case.

    Parameters
    ----------
    db:
        Active SQLAlchemy session (read-only usage).
    case_id:
        UUID of the case to load.

    Returns
    -------
    AIAnalysisContext
        Complete, deterministic, sanitized context ready for AI inference.

    Raises
    ------
    CaseNotFoundError
        If no case with the given *case_id* exists.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if case is None:
        raise CaseNotFoundError(case_id)

    case_context = _build_case_context(case)
    forensic_evidence = _build_forensic_evidence(case)
    threat_intelligence = _build_threat_intelligence(db, case_id)

    return AIAnalysisContext(
        case=case_context,
        forensic_evidence=forensic_evidence,
        threat_intelligence=threat_intelligence,
    )


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _build_case_context(case: Case) -> AICaseContext:
    return AICaseContext(
        case_id=case.id,
        case_number=case.case_number,
        case_title=case.title,
        case_status=case.status,
        case_priority=case.priority,
    )


def _build_forensic_evidence(case: Case) -> AIForensicEvidence:
    """Gather forensic artefacts for every email in the case.

    Emails are ordered by ``created_at`` for deterministic output.
    """
    # Deterministic ordering: earliest email first
    emails_sorted = sorted(case.emails, key=lambda e: e.created_at)

    email_contexts: list[AIEmailContext] = []
    for email in emails_sorted:
        email_contexts.append(_build_email_context(email))

    return AIForensicEvidence(emails=email_contexts)


def _build_email_context(email: Email) -> AIEmailContext:
    return AIEmailContext(
        email_id=email.id,
        message_id=email.message_id,
        subject=email.subject,
        sender=email.sender,
        sender_domain=email.sender_domain,
        reply_to=email.reply_to,
        received_at=email.received_at,
        analysis_status=email.analysis_status,
        raw_file_name=email.raw_file_name,
        raw_file_hash=email.raw_file_hash,
        headers=_build_headers(email.headers),
        urls=_build_urls(email.urls),
        domains=_build_domains(email.domains),
        ip_addresses=_build_ip_addresses(email.ip_addresses),
        attachments=_build_attachments(email.attachments),
    )


def _build_headers(headers: list[EmailHeader]) -> list[AIHeaderEvidence]:
    """Preserve header ordering via ``header_order`` (nulls last)."""
    sorted_headers = sorted(
        headers,
        key=lambda h: (h.header_order is None, h.header_order or 0),
    )
    return [
        AIHeaderEvidence(
            header_name=h.header_name,
            header_value=h.header_value,
            header_order=h.header_order,
        )
        for h in sorted_headers
    ]


def _build_urls(urls: list[URL]) -> list[AIURLEvidence]:
    sorted_urls = sorted(urls, key=lambda u: u.created_at)
    return [
        AIURLEvidence(
            url=u.url,
            normalized_url=u.normalized_url,
            domain=u.domain,
            scheme=u.scheme,
            path=u.path,
            reputation=u.reputation,
        )
        for u in sorted_urls
    ]


def _build_domains(domains: list[Domain]) -> list[AIDomainEvidence]:
    sorted_domains = sorted(domains, key=lambda d: d.created_at)
    return [
        AIDomainEvidence(
            domain=d.domain,
            registrar=d.registrar,
            first_seen=d.first_seen,
            last_seen=d.last_seen,
            reputation=d.reputation,
        )
        for d in sorted_domains
    ]


def _build_ip_addresses(ips: list[IPAddress]) -> list[AIIPAddressEvidence]:
    sorted_ips = sorted(ips, key=lambda ip: ip.created_at)
    return [
        AIIPAddressEvidence(
            ip_address=ip.ip_address,
            version=ip.version,
            asn=ip.asn,
            organization=ip.organization,
            country=ip.country,
            region=ip.region,
            city=ip.city,
            latitude=ip.latitude,
            longitude=ip.longitude,
            reputation=ip.reputation,
        )
        for ip in sorted_ips
    ]


def _build_attachments(attachments: list[Attachment]) -> list[AIAttachmentEvidence]:
    sorted_attachments = sorted(attachments, key=lambda a: a.created_at)
    return [
        AIAttachmentEvidence(
            file_name=a.file_name,
            content_type=a.content_type,
            file_size=a.file_size,
            sha256=a.sha256,
            md5=a.md5,
        )
        for a in sorted_attachments
    ]


def _build_threat_intelligence(
    db: Session, case_id: uuid.UUID
) -> AIThreatIntelligence:
    """Load threat-intelligence results ordered by ``created_at``.

    ``raw_response`` is intentionally excluded from the AI context.
    """
    records = (
        db.query(ThreatIntelligenceResult)
        .filter(ThreatIntelligenceResult.case_id == case_id)
        .order_by(ThreatIntelligenceResult.created_at.asc())
        .all()
    )

    results = [
        AIThreatIntelResult(
            indicator_type=r.indicator_type,
            indicator_value=r.indicator_value,
            provider=r.provider,
            queried_at=r.queried_at,
            status=r.status,
            reputation=r.reputation,
            confidence=r.confidence,
            malicious_count=r.malicious_count,
            suspicious_count=r.suspicious_count,
            harmless_count=r.harmless_count,
            country=r.country,
            asn=r.asn,
            organization=r.organization,
            error_message=r.error_message,
        )
        for r in records
    ]

    return AIThreatIntelligence(results=results)
