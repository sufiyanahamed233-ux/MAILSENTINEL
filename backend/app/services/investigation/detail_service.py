"""Detailed Email Investigation Service for MAILSENTINEL.

Provides read-only retrieval of detailed email forensic evidence, extracted artifacts,
email-specific threat intelligence, and case-level AI analysis results.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.ai_analysis import AIAnalysisResult
from app.models.case import Case
from app.models.email import Attachment, Email, EmailHeader
from app.models.network import Domain, IPAddress, URL
from app.models.threat_intel import ThreatIntelligenceResult
from app.schemas.ai_analysis import AIAnalysisResultResponse
from app.schemas.investigation import (
    AttachmentItem,
    DomainItem,
    HeaderItem,
    IpItem,
    ThreatIntelItem,
    UrlItem,
)
from app.schemas.investigation_detail import EmailDetailResponse
from app.services.investigation.service import CaseNotFoundError


class EmailNotFoundError(Exception):
    """Raised when an email record is not found."""


class EmailNotBelongToCaseError(Exception):
    """Raised when an email does not belong to the specified case."""


def _to_utc_comparable(dt: datetime | None) -> datetime | None:
    """Normalize datetime to timezone-aware UTC for deterministic sorting."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _header_sort_key(header: EmailHeader) -> tuple[int, int, datetime, str]:
    """Deterministic sort key for headers: header_order ASC NULLS LAST, created_at ASC, id ASC."""
    is_null = 1 if header.header_order is None else 0
    order = header.header_order or 0
    created = _to_utc_comparable(header.created_at) or datetime.min.replace(tzinfo=timezone.utc)
    return (is_null, order, created, str(header.id))


def _artifact_sort_key(item: URL | Domain | IPAddress | Attachment) -> tuple[datetime, str]:
    """Deterministic sort key for forensic artifacts: created_at ASC, id ASC."""
    created = _to_utc_comparable(item.created_at) or datetime.min.replace(tzinfo=timezone.utc)
    return (created, str(item.id))


def _ti_sort_key(ti: ThreatIntelligenceResult) -> tuple[datetime, str]:
    """Deterministic sort key for threat intelligence: queried_at ASC, id ASC."""
    queried = _to_utc_comparable(ti.queried_at) or datetime.min.replace(tzinfo=timezone.utc)
    return (queried, str(ti.id))


def _ai_sort_key(ai: AIAnalysisResult) -> tuple[datetime, str]:
    """Deterministic sort key for AI analysis results: created_at ASC, id ASC."""
    created = _to_utc_comparable(ai.created_at) or datetime.min.replace(tzinfo=timezone.utc)
    return (created, str(ai.id))


def _extract_email_observed_indicators(email: Email) -> dict[str, set[str]]:
    """Extract and normalize all observed forensic indicators from an email.

    Derives indicators from:
    - email IP addresses (ip_address)
    - email domains (domain, sender_domain)
    - email URLs (url, normalized_url, extracted domain)
    - email attachments (sha256, md5, raw_file_hash)
    """
    ips: set[str] = set()
    for ip_obj in (email.ip_addresses or []):
        if ip_obj.ip_address:
            ips.add(ip_obj.ip_address.strip())

    domains: set[str] = set()
    for dom_obj in (email.domains or []):
        if dom_obj.domain:
            domains.add(dom_obj.domain.strip().lower())
    if email.sender_domain:
        domains.add(email.sender_domain.strip().lower())

    urls: set[str] = set()
    for url_obj in (email.urls or []):
        if url_obj.url:
            urls.add(url_obj.url.strip())
        if url_obj.normalized_url:
            urls.add(url_obj.normalized_url.strip())
        if url_obj.domain:
            domains.add(url_obj.domain.strip().lower())

    hashes: set[str] = set()
    for att_obj in (email.attachments or []):
        if att_obj.sha256:
            hashes.add(att_obj.sha256.strip().lower())
        if att_obj.md5:
            hashes.add(att_obj.md5.strip().lower())
    if email.raw_file_hash:
        hashes.add(email.raw_file_hash.strip().lower())

    return {
        "ip": ips,
        "domain": domains,
        "url": urls,
        "file_hash": hashes,
    }


def _is_ti_relevant_to_email(ti: ThreatIntelligenceResult, indicators: dict[str, set[str]]) -> bool:
    """Determine whether a ThreatIntelligenceResult corresponds to indicators observed in this email."""
    ti_type = (ti.indicator_type or "").strip().lower()
    ti_val = (ti.indicator_value or "").strip()
    ti_val_lower = ti_val.lower()

    if ti_type in ("ip", "ipv4", "ipv6"):
        return ti_val in indicators["ip"] or ti_val_lower in {ip.lower() for ip in indicators["ip"]}
    elif ti_type == "domain":
        return ti_val_lower in indicators["domain"]
    elif ti_type == "url":
        urls_lower = {u.lower() for u in indicators["url"]}
        return ti_val in indicators["url"] or ti_val_lower in urls_lower
    elif ti_type in ("file_hash", "hash", "sha256", "md5"):
        return ti_val_lower in indicators["file_hash"]
    else:
        # Fallback for generic indicator types: match against any observed indicator value
        all_values_lower = (
            {ip.lower() for ip in indicators["ip"]}
            | indicators["domain"]
            | {u.lower() for u in indicators["url"]}
            | indicators["file_hash"]
        )
        return ti_val_lower in all_values_lower


def get_email_detail(
    db: Session,
    case_id: uuid.UUID,
    email_id: uuid.UUID,
) -> EmailDetailResponse:
    """Retrieve detailed forensic evidence and investigation context for a specific email.

    Validates:
    - Case must exist (raises CaseNotFoundError)
    - Email must exist (raises EmailNotFoundError)
    - Email must belong to the requested case (raises EmailNotBelongToCaseError)

    Threat intelligence filtering:
    - Derives observed indicators from this email's IPs, domains, URLs, and attachments
    - Returns only ThreatIntelligenceResult rows whose indicator corresponds to THIS email
    - Raw provider responses (raw_response) and credentials are strictly excluded

    AI analyses:
    - In the current MAILSENTINEL data model, AIAnalysisResult is scoped to the Case level
      (not individual emails). Therefore, all case-level AI threat assessments for this
      investigation are returned to provide analysts with comprehensive assessment context.
    """
    # 1. Validate that the Case exists and eager-load case-scoped enrichment/analyses
    case_stmt = (
        select(Case)
        .where(Case.id == case_id)
        .options(
            selectinload(Case.threat_intelligence_results),
            selectinload(Case.ai_analysis_results),
        )
    )
    case = db.execute(case_stmt).scalar_one_or_none()
    if case is None:
        raise CaseNotFoundError(f"Case with ID '{case_id}' not found.")

    # 2. Query the requested email and its observed forensic artifacts
    email_stmt = (
        select(Email)
        .where(Email.id == email_id)
        .options(
            selectinload(Email.headers),
            selectinload(Email.urls),
            selectinload(Email.domains),
            selectinload(Email.ip_addresses),
            selectinload(Email.attachments),
        )
    )
    email = db.execute(email_stmt).scalar_one_or_none()
    if email is None:
        raise EmailNotFoundError(f"Email with ID '{email_id}' not found.")

    # 3. Verify case ownership
    if email.case_id != case_id:
        raise EmailNotBelongToCaseError(
            f"Email with ID '{email_id}' does not belong to case '{case_id}'."
        )

    # 4. Map headers in deterministic order
    sorted_headers = sorted(email.headers or [], key=_header_sort_key)
    headers = [
        HeaderItem(
            header_name=h.header_name,
            header_value=h.header_value,
            header_order=h.header_order,
        )
        for h in sorted_headers
    ]

    # 5. Map network URLs in deterministic order
    sorted_urls = sorted(email.urls or [], key=_artifact_sort_key)
    urls = [
        UrlItem(
            url=u.url,
            normalized_url=u.normalized_url,
            domain=u.domain,
            scheme=u.scheme,
            path=u.path,
            reputation=u.reputation,
        )
        for u in sorted_urls
    ]

    # 6. Map domains in deterministic order
    sorted_domains = sorted(email.domains or [], key=_artifact_sort_key)
    domains = [
        DomainItem(
            domain=d.domain,
            registrar=d.registrar,
            first_seen=d.first_seen,
            last_seen=d.last_seen,
            reputation=d.reputation,
        )
        for d in sorted_domains
    ]

    # 7. Map IP infrastructure in deterministic order
    sorted_ips = sorted(email.ip_addresses or [], key=_artifact_sort_key)
    ip_addresses = [
        IpItem(
            ip_address=ip.ip_address,
            version=ip.version,
            asn=ip.asn,
            org=ip.organization,
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

    # 8. Map attachments in deterministic order (metadata only)
    sorted_attachments = sorted(email.attachments or [], key=_artifact_sort_key)
    attachments = [
        AttachmentItem(
            file_name=att.file_name,
            content_type=att.content_type,
            file_size=att.file_size,
            sha256=att.sha256,
            md5=att.md5,
        )
        for att in sorted_attachments
    ]

    # 9. Extract observed indicators from this email and filter threat intelligence results
    observed_indicators = _extract_email_observed_indicators(email)
    raw_case_ti = case.threat_intelligence_results or []
    email_relevant_ti = [
        t for t in raw_case_ti if _is_ti_relevant_to_email(t, observed_indicators)
    ]

    sorted_ti = sorted(email_relevant_ti, key=_ti_sort_key)
    threat_intel_items = [
        ThreatIntelItem(
            id=t.id,
            indicator_type=t.indicator_type,
            indicator_value=t.indicator_value,
            provider=t.provider,
            status=t.status,
            reputation=t.reputation,
            confidence=t.confidence,
            malicious_count=t.malicious_count,
            suspicious_count=t.suspicious_count,
            harmless_count=t.harmless_count,
            country=t.country,
            asn=t.asn,
            org=t.organization,
            organization=t.organization,
            queried_at=t.queried_at,
        )
        for t in sorted_ti
    ]

    # 10. Map case-level AI threat assessments in deterministic order
    # Note: AIAnalysisResult belongs to Case; all case-level assessments are surfaced.
    sorted_ai = sorted(case.ai_analysis_results or [], key=_ai_sort_key)
    ai_analysis_items = [
        AIAnalysisResultResponse.model_validate(a) for a in sorted_ai
    ]

    return EmailDetailResponse(
        id=email.id,
        case_id=email.case_id,
        message_id=email.message_id,
        subject=email.subject,
        sender=email.sender,
        sender_domain=email.sender_domain,
        reply_to=email.reply_to,
        received_at=email.received_at,
        raw_file_name=email.raw_file_name,
        raw_file_hash=email.raw_file_hash,
        analysis_status=email.analysis_status,
        created_at=email.created_at,
        headers=headers,
        urls=urls,
        domains=domains,
        ip_addresses=ip_addresses,
        attachments=attachments,
        threat_intelligence=threat_intel_items,
        ai_analyses=ai_analysis_items,
    )
