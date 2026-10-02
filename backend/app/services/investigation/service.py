"""Investigation Service Layer for MAILSENTINEL.

Handles assembling complete investigation case workspaces and paginated case listings
from PostgreSQL data. Ensures strict separation of concerns across forensic evidence,
external threat intelligence, and AI analysis conclusions.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.ai_analysis import AIAnalysisResult
from app.models.case import Case
from app.models.email import Attachment, Email, EmailHeader
from app.models.investigation import InvestigationEvent
from app.models.network import Domain, IPAddress, URL
from app.models.threat_intel import ThreatIntelligenceResult
from app.schemas.ai_analysis import AIAnalysisResultResponse
from app.schemas.investigation import (
    AttachmentItem,
    CaseListItem,
    CaseListResponse,
    CaseWorkspaceResponse,
    DomainItem,
    EmailWorkspaceItem,
    HeaderItem,
    InvestigationEventItem,
    InvestigationSummary,
    IpItem,
    ThreatIntelItem,
    UrlItem,
)


class CaseNotFoundError(Exception):
    """Raised when an investigation case is not found."""


def _to_utc_comparable(dt: datetime | None) -> datetime | None:
    """Normalize datetime to timezone-aware UTC for safe sorting."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _email_sort_key(email: Email) -> tuple[int, datetime | None, datetime, str]:
    """Sort key: received_at ASC NULLS LAST, then created_at ASC, then id."""
    is_null = 1 if email.received_at is None else 0
    rec = _to_utc_comparable(email.received_at)
    created = _to_utc_comparable(email.created_at) or datetime.min.replace(tzinfo=timezone.utc)
    return (is_null, rec, created, str(email.id))


def _header_sort_key(header: EmailHeader) -> tuple[int, int, datetime, str]:
    """Sort key: header_order ASC NULLS LAST, then created_at ASC, then id."""
    is_null = 1 if header.header_order is None else 0
    order = header.header_order or 0
    created = _to_utc_comparable(header.created_at) or datetime.min.replace(tzinfo=timezone.utc)
    return (is_null, order, created, str(header.id))


def _ai_sort_key(ai: AIAnalysisResult) -> tuple[datetime, str]:
    """Deterministic chronological order: created_at ASC, then id."""
    created = _to_utc_comparable(ai.created_at) or datetime.min.replace(tzinfo=timezone.utc)
    return (created, str(ai.id))


def _event_sort_key(ev: InvestigationEvent) -> tuple[datetime, str]:
    """Deterministic chronological order: created_at ASC, then id."""
    created = _to_utc_comparable(ev.created_at) or datetime.min.replace(tzinfo=timezone.utc)
    return (created, str(ev.id))


def get_case_workspace(db: Session, case_id: uuid.UUID) -> CaseWorkspaceResponse:
    """Assemble a complete investigation case workspace from PostgreSQL.

    Strictly separates:
    - Observed forensic evidence (emails and extracted artifacts)
    - External threat intelligence enrichments (raw_response excluded)
    - AI threat assessments (chronologically ordered)
    - Chronological investigation event audit trail

    Computes summary metrics in the service layer.
    """
    stmt = (
        select(Case)
        .where(Case.id == case_id)
        .options(
            selectinload(Case.emails).selectinload(Email.headers),
            selectinload(Case.emails).selectinload(Email.urls),
            selectinload(Case.emails).selectinload(Email.domains),
            selectinload(Case.emails).selectinload(Email.ip_addresses),
            selectinload(Case.emails).selectinload(Email.attachments),
            selectinload(Case.threat_intelligence_results),
            selectinload(Case.ai_analysis_results),
            selectinload(Case.investigation_events),
        )
    )
    case = db.execute(stmt).scalar_one_or_none()

    if case is None:
        raise CaseNotFoundError(f"Case with ID {case_id} not found.")

    # 1. Observed forensic emails (received_at ASC NULLS LAST, created_at ASC)
    raw_emails = case.emails or []
    sorted_emails = sorted(raw_emails, key=_email_sort_key)

    email_items: list[EmailWorkspaceItem] = []
    for email in sorted_emails:
        sorted_headers = sorted(email.headers or [], key=_header_sort_key)
        headers = [
            HeaderItem(
                header_name=h.header_name,
                header_value=h.header_value,
                header_order=h.header_order,
            )
            for h in sorted_headers
        ]

        urls = [
            UrlItem(
                url=u.url,
                normalized_url=u.normalized_url,
                domain=u.domain,
                scheme=u.scheme,
                path=u.path,
                reputation=u.reputation,
            )
            for u in (email.urls or [])
        ]

        domains = [
            DomainItem(
                domain=d.domain,
                registrar=d.registrar,
                first_seen=d.first_seen,
                last_seen=d.last_seen,
                reputation=d.reputation,
            )
            for d in (email.domains or [])
        ]

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
            for ip in (email.ip_addresses or [])
        ]

        attachments = [
            AttachmentItem(
                file_name=att.file_name,
                content_type=att.content_type,
                file_size=att.file_size,
                sha256=att.sha256,
                md5=att.md5,
            )
            for att in (email.attachments or [])
        ]

        email_items.append(
            EmailWorkspaceItem(
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
                created_at=email.created_at,
                headers=headers,
                urls=urls,
                domains=domains,
                ip_addresses=ip_addresses,
                attachments=attachments,
            )
        )

    # 2. Threat intelligence enrichments (raw_response deliberately excluded)
    raw_threat_intel = case.threat_intelligence_results or []
    sorted_threat_intel = sorted(
        raw_threat_intel,
        key=lambda t: (
            _to_utc_comparable(t.queried_at) or datetime.min.replace(tzinfo=timezone.utc),
            str(t.id),
        ),
    )
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
        for t in sorted_threat_intel
    ]

    # 3. AI analyses (deterministic chronological order: created_at ASC, id ASC)
    raw_ai = case.ai_analysis_results or []
    sorted_ai = sorted(raw_ai, key=_ai_sort_key)
    ai_items = [AIAnalysisResultResponse.model_validate(a) for a in sorted_ai]

    # 4. Investigation events audit trail (deterministic chronological order)
    raw_events = case.investigation_events or []
    sorted_events = sorted(raw_events, key=_event_sort_key)
    event_items = [
        InvestigationEventItem(
            id=ev.id,
            event_type=ev.event_type,
            description=ev.description,
            actor=ev.actor,
            created_at=ev.created_at,
            metadata=ev.event_metadata,
            event_metadata=ev.event_metadata,
        )
        for ev in sorted_events
    ]

    # 5. Service-layer computed summary
    latest_classification = sorted_ai[-1].classification if sorted_ai else None
    latest_risk_score = sorted_ai[-1].risk_score if sorted_ai else None
    valid_risk_scores = [a.risk_score for a in sorted_ai if a.risk_score is not None]
    highest_risk_score = max(valid_risk_scores) if valid_risk_scores else None

    summary = InvestigationSummary(
        email_count=len(email_items),
        threat_intel_count=len(threat_intel_items),
        ai_analysis_count=len(ai_items),
        latest_classification=latest_classification,
        latest_risk_score=latest_risk_score,
        highest_risk_score=highest_risk_score,
    )

    return CaseWorkspaceResponse(
        case_id=case.id,
        case_number=case.case_number,
        title=case.title,
        description=case.description,
        status=case.status,
        priority=case.priority,
        created_at=case.created_at,
        updated_at=case.updated_at,
        emails=email_items,
        threat_intelligence=threat_intel_items,
        ai_analyses=ai_items,
        investigation_events=event_items,
        summary=summary,
    )


def list_cases(db: Session, limit: int = 20, offset: int = 0) -> CaseListResponse:
    """Retrieve a paginated list of investigation cases ordered newest first."""
    safe_limit = max(1, min(limit, 100))
    safe_offset = max(0, offset)

    total = db.scalar(select(func.count()).select_from(Case)) or 0

    stmt = (
        select(Case)
        .options(selectinload(Case.emails))
        .order_by(Case.created_at.desc(), Case.id.desc())
        .limit(safe_limit)
        .offset(safe_offset)
    )
    cases = db.execute(stmt).scalars().all()

    items = [
        CaseListItem(
            case_id=c.id,
            case_number=c.case_number,
            title=c.title,
            description=c.description,
            status=c.status,
            priority=c.priority,
            created_at=c.created_at,
            updated_at=c.updated_at,
            email_count=len(c.emails) if c.emails else 0,
        )
        for c in cases
    ]

    return CaseListResponse(
        cases=items,
        items=items,
        total=total,
        limit=safe_limit,
        offset=safe_offset,
    )
