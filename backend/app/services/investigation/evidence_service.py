"""Phase 5C — Evidence, Events, and Indicators read-only service.

All three functions follow the same contract:
1. Validate the case exists; raise CaseNotFoundError otherwise.
2. Query the target collection with deterministic ordering.
3. Apply pagination (limit/offset) at the database level.
4. Map ORM rows to Pydantic response schemas (no model mutation).

Ordering guarantees
-------------------
evidence   : collected_at ASC, id ASC
events     : created_at  ASC, id ASC
indicators : created_at  ASC, id ASC
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.indicator import ThreatIndicator
from app.models.investigation import InvestigationEvent
from app.schemas.evidence import (
    EvidenceItem,
    EvidenceListResponse,
    EventListResponse,
    IndicatorListResponse,
    InvestigationEventItem,
    ThreatIndicatorItem,
)
from app.services.investigation.service import CaseNotFoundError


def _case_exists(db: Session, case_id: uuid.UUID) -> None:
    """Raise CaseNotFoundError if no case row exists for case_id."""
    exists = db.scalar(select(func.count()).select_from(Case).where(Case.id == case_id))
    if not exists:
        raise CaseNotFoundError(f"Case with ID '{case_id}' not found.")


def _safe_limit(limit: int) -> int:
    return max(1, min(limit, 100))


def _safe_offset(offset: int) -> int:
    return max(0, offset)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def get_case_evidence(
    db: Session,
    case_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
) -> EvidenceListResponse:
    """Return paginated chain-of-custody evidence records for a case.

    Ordered deterministically by collected_at ASC, id ASC.
    Raises CaseNotFoundError if the case does not exist.
    """
    _case_exists(db, case_id)

    safe_limit = _safe_limit(limit)
    safe_offset = _safe_offset(offset)

    total: int = (
        db.scalar(
            select(func.count())
            .select_from(Evidence)
            .where(Evidence.case_id == case_id)
        )
        or 0
    )

    rows = (
        db.execute(
            select(Evidence)
            .where(Evidence.case_id == case_id)
            .order_by(Evidence.collected_at.asc(), Evidence.id.asc())
            .limit(safe_limit)
            .offset(safe_offset)
        )
        .scalars()
        .all()
    )

    items = [EvidenceItem.model_validate(row) for row in rows]

    return EvidenceListResponse(
        case_id=case_id,
        items=items,
        total=total,
        limit=safe_limit,
        offset=safe_offset,
    )


# ---------------------------------------------------------------------------
# Investigation Events
# ---------------------------------------------------------------------------


def get_case_events(
    db: Session,
    case_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
) -> EventListResponse:
    """Return paginated, sanitized audit-trail events for a case.

    Ordered deterministically by created_at ASC, id ASC.
    Raises CaseNotFoundError if the case does not exist.

    Event metadata is sanitized by InvestigationEventItem to expose only
    allowlisted keys (credentials and raw responses are excluded).
    """
    _case_exists(db, case_id)

    safe_limit = _safe_limit(limit)
    safe_offset = _safe_offset(offset)

    total: int = (
        db.scalar(
            select(func.count())
            .select_from(InvestigationEvent)
            .where(InvestigationEvent.case_id == case_id)
        )
        or 0
    )

    rows = (
        db.execute(
            select(InvestigationEvent)
            .where(InvestigationEvent.case_id == case_id)
            .order_by(InvestigationEvent.created_at.asc(), InvestigationEvent.id.asc())
            .limit(safe_limit)
            .offset(safe_offset)
        )
        .scalars()
        .all()
    )

    items = [InvestigationEventItem.model_validate(row) for row in rows]

    return EventListResponse(
        case_id=case_id,
        items=items,
        total=total,
        limit=safe_limit,
        offset=safe_offset,
    )


# ---------------------------------------------------------------------------
# Threat Indicators
# ---------------------------------------------------------------------------


def get_case_indicators(
    db: Session,
    case_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
) -> IndicatorListResponse:
    """Return paginated normalized forensic threat indicators for a case.

    These are internally derived indicators (ThreatIndicator), distinct from
    external enrichment results (ThreatIntelligenceResult).

    Ordered deterministically by created_at ASC, id ASC.
    Raises CaseNotFoundError if the case does not exist.
    """
    _case_exists(db, case_id)

    safe_limit = _safe_limit(limit)
    safe_offset = _safe_offset(offset)

    total: int = (
        db.scalar(
            select(func.count())
            .select_from(ThreatIndicator)
            .where(ThreatIndicator.case_id == case_id)
        )
        or 0
    )

    rows = (
        db.execute(
            select(ThreatIndicator)
            .where(ThreatIndicator.case_id == case_id)
            .order_by(ThreatIndicator.created_at.asc(), ThreatIndicator.id.asc())
            .limit(safe_limit)
            .offset(safe_offset)
        )
        .scalars()
        .all()
    )

    items = [ThreatIndicatorItem.model_validate(row) for row in rows]

    return IndicatorListResponse(
        case_id=case_id,
        items=items,
        total=total,
        limit=safe_limit,
        offset=safe_offset,
    )
