"""Phase 5D — Forensic Report Generation Service.

Assembles existing persisted PostgreSQL investigation data into a single,
deterministic, structured forensic report.

Strict separation of concerns:
- Observed forensic evidence (emails and extracted artifacts)
- External ThreatIntelligenceResult enrichment
- AIAnalysisResult conclusions
- Chain-of-custody Evidence and InvestigationEvent audit trail

Security & Safety:
- Excludes raw email body (plain / HTML / raw MIME)
- Excludes attachment binary content
- Excludes external TI raw_response payloads
- Excludes API keys, credentials, and secrets
- Surfaces blockchain fields read-only (no blockchain queries)
- Never calls external AI, threat intel, or blockchain services
- Performs zero database writes (read-only)
- No new database tables
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evidence import Evidence
from app.models.investigation import InvestigationEvent
from app.schemas.evidence import EvidenceItem, InvestigationEventItem
from app.schemas.report import (
    CaseInformationItem,
    CaseReportResponse,
    ExecutiveSummaryItem,
)
from app.services.investigation.service import (
    CaseNotFoundError,
    get_case_workspace,
)


def generate_case_report(
    db: Session,
    case_id: uuid.UUID,
    generated_at: datetime | None = None,
) -> CaseReportResponse:
    """Generate a structured, deterministic forensic report for an investigation case.

    Reuses existing workspace resolution logic from `get_case_workspace` to load
    and validate the case, emails, forensic artifacts, threat intelligence, and AI analyses.
    Loads chain-of-custody Evidence records and sanitized InvestigationEvent audit trail.

    Deterministic for unchanged database state.
    Raises CaseNotFoundError if the case does not exist.
    """
    # 1. Fetch workspace (validates case existence, applies baseline ordering and security exclusions)
    workspace = get_case_workspace(db, case_id)

    # 2. Sort all email forensic sub-artifacts deterministically
    for email in workspace.emails:
        email.urls.sort(key=lambda u: (u.url, u.domain or ""))
        email.domains.sort(key=lambda d: d.domain)
        email.ip_addresses.sort(key=lambda ip: ip.ip_address)
        email.attachments.sort(key=lambda a: (a.file_name or "", a.sha256 or ""))

    # 3. Fetch all chain-of-custody Evidence records (deterministic: collected_at ASC, id ASC)
    evidence_rows = (
        db.execute(
            select(Evidence)
            .where(Evidence.case_id == case_id)
            .order_by(Evidence.collected_at.asc(), Evidence.id.asc())
        )
        .scalars()
        .all()
    )
    evidence_items = [EvidenceItem.model_validate(row) for row in evidence_rows]

    # 4. Fetch all InvestigationEvent audit records (deterministic: created_at ASC, id ASC)
    event_rows = (
        db.execute(
            select(InvestigationEvent)
            .where(InvestigationEvent.case_id == case_id)
            .order_by(InvestigationEvent.created_at.asc(), InvestigationEvent.id.asc())
        )
        .scalars()
        .all()
    )
    audit_event_items = [InvestigationEventItem.model_validate(row) for row in event_rows]

    # 5. Assemble Executive Summary
    ai_analyses = workspace.ai_analyses
    latest_ai = ai_analyses[-1] if ai_analyses else None

    verdict = latest_ai.classification if latest_ai else None
    risk_score = latest_ai.risk_score if latest_ai else None
    confidence = latest_ai.confidence if latest_ai else None
    summary_text = latest_ai.reasoning if latest_ai else None
    key_findings = list(latest_ai.supporting_evidence or []) if latest_ai else []
    attack_techniques = list(latest_ai.attack_techniques or []) if latest_ai else []
    recommended_actions = list(latest_ai.recommended_actions or []) if latest_ai else []

    valid_risk_scores = [a.risk_score for a in ai_analyses if a.risk_score is not None]
    highest_risk_score = max(valid_risk_scores) if valid_risk_scores else None

    executive_summary = ExecutiveSummaryItem(
        verdict=verdict,
        latest_classification=verdict,
        risk_score=risk_score,
        latest_risk_score=risk_score,
        highest_risk_score=highest_risk_score,
        confidence=confidence,
        summary_text=summary_text,
        key_findings=key_findings,
        attack_techniques=attack_techniques,
        recommended_actions=recommended_actions,
        email_count=len(workspace.emails),
        threat_intel_count=len(workspace.threat_intelligence),
        ai_analysis_count=len(ai_analyses),
        evidence_count=len(evidence_items),
        audit_event_count=len(audit_event_items),
    )

    # 6. Assemble Case Information
    case_info = CaseInformationItem(
        case_id=workspace.case_id,
        case_number=workspace.case_number,
        title=workspace.title,
        description=workspace.description,
        status=workspace.status,
        priority=workspace.priority,
        created_at=workspace.created_at,
        updated_at=workspace.updated_at,
    )

    # 7. Deterministic Report ID & Generation Timestamp
    # Derived deterministically from case_id and case lifecycle for state stability
    report_id = uuid.uuid5(case_id, "mailsentinel:forensic-report")
    report_generated_at = generated_at or workspace.updated_at or workspace.created_at or datetime.now(timezone.utc)

    return CaseReportResponse(
        report_id=report_id,
        generated_at=report_generated_at,
        case_information=case_info,
        case_info=case_info,
        executive_summary=executive_summary,
        emails_and_forensic_artifacts=workspace.emails,
        emails=workspace.emails,
        threat_intelligence=workspace.threat_intelligence,
        ai_findings=ai_analyses,
        ai_analyses=ai_analyses,
        evidence_chain_of_custody=evidence_items,
        evidence=evidence_items,
        investigation_audit_events=audit_event_items,
        audit_events=audit_event_items,
    )
