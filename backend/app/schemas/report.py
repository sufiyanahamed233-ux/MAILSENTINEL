"""Pydantic v2 schemas for Phase 5D — Structured Forensic Report Generation.

Defines schemas for the complete, deterministic forensic investigation report.
Strictly preserves separation across the 7 report sections:
1. Case Information
2. Executive Summary
3. Emails and Forensic Artifacts
4. Threat Intelligence (external enrichments)
5. AI Findings
6. Evidence / Chain-of-Custody
7. Investigation Audit Events

Security rules:
- No raw email body (body_plain, body_html, raw MIME)
- No attachment binary data
- No threat intelligence raw_response
- No credentials, secrets, or API keys
- Blockchain fields exposed read-only without blockchain queries
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.ai_analysis import AIAnalysisResultResponse
from app.schemas.evidence import EvidenceItem, InvestigationEventItem
from app.schemas.investigation import (
    AttachmentItem,
    DomainItem,
    EmailWorkspaceItem,
    HeaderItem,
    IpItem,
    ThreatIntelItem,
    UrlItem,
)


class CaseInformationItem(BaseModel):
    """Forensic report section 1: Case identification and lifecycle metadata."""

    model_config = ConfigDict(from_attributes=True)

    case_id: UUID = Field(..., description="Unique case identifier")
    case_number: str = Field(..., description="Human-readable case tracking number")
    title: str = Field(..., description="Investigation case title")
    description: str | None = Field(None, description="Optional case description")
    status: str = Field(..., description="Case status (e.g. open, in_progress, closed)")
    priority: str = Field(..., description="Case priority (e.g. low, medium, high, critical)")
    created_at: datetime = Field(..., description="Case creation timestamp")
    updated_at: datetime = Field(..., description="Case last-updated timestamp")

    @property
    def id(self) -> UUID:
        return self.case_id


# Alias for flexible importing
CaseInformation = CaseInformationItem


class ExecutiveSummaryItem(BaseModel):
    """Forensic report section 2: Executive summary and threat assessment."""

    model_config = ConfigDict(from_attributes=True)

    verdict: str | None = Field(None, description="Overall threat classification verdict")
    latest_classification: str | None = Field(None, description="Alias for verdict")
    risk_score: int | None = Field(None, ge=0, le=100, description="Latest assessed risk score")
    latest_risk_score: int | None = Field(None, ge=0, le=100, description="Alias for risk_score")
    highest_risk_score: int | None = Field(None, ge=0, le=100, description="Highest risk score across all analyses")
    confidence: float | None = Field(None, ge=0.0, le=1.0, description="Confidence in assessment")
    summary_text: str | None = Field(None, description="Executive summary narrative or analytical reasoning")
    key_findings: list[str] = Field(default_factory=list, description="Key observed forensic findings supporting verdict")
    attack_techniques: list[str] = Field(default_factory=list, description="Identified attack vectors and techniques")
    recommended_actions: list[str] = Field(default_factory=list, description="Remediation and containment recommendations")

    # Quantified forensic indicators
    email_count: int = Field(0, ge=0, description="Total emails in case")
    threat_intel_count: int = Field(0, ge=0, description="Total external threat intelligence results")
    ai_analysis_count: int = Field(0, ge=0, description="Total AI threat assessments performed")
    evidence_count: int = Field(0, ge=0, description="Total chain-of-custody evidence items")
    audit_event_count: int = Field(0, ge=0, description="Total investigation audit events")

    @property
    def total_emails(self) -> int:
        return self.email_count

    @property
    def total_threat_intel(self) -> int:
        return self.threat_intel_count

    @property
    def total_ai_analyses(self) -> int:
        return self.ai_analysis_count

    @property
    def total_evidence(self) -> int:
        return self.evidence_count

    @property
    def total_audit_events(self) -> int:
        return self.audit_event_count


ExecutiveSummary = ExecutiveSummaryItem
ReportEmailItem = EmailWorkspaceItem


class CaseReportResponse(BaseModel):
    """Complete, structured forensic investigation report response.

    Deterministically assembles existing PostgreSQL investigation data across
    7 strict forensic sections with full separation of concerns.
    """

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    report_id: UUID = Field(..., description="Deterministic report identifier")
    generated_at: datetime = Field(..., description="Timestamp of report generation")

    # Section 1: Case Information
    case_information: CaseInformationItem = Field(..., description="Case identification and metadata")
    case_info: CaseInformationItem | None = Field(None, description="Convenience alias for case_information")

    # Section 2: Executive Summary
    executive_summary: ExecutiveSummaryItem = Field(..., description="Executive summary and risk assessment")

    # Section 3: Emails and Forensic Artifacts
    emails_and_forensic_artifacts: list[EmailWorkspaceItem] = Field(
        default_factory=list, description="Observed emails with extracted forensic artifacts"
    )
    emails: list[EmailWorkspaceItem] = Field(
        default_factory=list, description="Convenience alias for emails_and_forensic_artifacts"
    )

    # Section 4: Threat Intelligence
    threat_intelligence: list[ThreatIntelItem] = Field(
        default_factory=list, description="External threat intelligence enrichment records (raw_response excluded)"
    )

    # Section 5: AI Findings
    ai_findings: list[AIAnalysisResultResponse] = Field(
        default_factory=list, description="AI threat assessment conclusions"
    )
    ai_analyses: list[AIAnalysisResultResponse] = Field(
        default_factory=list, description="Convenience alias for ai_findings"
    )

    # Section 6: Evidence / Chain-of-Custody
    evidence_chain_of_custody: list[EvidenceItem] = Field(
        default_factory=list, description="Chain-of-custody evidence integrity records"
    )
    evidence: list[EvidenceItem] = Field(
        default_factory=list, description="Convenience alias for evidence_chain_of_custody"
    )

    # Section 7: Investigation Audit Events
    investigation_audit_events: list[InvestigationEventItem] = Field(
        default_factory=list, description="Sanitized chronological investigation audit trail"
    )
    audit_events: list[InvestigationEventItem] = Field(
        default_factory=list, description="Convenience alias for investigation_audit_events"
    )

    @model_validator(mode="before")
    @classmethod
    def sync_convenience_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            c_info = data.get("case_information") or data.get("case_info")
            if c_info is not None:
                data["case_information"] = c_info
                data["case_info"] = c_info

            em = (
                data.get("emails_and_forensic_artifacts")
                if "emails_and_forensic_artifacts" in data
                else data.get("emails", [])
            )
            data["emails_and_forensic_artifacts"] = em
            data["emails"] = em

            ai = data.get("ai_findings") if "ai_findings" in data else data.get("ai_analyses", [])
            data["ai_findings"] = ai
            data["ai_analyses"] = ai

            ev = (
                data.get("evidence_chain_of_custody")
                if "evidence_chain_of_custody" in data
                else data.get("evidence", [])
            )
            data["evidence_chain_of_custody"] = ev
            data["evidence"] = ev

            ae = (
                data.get("investigation_audit_events")
                if "investigation_audit_events" in data
                else data.get("audit_events", [])
            )
            data["investigation_audit_events"] = ae
            data["audit_events"] = ae
        return data


ForensicReportResponse = CaseReportResponse
