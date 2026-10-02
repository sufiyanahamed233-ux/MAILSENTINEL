"""Tests for Phase 5D — Structured Forensic Report Generation.

Covers all required areas:
1.  Valid report generation and schema compliance (Service & API)
2.  Unknown case raises CaseNotFoundError (Service) & 404 Not Found (API)
3.  Multiple emails support and deterministic ordering (received_at ASC NULLS LAST, created_at ASC)
4.  Empty sections handled gracefully (case with no emails, TI, AI, evidence, or events)
5.  Deterministic ordering across all sections (emails, artifacts, TI, AI, evidence, events)
6.  Executive summary synthesis from AI findings & case statistics
7.  Strict separation: observed artifacts vs external TI vs AI findings vs Evidence/events
8.  Evidence chain-of-custody fields & read-only blockchain metadata
9.  Investigation audit events with safe metadata key filtering
10. Sensitive data exclusion: no body_plain, body_html, raw MIME, binaries, raw_response, API keys
11. Read-only verification: no database modifications on report generation
12. Pydantic v2 response validation & JSON serialization
13. Full DB integration: complex case matches persisted PostgreSQL data exactly
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db.session import SessionLocal
from app.main import app
from app.models.ai_analysis import AIAnalysisResult
from app.models.case import Case
from app.models.email import Attachment, Email, EmailHeader
from app.models.evidence import Evidence
from app.models.investigation import InvestigationEvent
from app.models.network import Domain, IPAddress, URL
from app.models.threat_intel import ThreatIntelligenceResult
from app.schemas.report import CaseReportResponse, ForensicReportResponse
from app.services.investigation.report_service import generate_case_report
from app.services.investigation.service import CaseNotFoundError

client = TestClient(app)


def _uid() -> uuid.UUID:
    return uuid.uuid4()


def _case_num(tag: str = "5D") -> str:
    return f"CASE-{tag}-{uuid.uuid4().hex[:8].upper()}"


def _make_case(db, tag: str = "5D", **kw) -> Case:
    defaults = dict(
        id=_uid(),
        case_number=_case_num(tag),
        title=f"Report Test Case {tag}",
        description="Forensic investigation report test",
        status="open",
        priority="high",
    )
    defaults.update(kw)
    c = Case(**defaults)
    db.add(c)
    db.flush()
    return c


def _make_email(db, case_id: uuid.UUID, **kw) -> Email:
    defaults = dict(
        id=_uid(),
        case_id=case_id,
        message_id=f"<msg-{uuid.uuid4().hex[:6]}@example.com>",
        subject="Phishing Alert Notification",
        sender="attacker@malicious.com",
        sender_domain="malicious.com",
        reply_to="drop@attacker.com",
        received_at=datetime.now(timezone.utc),
        raw_file_name="suspicious.eml",
        raw_file_hash="hash" + uuid.uuid4().hex,
        analysis_status="completed",
    )
    defaults.update(kw)
    em = Email(**defaults)
    db.add(em)
    db.flush()
    return em


def _make_evidence(db, case_id: uuid.UUID, **kw) -> Evidence:
    defaults = dict(
        id=_uid(),
        case_id=case_id,
        evidence_type="email_file",
        description="Original received email artefact",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        collected_at=datetime.now(timezone.utc),
        collected_by="forensic-agent-01",
        blockchain_tx_id="0xabc123def456",
        blockchain_verified=True,
    )
    defaults.update(kw)
    ev = Evidence(**defaults)
    db.add(ev)
    db.flush()
    return ev


def _make_event(db, case_id: uuid.UUID, **kw) -> InvestigationEvent:
    defaults = dict(
        id=_uid(),
        case_id=case_id,
        event_type="email_analyzed",
        description="Automated forensic extraction completed",
        actor="system",
        event_metadata={"action": "parsed", "email_status": "completed"},
    )
    defaults.update(kw)
    event = InvestigationEvent(**defaults)
    db.add(event)
    db.flush()
    return event


def _make_ti(db, case_id: uuid.UUID, **kw) -> ThreatIntelligenceResult:
    defaults = dict(
        id=_uid(),
        case_id=case_id,
        provider="virustotal",
        indicator_type="domain",
        indicator_value="malicious.com",
        status="malicious",
        reputation="malicious",
        confidence=95.0,
        malicious_count=42,
        suspicious_count=5,
        harmless_count=10,
        raw_response={"sensitive_token": "secret_key_123", "full_dump": True},
        queried_at=datetime.now(timezone.utc),
    )
    defaults.update(kw)
    ti = ThreatIntelligenceResult(**defaults)
    db.add(ti)
    db.flush()
    return ti


def _make_ai(db, case_id: uuid.UUID, **kw) -> AIAnalysisResult:
    defaults = dict(
        id=_uid(),
        case_id=case_id,
        classification="malicious",
        risk_score=92,
        confidence=0.96,
        reasoning="Credential harvesting phishing targeting accounting team.",
        threat_indicators=[
            {"indicator_type": "domain", "indicator_value": "malicious.com", "severity": "high", "description": "Known phishing domain"}
        ],
        supporting_evidence=["Spoofed sender domain", "Malicious link detected in message"],
        attack_techniques=["T1566.002 Spearphishing Link"],
        recommended_actions=["Block malicious.com at firewall", "Reset compromised credentials"],
        model="gemini-1.5-flash",
        provider="google",
        prompt_version="1.0.0",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kw)
    ai = AIAnalysisResult(**defaults)
    db.add(ai)
    db.flush()
    return ai


# ===========================================================================
# 1. Valid report generation and schema compliance
# ===========================================================================

def test_01_valid_report_structure_and_schema():
    """1. Generate valid report and verify all 7 sections match schema specifications."""
    with SessionLocal() as db:
        case = _make_case(db, "VAL")
        email = _make_email(db, case.id)
        
        # Add sub-artifacts to email
        h = EmailHeader(id=_uid(), email_id=email.id, header_name="Received", header_value="from mail.attacker.com", header_order=1)
        u = URL(id=_uid(), email_id=email.id, url="https://malicious.com/login", domain="malicious.com", scheme="https")
        d = Domain(id=_uid(), email_id=email.id, domain="malicious.com")
        ip = IPAddress(id=_uid(), email_id=email.id, ip_address="198.51.100.1")
        att = Attachment(id=_uid(), email_id=email.id, file_name="invoice.pdf", content_type="application/pdf", file_size=1024, sha256="aa" * 32)
        db.add_all([h, u, d, ip, att])

        ti = _make_ti(db, case.id)
        ai = _make_ai(db, case.id)
        ev = _make_evidence(db, case.id)
        event = _make_event(db, case.id)
        db.commit()

        # Service level
        report = generate_case_report(db, case.id)
        assert isinstance(report, CaseReportResponse)
        assert report.report_id is not None
        assert report.generated_at is not None

        # Section 1: Case Information
        assert report.case_information.case_id == case.id
        assert report.case_information.case_number == case.case_number
        assert report.case_information.title == case.title
        assert report.case_information.status == "open"
        assert report.case_information.priority == "high"
        assert report.case_info.case_id == case.id  # alias

        # Section 2: Executive Summary
        assert report.executive_summary.verdict == "malicious"
        assert report.executive_summary.risk_score == 92
        assert report.executive_summary.confidence == 0.96
        assert report.executive_summary.summary_text is not None
        assert "Credential harvesting" in report.executive_summary.summary_text
        assert len(report.executive_summary.key_findings) == 2
        assert len(report.executive_summary.attack_techniques) == 1
        assert len(report.executive_summary.recommended_actions) == 2
        assert report.executive_summary.email_count == 1
        assert report.executive_summary.threat_intel_count == 1
        assert report.executive_summary.ai_analysis_count == 1
        assert report.executive_summary.evidence_count == 1
        assert report.executive_summary.audit_event_count == 1

        # Section 3: Emails and Forensic Artifacts
        assert len(report.emails_and_forensic_artifacts) == 1
        assert len(report.emails) == 1  # alias
        em_item = report.emails_and_forensic_artifacts[0]
        assert em_item.email_id == email.id
        assert len(em_item.headers) == 1
        assert len(em_item.urls) == 1
        assert len(em_item.domains) == 1
        assert len(em_item.ip_addresses) == 1
        assert len(em_item.attachments) == 1

        # Section 4: Threat Intelligence
        assert len(report.threat_intelligence) == 1
        assert report.threat_intelligence[0].indicator_value == "malicious.com"

        # Section 5: AI Findings
        assert len(report.ai_findings) == 1
        assert len(report.ai_analyses) == 1  # alias
        assert report.ai_findings[0].classification == "malicious"

        # Section 6: Evidence / Chain-of-Custody
        assert len(report.evidence_chain_of_custody) == 1
        assert len(report.evidence) == 1  # alias
        assert report.evidence_chain_of_custody[0].id == ev.id
        assert report.evidence_chain_of_custody[0].blockchain_verified is True

        # Section 7: Investigation Audit Events
        assert len(report.investigation_audit_events) == 1
        assert len(report.audit_events) == 1  # alias
        assert report.investigation_audit_events[0].id == event.id


# ===========================================================================
# 2. Unknown case raises 404
# ===========================================================================

def test_02_unknown_case_raises_404():
    """2. Unknown case raises CaseNotFoundError in service and 404 HTTP in API."""
    missing_id = _uid()
    with SessionLocal() as db:
        with pytest.raises(CaseNotFoundError):
            generate_case_report(db, missing_id)

    res = client.get(f"/api/v1/cases/{missing_id}/report")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# ===========================================================================
# 3. Multiple emails support and deterministic ordering
# ===========================================================================

def test_03_multiple_emails_ordering():
    """3. Multiple emails in a case ordered by received_at ASC NULLS LAST, created_at ASC."""
    now = datetime.now(timezone.utc)
    t_early = now - timedelta(hours=2)
    t_late = now - timedelta(hours=1)

    with SessionLocal() as db:
        case = _make_case(db, "MULTI")
        # Ingest in reverse order
        e_null = _make_email(db, case.id, received_at=None, subject="No Date Email")
        e_late = _make_email(db, case.id, received_at=t_late, subject="Later Email")
        e_early = _make_email(db, case.id, received_at=t_early, subject="Earliest Email")
        db.commit()

        report = generate_case_report(db, case.id)
        email_ids = [em.email_id for em in report.emails_and_forensic_artifacts]
        # Expect order: earliest received, later received, null received
        assert email_ids == [e_early.id, e_late.id, e_null.id]
        assert report.executive_summary.email_count == 3


# ===========================================================================
# 4. Empty sections handled gracefully
# ===========================================================================

def test_04_empty_sections_handled_gracefully():
    """4. Empty case with no children returns 200 with empty collections and None metrics."""
    with SessionLocal() as db:
        case = _make_case(db, "EMPTY")
        db.commit()

        # Service
        report = generate_case_report(db, case.id)
        assert report.case_information.case_id == case.id
        assert report.emails_and_forensic_artifacts == []
        assert report.threat_intelligence == []
        assert report.ai_findings == []
        assert report.evidence_chain_of_custody == []
        assert report.investigation_audit_events == []

        # Executive summary defaults
        assert report.executive_summary.verdict is None
        assert report.executive_summary.risk_score is None
        assert report.executive_summary.highest_risk_score is None
        assert report.executive_summary.confidence is None
        assert report.executive_summary.summary_text is None
        assert report.executive_summary.key_findings == []
        assert report.executive_summary.attack_techniques == []
        assert report.executive_summary.recommended_actions == []
        assert report.executive_summary.email_count == 0
        assert report.executive_summary.threat_intel_count == 0
        assert report.executive_summary.ai_analysis_count == 0
        assert report.executive_summary.evidence_count == 0
        assert report.executive_summary.audit_event_count == 0

    # API
    res = client.get(f"/api/v1/cases/{case.id}/report")
    assert res.status_code == 200
    data = res.json()
    assert data["emails_and_forensic_artifacts"] == []
    assert data["threat_intelligence"] == []
    assert data["ai_findings"] == []
    assert data["evidence_chain_of_custody"] == []
    assert data["investigation_audit_events"] == []
    assert data["executive_summary"]["email_count"] == 0


# ===========================================================================
# 5. Deterministic ordering across all sections
# ===========================================================================

def test_05_deterministic_ordering_across_all_sections():
    """5. Report generation is deterministic for unchanged database state."""
    base_t = datetime.now(timezone.utc) - timedelta(days=1)
    with SessionLocal() as db:
        case = _make_case(db, "DET")
        email = _make_email(db, case.id, received_at=base_t)

        # 2 headers with orders
        h2 = EmailHeader(id=_uid(), email_id=email.id, header_name="Subject", header_value="Test", header_order=2)
        h1 = EmailHeader(id=_uid(), email_id=email.id, header_name="Date", header_value="Today", header_order=1)
        # 2 URLs
        u2 = URL(id=_uid(), email_id=email.id, url="https://beta.com", domain="beta.com")
        u1 = URL(id=_uid(), email_id=email.id, url="https://alpha.com", domain="alpha.com")
        db.add_all([h2, h1, u2, u1])

        # 2 TI results with different queried_at
        ti2 = _make_ti(db, case.id, indicator_value="domain2.com", queried_at=base_t + timedelta(minutes=10))
        ti1 = _make_ti(db, case.id, indicator_value="domain1.com", queried_at=base_t + timedelta(minutes=5))

        # 2 AI analyses with different created_at
        ai1 = _make_ai(db, case.id, risk_score=50, classification="suspicious", created_at=base_t + timedelta(minutes=15))
        ai2 = _make_ai(db, case.id, risk_score=90, classification="malicious", created_at=base_t + timedelta(minutes=30))

        # 2 Evidence rows with different collected_at
        ev2 = _make_evidence(db, case.id, description="Second evidence", collected_at=base_t + timedelta(minutes=8))
        ev1 = _make_evidence(db, case.id, description="First evidence", collected_at=base_t + timedelta(minutes=2))

        # 2 Audit events with different created_at
        ev_audit2 = _make_event(db, case.id, description="Second event", created_at=base_t + timedelta(minutes=20))
        ev_audit1 = _make_event(db, case.id, description="First event", created_at=base_t + timedelta(minutes=1))

        db.commit()

        # Generate report twice
        report1 = generate_case_report(db, case.id)
        report2 = generate_case_report(db, case.id)

        # Whole dumps must be 100% equal
        assert report1.model_dump() == report2.model_dump()
        assert report1.report_id == report2.report_id
        assert report1.generated_at == report2.generated_at

        # Verify ordering of each sub-section
        # Headers: 1 before 2
        headers = report1.emails_and_forensic_artifacts[0].headers
        assert [h.header_order for h in headers] == [1, 2]

        # URLs: alpha before beta
        urls = report1.emails_and_forensic_artifacts[0].urls
        assert [u.url for u in urls] == ["https://alpha.com", "https://beta.com"]

        # TI: queried_at ASC (ti1 before ti2)
        assert [t.id for t in report1.threat_intelligence] == [ti1.id, ti2.id]

        # AI: created_at ASC (ai1 before ai2)
        assert [a.id for a in report1.ai_findings] == [ai1.id, ai2.id]

        # Evidence: collected_at ASC (ev1 before ev2)
        assert [e.id for e in report1.evidence_chain_of_custody] == [ev1.id, ev2.id]

        # Events: created_at ASC (ev_audit1 before ev_audit2)
        assert [e.id for e in report1.investigation_audit_events] == [ev_audit1.id, ev_audit2.id]


# ===========================================================================
# 6. Executive summary synthesis
# ===========================================================================

def test_06_ai_executive_summary_synthesis():
    """6. Executive summary accurately synthesizes the latest AI analysis and highest risk score."""
    t0 = datetime.now(timezone.utc) - timedelta(hours=1)
    with SessionLocal() as db:
        case = _make_case(db, "EXEC")
        _make_email(db, case.id)
        _make_email(db, case.id)

        # AI 1: risk score 95 (higher), earlier
        _make_ai(
            db,
            case.id,
            risk_score=95,
            classification="malicious",
            reasoning="Severe ransomware threat",
            created_at=t0,
        )
        # AI 2: risk score 80, later (latest)
        _make_ai(
            db,
            case.id,
            risk_score=80,
            classification="suspicious",
            reasoning="Follow-up reclassification to suspicious",
            created_at=t0 + timedelta(minutes=30),
            recommended_actions=["Monitor recipient mailbox"],
        )
        db.commit()

        report = generate_case_report(db, case.id)
        exec_sum = report.executive_summary

        # Latest AI assessment
        assert exec_sum.verdict == "suspicious"
        assert exec_sum.risk_score == 80
        assert exec_sum.summary_text == "Follow-up reclassification to suspicious"
        assert exec_sum.recommended_actions == ["Monitor recipient mailbox"]

        # Highest risk score across all analyses
        assert exec_sum.highest_risk_score == 95

        # Counts
        assert exec_sum.email_count == 2
        assert exec_sum.ai_analysis_count == 2


# ===========================================================================
# 7. Threat intelligence separation
# ===========================================================================

def test_07_threat_intelligence_separation():
    """7. Observed artifacts vs external ThreatIntelligenceResult enrichments remain strictly separated."""
    with SessionLocal() as db:
        case = _make_case(db, "SEP")
        email = _make_email(db, case.id)
        d = Domain(id=_uid(), email_id=email.id, domain="example.org")
        db.add(d)
        _make_ti(db, case.id, provider="virustotal", indicator_type="domain", indicator_value="example.org", malicious_count=15)
        db.commit()

        report = generate_case_report(db, case.id)

        # Email forensic section contains observed domain
        assert len(report.emails_and_forensic_artifacts[0].domains) == 1
        assert report.emails_and_forensic_artifacts[0].domains[0].domain == "example.org"

        # Threat intel section contains external enrichment record
        assert len(report.threat_intelligence) == 1
        assert report.threat_intelligence[0].provider == "virustotal"
        assert report.threat_intelligence[0].malicious_count == 15

        # They are separate objects in separate sections
        assert type(report.emails_and_forensic_artifacts[0].domains[0]).__name__ == "DomainItem"
        assert type(report.threat_intelligence[0]).__name__ == "ThreatIntelItem"


# ===========================================================================
# 8. Evidence fields & blockchain read-only exposure
# ===========================================================================

def test_08_evidence_fields_and_blockchain_read_only():
    """8. Evidence chain-of-custody items include required fields and read-only blockchain integrity proof."""
    with SessionLocal() as db:
        case = _make_case(db, "EVID")
        ev = _make_evidence(
            db,
            case.id,
            evidence_type="email_rfc822",
            description="Forensic EML archive",
            sha256="4F53CDA18C2BAA0C0354BB5F9A3ECBE5ED12AB4D8E11BA873C2F11161202B945",
            collected_by="officer_alice",
            blockchain_tx_id="0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
            blockchain_verified=True,
        )
        db.commit()

        report = generate_case_report(db, case.id)
        ev_item = report.evidence_chain_of_custody[0]

        assert ev_item.id == ev.id
        assert ev_item.case_id == case.id
        assert ev_item.evidence_type == "email_rfc822"
        assert ev_item.description == "Forensic EML archive"
        # sha256 normalized to lowercase by validator
        assert ev_item.sha256 == "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        assert ev_item.collected_by == "officer_alice"
        assert ev_item.blockchain_tx_id.startswith("0x7f")
        assert ev_item.blockchain_verified is True


# ===========================================================================
# 9. Investigation audit events and metadata sanitization
# ===========================================================================

def test_09_audit_events_and_metadata_sanitization():
    """9. Audit events preserve allowlisted metadata keys while stripping sensitive or raw fields."""
    with SessionLocal() as db:
        case = _make_case(db, "AUDIT")
        _make_event(
            db,
            case.id,
            event_type="ti_lookup",
            actor="analyst_bob",
            event_metadata={
                "action": "lookup",
                "provider": "virustotal",
                "indicator_value": "bad.com",
                "risk_score": 90,
                # Unsafe keys that MUST be stripped:
                "api_key": "SUPER_SECRET_KEY_DO_NOT_EXPOSE",
                "password": "hunter2",
                "raw_response": {"huge": "payload"},
                "body_html": "<p>leaked</p>",
            },
        )
        db.commit()

        report = generate_case_report(db, case.id)
        event_item = report.investigation_audit_events[0]

        assert event_item.event_type == "ti_lookup"
        assert event_item.actor == "analyst_bob"
        assert event_item.metadata is not None

        # Safe keys preserved
        assert event_item.metadata["action"] == "lookup"
        assert event_item.metadata["provider"] == "virustotal"
        assert event_item.metadata["indicator_value"] == "bad.com"
        assert event_item.metadata["risk_score"] == 90

        # Unsafe keys stripped
        assert "api_key" not in event_item.metadata
        assert "password" not in event_item.metadata
        assert "raw_response" not in event_item.metadata
        assert "body_html" not in event_item.metadata


# ===========================================================================
# 10. Sensitive data exclusion (bodies, binaries, secrets, raw responses)
# ===========================================================================

def test_10_sensitive_data_exclusion():
    """10. Report never contains raw email bodies, attachment binaries, TI raw_response, or API keys."""
    with SessionLocal() as db:
        case = _make_case(db, "SENS")
        email = _make_email(db, case.id, subject="Phishing notification")
        Attachment(
            id=_uid(),
            email_id=email.id,
            file_name="malware.exe",
            content_type="application/octet-stream",
            file_size=2048,
            sha256="cc" * 32,
        )
        _make_ti(
            db,
            case.id,
            raw_response={"secret_token": "VT_TOKEN_SECRET_XYZ", "credentials": "root"},
        )
        _make_event(
            db,
            case.id,
            event_metadata={
                "action": "classified",
                "api_key": "LEAKED_API_KEY_ABC",
                "password": "LEAKED_PASSWORD_XYZ",
                "body_html": "<p>leaked body html</p>",
            },
        )
        db.commit()

        # Test both python dict and API JSON payload
        report = generate_case_report(db, case.id)
        report_dict = report.model_dump()
        report_json_str = json.dumps(report_dict, default=str)

        # Assert no sensitive content leaked
        assert "VT_TOKEN_SECRET_XYZ" not in report_json_str
        assert "secret_token" not in report_json_str
        assert "LEAKED_API_KEY_ABC" not in report_json_str
        assert "LEAKED_PASSWORD_XYZ" not in report_json_str
        assert "leaked body html" not in report_json_str

        # API endpoint check
        res = client.get(f"/api/v1/cases/{case.id}/report")
        assert res.status_code == 200
        raw_api_str = res.text
        assert "VT_TOKEN_SECRET_XYZ" not in raw_api_str
        assert "LEAKED_API_KEY_ABC" not in raw_api_str
        assert "LEAKED_PASSWORD_XYZ" not in raw_api_str
        assert "leaked body html" not in raw_api_str
        assert "raw_response" not in raw_api_str
        assert "body_plain" not in raw_api_str
        assert "body_html" not in raw_api_str


# ===========================================================================
# 11. Read-only behavior
# ===========================================================================

def test_11_read_only_behavior():
    """11. Report generation performs zero database writes (read-only)."""
    with SessionLocal() as db:
        case = _make_case(db, "RO")
        _make_email(db, case.id)
        _make_evidence(db, case.id)
        _make_event(db, case.id)
        _make_ti(db, case.id)
        _make_ai(db, case.id)
        db.commit()

        # Snapshot row counts across all affected tables
        counts_before = {
            "cases": db.scalar(select(func.count()).select_from(Case)),
            "emails": db.scalar(select(func.count()).select_from(Email)),
            "evidence": db.scalar(select(func.count()).select_from(Evidence)),
            "events": db.scalar(select(func.count()).select_from(InvestigationEvent)),
            "threat_intel": db.scalar(select(func.count()).select_from(ThreatIntelligenceResult)),
            "ai_analysis": db.scalar(select(func.count()).select_from(AIAnalysisResult)),
        }

        # Call service
        generate_case_report(db, case.id)

    # Call API
    res = client.get(f"/api/v1/cases/{case.id}/report")
    assert res.status_code == 200

    with SessionLocal() as db:
        counts_after = {
            "cases": db.scalar(select(func.count()).select_from(Case)),
            "emails": db.scalar(select(func.count()).select_from(Email)),
            "evidence": db.scalar(select(func.count()).select_from(Evidence)),
            "events": db.scalar(select(func.count()).select_from(InvestigationEvent)),
            "threat_intel": db.scalar(select(func.count()).select_from(ThreatIntelligenceResult)),
            "ai_analysis": db.scalar(select(func.count()).select_from(AIAnalysisResult)),
        }

    # Verify zero database modifications
    assert counts_before == counts_after


# ===========================================================================
# 12. Pydantic v2 response validation & JSON serialization
# ===========================================================================

def test_12_pydantic_v2_response_validation():
    """12. Report serializes cleanly to JSON and validates under Pydantic v2."""
    with SessionLocal() as db:
        case = _make_case(db, "VAL2")
        _make_email(db, case.id)
        db.commit()

        report = generate_case_report(db, case.id)
        dumped = report.model_dump()

        # Validate with CaseReportResponse and ForensicReportResponse
        validated = CaseReportResponse.model_validate(dumped)
        assert validated.case_information.case_id == case.id

        validated_alias = ForensicReportResponse.model_validate(dumped)
        assert validated_alias.report_id == report.report_id

    # Test HTTP endpoint serialization
    res = client.get(f"/api/v1/cases/{case.id}/report")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("application/json")
    payload = res.json()
    validated_http = CaseReportResponse.model_validate(payload)
    assert validated_http.case_information.case_id == case.id


# ===========================================================================
# 13. Full database integration
# ===========================================================================

def test_13_full_database_integration():
    """13. Complex investigation case matches all persisted PostgreSQL entities exactly."""
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        case = _make_case(db, "FULL", title="Operation DeepSentinel Investigation")

        # 2 emails
        e1 = _make_email(db, case.id, subject="First Phish", received_at=now - timedelta(hours=3))
        e2 = _make_email(db, case.id, subject="Second Phish", received_at=now - timedelta(hours=1))

        # Email 1 artifacts
        h1 = EmailHeader(id=_uid(), email_id=e1.id, header_name="X-Mailer", header_value="PHP/7.4", header_order=1)
        u1 = URL(id=_uid(), email_id=e1.id, url="http://phish.net/login", domain="phish.net")
        d1 = Domain(id=_uid(), email_id=e1.id, domain="phish.net")
        ip1 = IPAddress(id=_uid(), email_id=e1.id, ip_address="203.0.113.10")
        att1 = Attachment(id=_uid(), email_id=e1.id, file_name="payroll.xlsm", content_type="application/vnd.ms-excel", file_size=4096, sha256="11" * 32)
        db.add_all([h1, u1, d1, ip1, att1])

        # 2 Threat Intel entries
        ti1 = _make_ti(db, case.id, provider="virustotal", indicator_value="phish.net", status="malicious")
        ti2 = _make_ti(db, case.id, provider="abuseipdb", indicator_type="ip", indicator_value="203.0.113.10", status="suspicious")

        # 2 AI analyses
        ai1 = _make_ai(db, case.id, classification="suspicious", risk_score=60, created_at=now - timedelta(hours=2))
        ai2 = _make_ai(db, case.id, classification="malicious", risk_score=95, created_at=now - timedelta(hours=1))

        # 2 Evidence records
        ev1 = _make_evidence(db, case.id, evidence_type="raw_eml", description="Email 1 EML", collected_at=now - timedelta(hours=3))
        ev2 = _make_evidence(db, case.id, evidence_type="raw_eml", description="Email 2 EML", collected_at=now - timedelta(hours=1))

        # 2 Investigation events
        event1 = _make_event(db, case.id, event_type="case_opened", description="Case created", created_at=now - timedelta(hours=4))
        event2 = _make_event(db, case.id, event_type="email_parsed", description="Email parsed", created_at=now - timedelta(hours=2))

        db.commit()

        res = client.get(f"/api/v1/cases/{case.id}/report")
        assert res.status_code == 200
        data = res.json()

        # Section 1
        assert data["case_information"]["case_id"] == str(case.id)
        assert data["case_information"]["title"] == "Operation DeepSentinel Investigation"

        # Section 2
        assert data["executive_summary"]["verdict"] == "malicious"
        assert data["executive_summary"]["risk_score"] == 95
        assert data["executive_summary"]["highest_risk_score"] == 95
        assert data["executive_summary"]["email_count"] == 2
        assert data["executive_summary"]["threat_intel_count"] == 2
        assert data["executive_summary"]["ai_analysis_count"] == 2
        assert data["executive_summary"]["evidence_count"] == 2
        assert data["executive_summary"]["audit_event_count"] == 2

        # Section 3
        assert len(data["emails_and_forensic_artifacts"]) == 2
        first_email = data["emails_and_forensic_artifacts"][0]
        assert first_email["email_id"] == str(e1.id)
        assert len(first_email["headers"]) == 1
        assert len(first_email["urls"]) == 1
        assert len(first_email["domains"]) == 1
        assert len(first_email["ip_addresses"]) == 1
        assert len(first_email["attachments"]) == 1

        # Section 4
        assert len(data["threat_intelligence"]) == 2

        # Section 5
        assert len(data["ai_findings"]) == 2
        assert data["ai_findings"][-1]["risk_score"] == 95

        # Section 6
        assert len(data["evidence_chain_of_custody"]) == 2
        assert data["evidence_chain_of_custody"][0]["id"] == str(ev1.id)

        # Section 7
        assert len(data["investigation_audit_events"]) == 2
        assert data["investigation_audit_events"][0]["id"] == str(event1.id)
