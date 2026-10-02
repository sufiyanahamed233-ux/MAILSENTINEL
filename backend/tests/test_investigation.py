"""Tests for Phase 5A — Investigation Service and Case Workspace API.

Covers all 18 cases identified in the approved Phase 5A diagnosis:
1.  get_case_workspace() returns correctly structured workspace for case with 1 email (Service unit)
2.  get_case_workspace() returns correctly structured workspace for case with 3 emails (Service unit)
3.  get_case_workspace() raises CaseNotFoundError for unknown case_id (Service unit)
4.  raw_response from ThreatIntelligenceResult never present in workspace (Service unit)
5.  body_plain / body_html never present in workspace (Service unit)
6.  API keys never present in workspace (Service unit)
7.  Emails ordered by received_at ASC NULLS LAST, then created_at ASC (Service unit)
8.  summary.email_count equals len of emails list (Service unit)
9.  summary.latest_classification reflects most recent AIAnalysisResult (Service unit)
10. GET /api/v1/cases/{case_id} returns 200 with correct schema (API TestClient)
11. GET /api/v1/cases/{case_id} returns 404 for missing case (API TestClient)
12. GET /api/v1/cases returns 200 with list + pagination (API TestClient)
13. Case with no emails has empty emails: [] (API TestClient)
14. Case with no AI analysis has empty ai_analyses: [] (API TestClient)
15. Case with no threat intel has empty threat_intelligence: [] (API TestClient)
16. investigation_events appear in chronological order (Service unit)
17. CaseListResponse pagination fields (total, limit, offset) correct (API TestClient)
18. Full DB integration: workspace matches all persisted rows (DB integration)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models.ai_analysis import AIAnalysisResult
from app.models.case import Case
from app.models.email import Attachment, Email, EmailHeader
from app.models.investigation import InvestigationEvent
from app.models.network import Domain, IPAddress, URL
from app.models.threat_intel import ThreatIntelligenceResult
from app.schemas.investigation import (
    CaseListItem,
    CaseListResponse,
    CaseWorkspaceResponse,
)
from app.services.investigation.service import (
    CaseNotFoundError,
    get_case_workspace,
    list_cases,
)

client = TestClient(app)


def _unique_case_num(tag: str = "5A") -> str:
    return f"CASE-{tag}-{uuid.uuid4().hex[:8].upper()}"


# ===========================================================================
# 1. get_case_workspace() with 1 email
# ===========================================================================

def test_01_get_case_workspace_single_email():
    """1. get_case_workspace() returns correctly structured workspace for case with 1 email."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("SE1"),
            title="Single Email Forensic Case",
            status="open",
            priority="high",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=uuid.uuid4(),
            case_id=case.id,
            message_id="<se1@example.com>",
            subject="Invoice Payment Required",
            sender="billing@spoofed.com",
            sender_domain="spoofed.com",
            reply_to="attacker@drop.com",
            received_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            analysis_status="parsed",
            raw_file_name="invoice.eml",
            raw_file_hash="abcdef0123456789" * 4,
        )
        db.add(email)
        db.flush()

        h1 = EmailHeader(email_id=email.id, header_name="Received", header_value="from mail.spoofed.com", header_order=1)
        h2 = EmailHeader(email_id=email.id, header_name="Subject", header_value="Invoice Payment Required", header_order=2)
        url1 = URL(email_id=email.id, url="https://malicious.example.com/login", domain="malicious.example.com", reputation="suspicious")
        dom1 = Domain(email_id=email.id, domain="spoofed.com", reputation="neutral")
        ip1 = IPAddress(email_id=email.id, ip_address="198.51.100.42", country="US", reputation="suspicious")
        att1 = Attachment(email_id=email.id, file_name="invoice.pdf", content_type="application/pdf", file_size=4096, sha256="abcd" * 16)

        db.add_all([h1, h2, url1, dom1, ip1, att1])
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)

            assert isinstance(workspace, CaseWorkspaceResponse)
            assert workspace.case_id == case_id
            assert workspace.case_number == case.case_number
            assert workspace.title == "Single Email Forensic Case"
            assert workspace.status == "open"
            assert workspace.priority == "high"

            assert len(workspace.emails) == 1
            em_ws = workspace.emails[0]
            assert em_ws.email_id == email.id
            assert em_ws.subject == "Invoice Payment Required"
            assert em_ws.sender == "billing@spoofed.com"
            assert em_ws.sender_domain == "spoofed.com"
            assert em_ws.reply_to == "attacker@drop.com"
            assert em_ws.analysis_status == "parsed"

            assert len(em_ws.headers) == 2
            assert em_ws.headers[0].header_name == "Received"
            assert em_ws.headers[1].header_name == "Subject"

            assert len(em_ws.urls) == 1
            assert em_ws.urls[0].url == "https://malicious.example.com/login"

            assert len(em_ws.domains) == 1
            assert em_ws.domains[0].domain == "spoofed.com"

            assert len(em_ws.ip_addresses) == 1
            assert em_ws.ip_addresses[0].ip_address == "198.51.100.42"

            assert len(em_ws.attachments) == 1
            assert em_ws.attachments[0].file_name == "invoice.pdf"
            assert em_ws.attachments[0].sha256 == "abcd" * 16

            assert workspace.summary.email_count == 1
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 2. get_case_workspace() with 3 emails
# ===========================================================================

def test_02_get_case_workspace_three_emails():
    """2. get_case_workspace() returns correctly structured workspace for case with 3 emails."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("ME3"),
            title="Multi Email Case",
            status="open",
            priority="medium",
        )
        db.add(case)
        db.flush()

        for i in range(1, 4):
            em = Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject=f"Campaign Email #{i}",
                sender=f"sender{i}@phish.com",
                received_at=datetime(2026, 1, i, 12, 0, 0, tzinfo=timezone.utc),
                analysis_status="parsed",
            )
            db.add(em)
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)
            assert len(workspace.emails) == 3
            subjects = [e.subject for e in workspace.emails]
            assert subjects == ["Campaign Email #1", "Campaign Email #2", "Campaign Email #3"]
            assert workspace.summary.email_count == 3
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 3. get_case_workspace() raises CaseNotFoundError for unknown case_id
# ===========================================================================

def test_03_get_case_workspace_raises_case_not_found():
    """3. get_case_workspace() raises CaseNotFoundError for unknown case_id."""
    missing_id = uuid.uuid4()
    with SessionLocal() as db:
        with pytest.raises(CaseNotFoundError) as exc_info:
            get_case_workspace(db, missing_id)
        assert str(missing_id) in str(exc_info.value)


# ===========================================================================
# 4. raw_response from ThreatIntelligenceResult never present in workspace
# ===========================================================================

def test_04_raw_response_never_present_in_workspace():
    """4. raw_response from ThreatIntelligenceResult is never present in workspace."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("RAW"),
            title="Raw Response Safety Check",
            status="open",
            priority="low",
        )
        db.add(case)
        db.flush()

        ti = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="domain",
            indicator_value="evil-payload.com",
            provider="virustotal",
            status="success",
            reputation="malicious",
            confidence=0.98,
            malicious_count=45,
            suspicious_count=2,
            harmless_count=10,
            queried_at=datetime.now(timezone.utc),
            raw_response={
                "secret_provider_payload": "CONFIDENTIAL_RAW_DUMP",
                "internal_engine_details": {"engine1": "Trojan.Downloader"},
            },
        )
        db.add(ti)
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)
            assert len(workspace.threat_intelligence) == 1
            ti_item = workspace.threat_intelligence[0]

            assert ti_item.indicator_value == "evil-payload.com"
            assert ti_item.provider == "virustotal"
            assert ti_item.malicious_count == 45

            # Assert raw_response attribute does not exist on schema
            assert not hasattr(ti_item, "raw_response")

            # Assert serialized output contains no raw payload
            dump_json = workspace.model_dump_json()
            assert "raw_response" not in dump_json
            assert "CONFIDENTIAL_RAW_DUMP" not in dump_json
            assert "internal_engine_details" not in dump_json
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 5. body_plain / body_html never present in workspace
# ===========================================================================

def test_05_body_plain_body_html_never_present_in_workspace():
    """5. body_plain / body_html never present in workspace."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("BDY"),
            title="Body Safety Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.flush()

        em = Email(
            id=uuid.uuid4(),
            case_id=case.id,
            subject="Test Email With No Body In DB",
            sender="alice@example.com",
            analysis_status="parsed",
        )
        db.add(em)
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)
            assert len(workspace.emails) == 1
            email_ws = workspace.emails[0]

            assert not hasattr(email_ws, "body_plain")
            assert not hasattr(email_ws, "body_html")

            dump_str = workspace.model_dump_json()
            assert "body_plain" not in dump_str
            assert "body_html" not in dump_str
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 6. API keys never present in workspace
# ===========================================================================

def test_06_api_keys_never_present_in_workspace():
    """6. API keys, secrets, or credentials are never present in workspace."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("KEY"),
            title="API Key Safety Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)
            dump_str = workspace.model_dump_json().lower()

            for sensitive_word in ("api_key", "apikey", "secret", "password", "token", "credentials"):
                assert sensitive_word not in dump_str
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 7. Emails ordered by received_at ASC NULLS LAST, then created_at ASC
# ===========================================================================

def test_07_emails_ordered_received_at_asc_nulls_last_then_created_at():
    """7. Email ordering: received_at ASC NULLS LAST, then created_at ASC."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("ORD"),
            title="Email Ordering Test Case",
            status="open",
            priority="medium",
        )
        db.add(case)
        db.flush()

        # E1: received later
        e1 = Email(
            id=uuid.uuid4(),
            case_id=case.id,
            subject="E1 - Feb 2026",
            received_at=datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            analysis_status="parsed",
        )
        # E2: received earlier
        e2 = Email(
            id=uuid.uuid4(),
            case_id=case.id,
            subject="E2 - Jan 2026",
            received_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            created_at=datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc),
            analysis_status="parsed",
        )
        # E3: received_at is NULL, created earlier
        e3 = Email(
            id=uuid.uuid4(),
            case_id=case.id,
            subject="E3 - No Received, Created Early",
            received_at=None,
            created_at=datetime(2026, 1, 10, 0, 0, 0, tzinfo=timezone.utc),
            analysis_status="parsed",
        )
        # E4: received_at is NULL, created later
        e4 = Email(
            id=uuid.uuid4(),
            case_id=case.id,
            subject="E4 - No Received, Created Late",
            received_at=None,
            created_at=datetime(2026, 1, 20, 0, 0, 0, tzinfo=timezone.utc),
            analysis_status="parsed",
        )

        # Add out of order
        db.add_all([e3, e1, e4, e2])
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)
            ordered_subjects = [em.subject for em in workspace.emails]
            assert ordered_subjects == [
                "E2 - Jan 2026",                 # received earlier
                "E1 - Feb 2026",                 # received later
                "E3 - No Received, Created Early", # received NULL, created first
                "E4 - No Received, Created Late",  # received NULL, created second
            ]
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 8. summary.email_count equals len of emails list
# ===========================================================================

def test_08_summary_email_count_equals_len_emails():
    """8. summary.email_count equals len of emails list."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("SUMM"),
            title="Summary Count Case",
            status="open",
            priority="medium",
        )
        db.add(case)
        db.flush()

        for i in range(4):
            db.add(Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject=f"Email {i}",
                analysis_status="parsed",
            ))
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)
            assert workspace.summary.email_count == 4
            assert workspace.summary.email_count == len(workspace.emails)
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 9. summary.latest_classification reflects most recent AIAnalysisResult
# ===========================================================================

def test_09_summary_latest_classification_and_risk_scores():
    """9. summary.latest_classification reflects most recent AIAnalysisResult."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("AI9"),
            title="AI Summary Reflection Case",
            status="open",
            priority="high",
        )
        db.add(case)
        db.flush()

        ai1 = AIAnalysisResult(
            id=uuid.uuid4(),
            case_id=case.id,
            classification="suspicious",
            risk_score=60,
            confidence=0.8,
            reasoning="Suspicious domain detected.",
            created_at=datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        ai2 = AIAnalysisResult(
            id=uuid.uuid4(),
            case_id=case.id,
            classification="malicious",
            risk_score=95,
            confidence=0.95,
            reasoning="Credential harvester confirmed.",
            created_at=datetime(2026, 1, 2, 10, 0, 0, tzinfo=timezone.utc),
        )
        ai3 = AIAnalysisResult(
            id=uuid.uuid4(),
            case_id=case.id,
            classification="suspicious",
            risk_score=75,
            confidence=0.85,
            reasoning="Follow up re-assessment.",
            created_at=datetime(2026, 1, 3, 10, 0, 0, tzinfo=timezone.utc),
        )

        db.add_all([ai2, ai1, ai3])
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)
            assert workspace.summary.ai_analysis_count == 3
            # Most recent by created_at is ai3
            assert workspace.summary.latest_classification == "suspicious"
            assert workspace.summary.latest_risk_score == 75
            # Highest risk score across all results is 95
            assert workspace.summary.highest_risk_score == 95
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 10. GET /api/v1/cases/{case_id} returns 200 with correct schema
# ===========================================================================

def test_10_api_get_case_workspace_200():
    """10. GET /api/v1/cases/{case_id} returns 200 with correct schema."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("API200"),
            title="API 200 Test Case",
            status="open",
            priority="high",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=uuid.uuid4(),
            case_id=case.id,
            subject="Test API Subject",
            sender="user@test.org",
            analysis_status="parsed",
        )
        db.add(email)
        db.commit()

        try:
            response = client.get(f"/api/v1/cases/{case_id}")
            assert response.status_code == 200
            data = response.json()

            assert data["case_id"] == str(case_id)
            assert data["case_number"] == case.case_number
            assert data["title"] == "API 200 Test Case"
            assert len(data["emails"]) == 1
            assert data["emails"][0]["subject"] == "Test API Subject"
            assert "summary" in data
            assert data["summary"]["email_count"] == 1
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 11. GET /api/v1/cases/{case_id} returns 404 for missing case
# ===========================================================================

def test_11_api_get_case_workspace_404():
    """11. GET /api/v1/cases/{case_id} returns 404 for missing case."""
    missing_id = uuid.uuid4()
    response = client.get(f"/api/v1/cases/{missing_id}")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert str(missing_id) in data["detail"]


# ===========================================================================
# 12. GET /api/v1/cases returns 200 with list + pagination
# ===========================================================================

def test_12_api_list_cases_200():
    """12. GET /api/v1/cases returns 200 with list + pagination."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("LST"),
            title="Listing Test Case",
            status="open",
            priority="medium",
        )
        db.add(case)
        db.commit()

        try:
            response = client.get("/api/v1/cases?limit=10&offset=0")
            assert response.status_code == 200
            data = response.json()

            assert "cases" in data
            assert "items" in data
            assert "total" in data
            assert "limit" in data
            assert "offset" in data
            assert data["limit"] == 10
            assert data["offset"] == 0
            assert data["total"] >= 1
            assert isinstance(data["cases"], list)
            assert any(c["case_id"] == str(case_id) for c in data["cases"])
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 13. Case with no emails has empty emails: []
# ===========================================================================

def test_13_case_no_emails_returns_empty_list():
    """13. Case with no emails has empty emails: []."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("NOEM"),
            title="No Emails Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.commit()

        try:
            response = client.get(f"/api/v1/cases/{case_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["emails"] == []
            assert data["summary"]["email_count"] == 0
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 14. Case with no AI analysis has empty ai_analyses: []
# ===========================================================================

def test_14_case_no_ai_analysis_returns_empty_list():
    """14. Case with no AI analysis has empty ai_analyses: []."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("NOAI"),
            title="No AI Analysis Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.commit()

        try:
            response = client.get(f"/api/v1/cases/{case_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["ai_analyses"] == []
            assert data["summary"]["ai_analysis_count"] == 0
            assert data["summary"]["latest_classification"] is None
            assert data["summary"]["latest_risk_score"] is None
            assert data["summary"]["highest_risk_score"] is None
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 15. Case with no threat intel has empty threat_intelligence: []
# ===========================================================================

def test_15_case_no_threat_intel_returns_empty_list():
    """15. Case with no threat intel has empty threat_intelligence: []."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("NOTI"),
            title="No Threat Intel Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.commit()

        try:
            response = client.get(f"/api/v1/cases/{case_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["threat_intelligence"] == []
            assert data["summary"]["threat_intel_count"] == 0
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 16. investigation_events appear in chronological order
# ===========================================================================

def test_16_investigation_events_appear_in_chronological_order():
    """16. investigation_events appear in chronological order."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("EVT"),
            title="Chronological Events Case",
            status="open",
            priority="medium",
        )
        db.add(case)
        db.flush()

        ev1 = InvestigationEvent(
            id=uuid.uuid4(),
            case_id=case.id,
            event_type="case_created",
            description="Case initialized by analyst",
            actor="analyst_1",
            created_at=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        )
        ev2 = InvestigationEvent(
            id=uuid.uuid4(),
            case_id=case.id,
            event_type="email_uploaded",
            description="First evidence email parsed",
            actor="system",
            created_at=datetime(2026, 1, 1, 9, 5, 0, tzinfo=timezone.utc),
        )
        ev3 = InvestigationEvent(
            id=uuid.uuid4(),
            case_id=case.id,
            event_type="threat_intel_run",
            description="Threat intel enrichment executed",
            actor="system",
            created_at=datetime(2026, 1, 1, 9, 10, 0, tzinfo=timezone.utc),
        )
        ev4 = InvestigationEvent(
            id=uuid.uuid4(),
            case_id=case.id,
            event_type="ai_analyzed",
            description="AI model completed assessment",
            actor="gemini-2.5-pro",
            created_at=datetime(2026, 1, 1, 9, 15, 0, tzinfo=timezone.utc),
        )

        # Add out of order to verify sorting
        db.add_all([ev3, ev1, ev4, ev2])
        db.commit()

        try:
            workspace = get_case_workspace(db, case_id)
            assert len(workspace.investigation_events) == 4
            types = [e.event_type for e in workspace.investigation_events]
            assert types == ["case_created", "email_uploaded", "threat_intel_run", "ai_analyzed"]
            assert workspace.investigation_events[0].actor == "analyst_1"
            assert workspace.investigation_events[3].actor == "gemini-2.5-pro"
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 17. CaseListResponse pagination fields (total, limit, offset) correct
# ===========================================================================

def test_17_case_list_response_pagination_fields():
    """17. CaseListResponse pagination fields (total, limit, offset) correct."""
    cases_created = []
    with SessionLocal() as db:
        for i in range(3):
            c = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_num(f"PG{i}"),
                title=f"Pagination Test Case {i}",
                status="open",
                priority="low",
            )
            db.add(c)
            cases_created.append(c)
        db.commit()

        try:
            # Test valid limit and offset
            response = client.get("/api/v1/cases?limit=2&offset=1")
            assert response.status_code == 200
            data = response.json()

            assert data["limit"] == 2
            assert data["offset"] == 1
            assert data["total"] >= 3
            assert len(data["cases"]) <= 2

            # Test validation: negative offset
            err_offset = client.get("/api/v1/cases?limit=10&offset=-1")
            assert err_offset.status_code == 422

            # Test validation: limit > 100
            err_limit = client.get("/api/v1/cases?limit=101&offset=0")
            assert err_limit.status_code == 422

            # Test validation: limit < 1
            err_limit_zero = client.get("/api/v1/cases?limit=0&offset=0")
            assert err_limit_zero.status_code == 422
        finally:
            for c in cases_created:
                db.delete(c)
            db.commit()


# ===========================================================================
# 18. Full DB integration: workspace matches all persisted rows
# ===========================================================================

def test_18_full_db_integration_workspace_matches_all_persisted_rows():
    """18. Full DB integration: workspace matches all persisted rows across all models."""
    case_id = uuid.uuid4()
    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("FULL"),
            title="Complete Multi-Domain Phishing Investigation",
            description="Suspicious spear-phishing targeting finance department",
            status="investigating",
            priority="critical",
        )
        db.add(case)
        db.flush()

        # Email 1
        email1 = Email(
            id=uuid.uuid4(),
            case_id=case.id,
            message_id="<initial-probe@fake-internal.net>",
            subject="Urgent: Wire Transfer Verification",
            sender="cfo@fake-internal.net",
            sender_domain="fake-internal.net",
            reply_to="attacker@c2-server.com",
            received_at=datetime(2026, 2, 1, 8, 30, 0, tzinfo=timezone.utc),
            analysis_status="completed",
            raw_file_name="probe.eml",
            raw_file_hash="11223344" * 8,
        )
        db.add(email1)
        db.flush()

        h1 = EmailHeader(email_id=email1.id, header_name="Received", header_value="from c2.net by mx.corp.com", header_order=1)
        h2 = EmailHeader(email_id=email1.id, header_name="From", header_value="cfo@fake-internal.net", header_order=2)
        url1 = URL(email_id=email1.id, url="https://fake-internal.net/portal/auth", domain="fake-internal.net", reputation="malicious")
        dom1 = Domain(email_id=email1.id, domain="fake-internal.net", registrar="Hostinger", reputation="malicious")
        ip1 = IPAddress(email_id=email1.id, ip_address="203.0.113.195", asn="AS12345", organization="BadHosting Ltd", country="RO", reputation="malicious")
        att1 = Attachment(email_id=email1.id, file_name="wire_details.docx", content_type="application/vnd.openxmlformats", file_size=12000, sha256="99887766" * 8)
        db.add_all([h1, h2, url1, dom1, ip1, att1])

        # Threat Intelligence Result
        ti1 = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="ip",
            indicator_value="203.0.113.195",
            provider="abuseipdb",
            status="completed",
            reputation="malicious",
            confidence=1.0,
            malicious_count=88,
            suspicious_count=5,
            harmless_count=0,
            country="RO",
            asn=12345,
            organization="BadHosting Ltd",
            queried_at=datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc),
            raw_response={"abuse_score": 100, "reports_count": 88, "raw_data_sensitive": True},
        )
        db.add(ti1)

        # AI Analysis Result
        ai1 = AIAnalysisResult(
            id=uuid.uuid4(),
            case_id=case.id,
            classification="malicious",
            risk_score=94,
            confidence=0.96,
            reasoning="High-confidence BEC / wire transfer fraud impersonating executive.",
            attack_techniques=["T1566.002", "T1586.002"],
            recommended_actions=["Block IP 203.0.113.195", "Reset executive credentials", "Notify finance team"],
            model="gemini-2.5-pro",
            provider="google_gemini",
            prompt_version="1.0.0",
            created_at=datetime(2026, 2, 1, 9, 30, 0, tzinfo=timezone.utc),
        )
        db.add(ai1)

        # Investigation Event
        ev1 = InvestigationEvent(
            id=uuid.uuid4(),
            case_id=case.id,
            event_type="ioc_blocked",
            description="SOC analyst blacklisted IP 203.0.113.195 at firewall",
            actor="sec_analyst_42",
            created_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        db.add(ev1)
        db.commit()

        try:
            # 1. Direct Service Call
            workspace = get_case_workspace(db, case_id)

            assert workspace.case_id == case_id
            assert workspace.case_number == case.case_number
            assert workspace.title == "Complete Multi-Domain Phishing Investigation"
            assert workspace.description == "Suspicious spear-phishing targeting finance department"
            assert workspace.status == "investigating"
            assert workspace.priority == "critical"

            # Check email & forensic evidence
            assert len(workspace.emails) == 1
            em = workspace.emails[0]
            assert em.email_id == email1.id
            assert em.message_id == "<initial-probe@fake-internal.net>"
            assert em.sender == "cfo@fake-internal.net"
            assert em.sender_domain == "fake-internal.net"
            assert em.reply_to == "attacker@c2-server.com"
            assert em.raw_file_name == "probe.eml"
            assert em.raw_file_hash == "11223344" * 8

            assert len(em.headers) == 2
            assert em.headers[0].header_name == "Received"
            assert em.headers[1].header_name == "From"

            assert len(em.urls) == 1
            assert em.urls[0].url == "https://fake-internal.net/portal/auth"
            assert em.urls[0].reputation == "malicious"

            assert len(em.domains) == 1
            assert em.domains[0].domain == "fake-internal.net"
            assert em.domains[0].registrar == "Hostinger"

            assert len(em.ip_addresses) == 1
            assert em.ip_addresses[0].ip_address == "203.0.113.195"
            assert em.ip_addresses[0].asn == "AS12345"
            assert em.ip_addresses[0].country == "RO"
            assert em.ip_addresses[0].reputation == "malicious"

            assert len(em.attachments) == 1
            assert em.attachments[0].file_name == "wire_details.docx"
            assert em.attachments[0].file_size == 12000

            # Check threat intelligence
            assert len(workspace.threat_intelligence) == 1
            ti_res = workspace.threat_intelligence[0]
            assert ti_res.indicator_value == "203.0.113.195"
            assert ti_res.provider == "abuseipdb"
            assert ti_res.malicious_count == 88
            assert ti_res.reputation == "malicious"
            assert not hasattr(ti_res, "raw_response")

            # Check AI analysis
            assert len(workspace.ai_analyses) == 1
            ai_res = workspace.ai_analyses[0]
            assert ai_res.classification == "malicious"
            assert ai_res.risk_score == 94
            assert ai_res.attack_techniques == ["T1566.002", "T1586.002"]
            assert ai_res.model == "gemini-2.5-pro"

            # Check investigation event
            assert len(workspace.investigation_events) == 1
            ev_res = workspace.investigation_events[0]
            assert ev_res.event_type == "ioc_blocked"
            assert ev_res.actor == "sec_analyst_42"

            # Check summary
            assert workspace.summary.email_count == 1
            assert workspace.summary.threat_intel_count == 1
            assert workspace.summary.ai_analysis_count == 1
            assert workspace.summary.latest_classification == "malicious"
            assert workspace.summary.latest_risk_score == 94
            assert workspace.summary.highest_risk_score == 94

            # 2. Test via HTTP API TestClient
            api_resp = client.get(f"/api/v1/cases/{case_id}")
            assert api_resp.status_code == 200
            api_data = api_resp.json()

            assert api_data["case_id"] == str(case_id)
            assert api_data["case_number"] == case.case_number
            assert len(api_data["emails"]) == 1
            assert len(api_data["threat_intelligence"]) == 1
            assert len(api_data["ai_analyses"]) == 1
            assert len(api_data["investigation_events"]) == 1
            assert api_data["summary"]["latest_classification"] == "malicious"
            assert api_data["summary"]["highest_risk_score"] == 94

            # Verify serialization safety
            raw_json = api_resp.text
            assert "raw_data_sensitive" not in raw_json
            assert "abuse_score" not in raw_json
            assert "body_plain" not in raw_json
            assert "body_html" not in raw_json
        finally:
            db.delete(case)
            db.commit()
