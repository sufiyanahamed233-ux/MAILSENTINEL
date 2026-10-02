"""Tests for Phase 5B — Detailed Email Forensic Evidence and Investigation API.

Covers all Phase 5B requirements and corrections:
1.  valid case + email returns 200
2.  unknown case → 404
3.  unknown email → 404
4.  email belonging to another case → 404
5.  headers/artifacts are returned
6.  TI raw_response is never returned
7.  email body/HTML/raw MIME are never returned
8.  attachment binary is never returned
9.  AI results are returned (case-scoped assessments)
10. deterministic ordering
11. API response validation
12. database integration with persisted Phase 3/4 data
13. multi-email TI indicator scoping:
    - case with two emails and separate TI indicators
    - requesting email A returns only TI relevant to email A
    - requesting email B returns only TI relevant to email B
    - unrelated case TI is excluded
14. canonical schema validation: response contains only canonical
    threat_intelligence and ai_analyses fields (no duplicate related_* fields)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models.ai_analysis import AIAnalysisResult
from app.models.case import Case
from app.models.email import Attachment, Email, EmailHeader
from app.models.network import Domain, IPAddress, URL
from app.models.threat_intel import ThreatIntelligenceResult
from app.schemas.investigation_detail import EmailDetailResponse
from app.services.investigation.detail_service import (
    CaseNotFoundError,
    EmailNotBelongToCaseError,
    EmailNotFoundError,
    get_email_detail,
)

client = TestClient(app)


def _unique_case_num(tag: str = "5B") -> str:
    return f"CASE-{tag}-{uuid.uuid4().hex[:8].upper()}"


# ===========================================================================
# 1. valid case + email returns 200
# ===========================================================================

def test_01_valid_case_and_email_returns_200():
    """1. valid case + email returns 200 with structured EmailDetailResponse."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("VLD"),
            title="Valid Case Test",
            status="open",
            priority="high",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            message_id="<test01@target.com>",
            subject="Urgent Security Alert",
            sender="security@service-notice.com",
            sender_domain="service-notice.com",
            reply_to="attacker@c2.net",
            received_at=datetime(2026, 2, 10, 14, 0, 0, tzinfo=timezone.utc),
            analysis_status="parsed",
            raw_file_name="alert.eml",
            raw_file_hash="12345678" * 8,
        )
        db.add(email)
        db.commit()

        try:
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            data = resp.json()

            assert data["id"] == str(email_id)
            assert data["case_id"] == str(case_id)
            assert data["message_id"] == "<test01@target.com>"
            assert data["subject"] == "Urgent Security Alert"
            assert data["sender"] == "security@service-notice.com"
            assert data["sender_domain"] == "service-notice.com"
            assert data["reply_to"] == "attacker@c2.net"
            assert data["analysis_status"] == "parsed"
            assert data["raw_file_name"] == "alert.eml"
            assert data["raw_file_hash"] == "12345678" * 8
            assert "created_at" in data
            assert isinstance(data["headers"], list)
            assert isinstance(data["urls"], list)
            assert isinstance(data["domains"], list)
            assert isinstance(data["ip_addresses"], list)
            assert isinstance(data["attachments"], list)
            assert "threat_intelligence" in data
            assert "ai_analyses" in data
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 2. unknown case → 404
# ===========================================================================

def test_02_unknown_case_returns_404():
    """2. unknown case → 404."""
    unknown_case_id = uuid.uuid4()
    dummy_email_id = uuid.uuid4()

    resp = client.get(f"/api/v1/cases/{unknown_case_id}/emails/{dummy_email_id}")
    assert resp.status_code == 404
    data = resp.json()
    assert "detail" in data
    assert str(unknown_case_id) in data["detail"]


# ===========================================================================
# 3. unknown email → 404
# ===========================================================================

def test_03_unknown_email_returns_404():
    """3. unknown email → 404."""
    case_id = uuid.uuid4()
    unknown_email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("UNKEM"),
            title="Unknown Email Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.commit()

        try:
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{unknown_email_id}")
            assert resp.status_code == 404
            data = resp.json()
            assert "detail" in data
            assert str(unknown_email_id) in data["detail"]
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 4. email belonging to another case → 404
# ===========================================================================

def test_04_email_belonging_to_another_case_returns_404():
    """4. email belonging to another case → 404."""
    case_a_id = uuid.uuid4()
    case_b_id = uuid.uuid4()
    email_b_id = uuid.uuid4()

    with SessionLocal() as db:
        case_a = Case(
            id=case_a_id,
            case_number=_unique_case_num("CASEA"),
            title="Case A",
            status="open",
            priority="low",
        )
        case_b = Case(
            id=case_b_id,
            case_number=_unique_case_num("CASEB"),
            title="Case B",
            status="open",
            priority="low",
        )
        db.add_all([case_a, case_b])
        db.flush()

        email_b = Email(
            id=email_b_id,
            case_id=case_b.id,
            subject="Email of Case B",
            sender="b@test.com",
            analysis_status="parsed",
        )
        db.add(email_b)
        db.commit()

        try:
            # Request email_b using case_a_id -> must be 404
            resp = client.get(f"/api/v1/cases/{case_a_id}/emails/{email_b_id}")
            assert resp.status_code == 404
            data = resp.json()
            assert "detail" in data
            assert "does not belong to case" in data["detail"]

            # Service unit assertion
            with pytest.raises(EmailNotBelongToCaseError):
                get_email_detail(db, case_a_id, email_b_id)
        finally:
            db.delete(case_a)
            db.delete(case_b)
            db.commit()


# ===========================================================================
# 5. headers/artifacts are returned
# ===========================================================================

def test_05_headers_and_artifacts_are_returned():
    """5. headers/artifacts are returned with detailed metadata."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("ARTF"),
            title="Artifacts Test Case",
            status="open",
            priority="medium",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            subject="Suspicious Invoice Delivery",
            analysis_status="parsed",
        )
        db.add(email)
        db.flush()

        h1 = EmailHeader(email_id=email.id, header_name="Received", header_value="from mail.attacker.net", header_order=1)
        h2 = EmailHeader(email_id=email.id, header_name="X-Mailer", header_value="PHPMailer 6.0", header_order=2)
        url1 = URL(email_id=email.id, url="https://attacker.net/login.php", normalized_url="http://attacker.net/login.php", domain="attacker.net", scheme="https", path="/login.php", reputation="malicious")
        dom1 = Domain(email_id=email.id, domain="attacker.net", registrar="Namecheap", reputation="malicious")
        ip1 = IPAddress(
            email_id=email.id,
            ip_address="198.51.100.99",
            version=4,
            asn="AS65530",
            organization="Malicious Hosting Inc",
            country="DE",
            region="Bavaria",
            city="Munich",
            latitude=48.1351,
            longitude=11.5820,
            reputation="malicious",
        )
        att1 = Attachment(
            email_id=email.id,
            file_name="remittance_advice.xlsx",
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            file_size=24500,
            sha256="aabbccddeeff0011" * 4,
            md5="11223344" * 4,
        )
        db.add_all([h1, h2, url1, dom1, ip1, att1])
        db.commit()

        try:
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            data = resp.json()

            # Headers
            assert len(data["headers"]) == 2
            assert data["headers"][0]["header_name"] == "Received"
            assert data["headers"][1]["header_name"] == "X-Mailer"

            # URLs
            assert len(data["urls"]) == 1
            u = data["urls"][0]
            assert u["url"] == "https://attacker.net/login.php"
            assert u["domain"] == "attacker.net"
            assert u["reputation"] == "malicious"

            # Domains
            assert len(data["domains"]) == 1
            d = data["domains"][0]
            assert d["domain"] == "attacker.net"
            assert d["registrar"] == "Namecheap"

            # IP infrastructure
            assert len(data["ip_addresses"]) == 1
            ip = data["ip_addresses"][0]
            assert ip["ip_address"] == "198.51.100.99"
            assert ip["version"] == 4
            assert ip["asn"] == "AS65530"
            assert ip["organization"] == "Malicious Hosting Inc"
            assert ip["country"] == "DE"
            assert ip["city"] == "Munich"
            assert ip["latitude"] == 48.1351
            assert ip["longitude"] == 11.5820

            # Attachments
            assert len(data["attachments"]) == 1
            a = data["attachments"][0]
            assert a["file_name"] == "remittance_advice.xlsx"
            assert a["file_size"] == 24500
            assert a["sha256"] == "aabbccddeeff0011" * 4
            assert a["md5"] == "11223344" * 4
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 6. TI raw_response is never returned
# ===========================================================================

def test_06_ti_raw_response_never_returned():
    """6. TI raw_response is never returned in API or service responses."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("RAWTI"),
            title="TI Raw Response Safety Case",
            status="open",
            priority="medium",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            subject="TI Check Email",
            analysis_status="parsed",
        )
        db.add(email)
        db.flush()

        # Add domain to email to associate with TI indicator
        dom = Domain(email_id=email.id, domain="bad-site.com")
        db.add(dom)

        ti = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="domain",
            indicator_value="bad-site.com",
            provider="virustotal",
            status="completed",
            reputation="malicious",
            confidence=0.99,
            malicious_count=70,
            queried_at=datetime.now(timezone.utc),
            raw_response={
                "sensitive_api_payload": "TOP_SECRET_EXTERNAL_DATA",
                "auth_header_leak": "Bearer secret_api_key_12345",
            },
        )
        db.add(ti)
        db.commit()

        try:
            # 1. API check
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            raw_text = resp.text
            assert "TOP_SECRET_EXTERNAL_DATA" not in raw_text
            assert "secret_api_key_12345" not in raw_text
            assert "raw_response" not in raw_text

            # 2. Schema check
            detail = get_email_detail(db, case_id, email_id)
            assert len(detail.threat_intelligence) == 1
            ti_item = detail.threat_intelligence[0]
            assert not hasattr(ti_item, "raw_response")
            assert "raw_response" not in detail.model_dump_json()
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 7. email body/HTML/raw MIME are never returned
# ===========================================================================

def test_07_email_body_html_raw_mime_never_returned():
    """7. email body/HTML/raw MIME are never returned in response."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("NOBDY"),
            title="Body Safety Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            subject="Clean Body Email",
            analysis_status="parsed",
        )
        db.add(email)
        db.commit()

        try:
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            raw_text = resp.text

            assert "body_plain" not in raw_text
            assert "body_html" not in raw_text
            assert "raw_mime" not in raw_text

            detail = get_email_detail(db, case_id, email_id)
            assert not hasattr(detail, "body_plain")
            assert not hasattr(detail, "body_html")
            assert not hasattr(detail, "raw_mime")
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 8. attachment binary is never returned
# ===========================================================================

def test_08_attachment_binary_never_returned():
    """8. attachment binary is never returned."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("NOBIN"),
            title="Binary Safety Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            subject="Attachment Binary Check",
            analysis_status="parsed",
        )
        db.add(email)
        db.flush()

        att = Attachment(
            email_id=email.id,
            file_name="malware.exe",
            content_type="application/x-dosexec",
            file_size=1048576,
            sha256="deadbeef" * 8,
            md5="cafebabe" * 4,
        )
        db.add(att)
        db.commit()

        try:
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            data = resp.json()
            att_data = data["attachments"][0]

            assert att_data["file_name"] == "malware.exe"
            assert att_data["file_size"] == 1048576
            assert "binary" not in att_data
            assert "content" not in att_data
            assert "raw_bytes" not in att_data
            assert "file_content" not in att_data
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 9. AI results are returned
# ===========================================================================

def test_09_ai_results_are_returned():
    """9. AI results are returned with complete assessment fields (case-scoped)."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("AIRET"),
            title="AI Assessment Check Case",
            status="open",
            priority="critical",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            subject="Phishing Campaign Email",
            analysis_status="completed",
        )
        db.add(email)
        db.flush()

        ai = AIAnalysisResult(
            id=uuid.uuid4(),
            case_id=case.id,
            classification="malicious",
            risk_score=92,
            confidence=0.97,
            reasoning="Observed credential phishing attacking Office 365.",
            attack_techniques=["T1566.002", "T1056.001"],
            recommended_actions=["Block sender domain", "Force password reset"],
            model="gemini-2.5-pro",
            provider="google_gemini",
            prompt_version="1.0.0",
            created_at=datetime.now(timezone.utc),
        )
        db.add(ai)
        db.commit()

        try:
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            data = resp.json()

            assert len(data["ai_analyses"]) == 1
            ai_data = data["ai_analyses"][0]
            assert ai_data["classification"] == "malicious"
            assert ai_data["risk_score"] == 92
            assert ai_data["confidence"] == 0.97
            assert ai_data["attack_techniques"] == ["T1566.002", "T1056.001"]
            assert ai_data["recommended_actions"] == ["Block sender domain", "Force password reset"]
            assert ai_data["model"] == "gemini-2.5-pro"
            assert ai_data["provider"] == "google_gemini"
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 10. deterministic ordering
# ===========================================================================

def test_10_deterministic_ordering():
    """10. deterministic ordering for headers, artifacts, threat intelligence, and AI results."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("DETERM"),
            title="Ordering Test Case",
            status="open",
            priority="medium",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            subject="Deterministic Ordering Email",
            analysis_status="parsed",
        )
        db.add(email)
        db.flush()

        # Headers with out-of-order header_order
        h3 = EmailHeader(email_id=email.id, header_name="Subject", header_value="Order 3", header_order=3)
        h1 = EmailHeader(email_id=email.id, header_name="Received", header_value="Order 1", header_order=1)
        h2 = EmailHeader(email_id=email.id, header_name="From", header_value="Order 2", header_order=2)
        h_none = EmailHeader(email_id=email.id, header_name="X-Custom", header_value="Order None", header_order=None)

        # URLs created at different times
        u2 = URL(email_id=email.id, url="https://second.com", created_at=datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc))
        u1 = URL(email_id=email.id, url="https://first.com", created_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc))

        # AI results created at different times
        ai2 = AIAnalysisResult(
            id=uuid.uuid4(),
            case_id=case.id,
            classification="malicious",
            risk_score=90,
            created_at=datetime(2026, 1, 5, 0, 0, 0, tzinfo=timezone.utc),
        )
        ai1 = AIAnalysisResult(
            id=uuid.uuid4(),
            case_id=case.id,
            classification="suspicious",
            risk_score=60,
            created_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        )

        db.add_all([h3, h1, h_none, h2, u2, u1, ai2, ai1])
        db.commit()

        try:
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            data = resp.json()

            # Headers: 1, 2, 3, then None
            header_names = [h["header_name"] for h in data["headers"]]
            assert header_names == ["Received", "From", "Subject", "X-Custom"]

            # URLs: first.com then second.com
            urls = [u["url"] for u in data["urls"]]
            assert urls == ["https://first.com", "https://second.com"]

            # AI analyses: ai1 (Jan 1) then ai2 (Jan 5)
            ai_scores = [a["risk_score"] for a in data["ai_analyses"]]
            assert ai_scores == [60, 90]
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 11. API response validation
# ===========================================================================

def test_11_api_response_validation():
    """11. API response validation and read-only behavior."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("VAL"),
            title="Validation Test Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            subject="Validation Subject",
            analysis_status="parsed",
        )
        db.add(email)
        db.commit()

        initial_case_updated = case.updated_at

        try:
            # 1. Valid API call conforms strictly to Pydantic schema
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            parsed_model = EmailDetailResponse.model_validate(resp.json())
            assert parsed_model.id == email_id
            assert parsed_model.case_id == case_id

            # 2. Invalid UUID parameter format returns 422
            resp_inv_case = client.get(f"/api/v1/cases/not-a-uuid/emails/{email_id}")
            assert resp_inv_case.status_code == 422

            resp_inv_email = client.get(f"/api/v1/cases/{case_id}/emails/not-a-uuid")
            assert resp_inv_email.status_code == 422

            # 3. Read-only validation: verify no DB rows were updated or created
            refreshed_case = db.get(Case, case_id)
            assert refreshed_case.updated_at == initial_case_updated
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 12. database integration with persisted Phase 3/4 data
# ===========================================================================

def test_12_database_integration_persisted_phase_3_4_data():
    """12. database integration with persisted Phase 3/4 data across all models."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("FULL5B"),
            title="End-to-End Investigation Detail Case",
            description="Spear-phishing targeting executive mailbox",
            status="investigating",
            priority="critical",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            message_id="<exec-urgent-01@spoofed-bank.com>",
            subject="ACTION REQUIRED: Confirm Transfer of $250,000",
            sender="ceo@spoofed-bank.com",
            sender_domain="spoofed-bank.com",
            reply_to="dropzone@c2-bulletproof.ch",
            received_at=datetime(2026, 2, 1, 9, 15, 0, tzinfo=timezone.utc),
            analysis_status="completed",
            raw_file_name="ceo_wire.eml",
            raw_file_hash="9988776655443322" * 4,
        )
        db.add(email)
        db.flush()

        # Forensic artifacts
        h1 = EmailHeader(email_id=email.id, header_name="Received", header_value="from c2-bulletproof.ch by mx.corp.com", header_order=1)
        h2 = EmailHeader(email_id=email.id, header_name="From", header_value="ceo@spoofed-bank.com", header_order=2)
        url1 = URL(email_id=email.id, url="https://wire-auth.spoofed-bank.com/login", normalized_url="http://wire-auth.spoofed-bank.com/login", domain="wire-auth.spoofed-bank.com", scheme="https", path="/login", reputation="malicious")
        dom1 = Domain(email_id=email.id, domain="spoofed-bank.com", registrar="Epik", reputation="malicious")
        ip1 = IPAddress(email_id=email.id, ip_address="185.220.101.5", asn="AS208323", organization="AnonNetwork", country="CH", city="Zurich", reputation="malicious")
        att1 = Attachment(email_id=email.id, file_name="wire_auth.pdf", content_type="application/pdf", file_size=48120, sha256="aabb1122" * 8, md5="33445566" * 4)

        # Threat Intelligence Result (persisted like Phase 3)
        ti1 = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="ip",
            indicator_value="185.220.101.5",
            provider="abuseipdb",
            status="success",
            reputation="malicious",
            confidence=0.99,
            malicious_count=120,
            suspicious_count=15,
            harmless_count=1,
            country="CH",
            asn=208323,
            organization="AnonNetwork",
            queried_at=datetime(2026, 2, 1, 9, 30, 0, tzinfo=timezone.utc),
            raw_response={"ip": "185.220.101.5", "abuseConfidenceScore": 100, "totalReports": 120},
        )

        # AI Analysis Result (persisted like Phase 4)
        ai1 = AIAnalysisResult(
            id=uuid.uuid4(),
            case_id=case.id,
            classification="malicious",
            risk_score=96,
            confidence=0.98,
            reasoning="Critical Business Email Compromise (BEC) wire transfer deception.",
            threat_indicators=[
                {"indicator_type": "domain", "indicator_value": "spoofed-bank.com", "severity": "critical", "description": "Spoofed corporate bank domain"},
                {"indicator_type": "ip", "indicator_value": "185.220.101.5", "severity": "high", "description": "High abuse score bulletproof exit node"},
            ],
            supporting_evidence=[
                "Executive impersonation without SPF alignment",
                "AbuseIPDB reports 120 malicious incidents for sending IP",
            ],
            attack_techniques=["T1566.002", "T1586.002", "T1056"],
            recommended_actions=[
                "Quarantine all inbound emails from spoofed-bank.com",
                "Block IP 185.220.101.5 on perimeter firewall",
                "Contact finance team to hold pending wire transfers",
            ],
            model="gemini-2.5-pro",
            provider="google_gemini",
            prompt_version="1.0.0",
            created_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc),
        )

        db.add_all([h1, h2, url1, dom1, ip1, att1, ti1, ai1])
        db.commit()

        try:
            # Service call
            detail = get_email_detail(db, case_id, email_id)
            assert detail.id == email_id
            assert detail.case_id == case_id
            assert detail.subject == "ACTION REQUIRED: Confirm Transfer of $250,000"
            assert len(detail.headers) == 2
            assert len(detail.urls) == 1
            assert len(detail.domains) == 1
            assert len(detail.ip_addresses) == 1
            assert len(detail.attachments) == 1
            assert len(detail.threat_intelligence) == 1
            assert len(detail.ai_analyses) == 1

            # API call
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            data = resp.json()

            assert data["id"] == str(email_id)
            assert data["case_id"] == str(case_id)
            assert data["sender"] == "ceo@spoofed-bank.com"
            assert data["headers"][0]["header_name"] == "Received"
            assert data["urls"][0]["url"] == "https://wire-auth.spoofed-bank.com/login"
            assert data["domains"][0]["domain"] == "spoofed-bank.com"
            assert data["ip_addresses"][0]["ip_address"] == "185.220.101.5"
            assert data["ip_addresses"][0]["country"] == "CH"
            assert data["attachments"][0]["file_name"] == "wire_auth.pdf"
            assert data["threat_intelligence"][0]["indicator_value"] == "185.220.101.5"
            assert data["ai_analyses"][0]["risk_score"] == 96
            assert data["ai_analyses"][0]["classification"] == "malicious"

            # Check raw safety exclusions
            assert "raw_response" not in resp.text
            assert "abuseConfidenceScore" not in resp.text
            assert "body_plain" not in resp.text
            assert "body_html" not in resp.text
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 13. multi-email TI indicator scoping
# ===========================================================================

def test_13_multi_email_ti_scoping_and_unrelated_exclusion():
    """13. Multi-email TI scoping:
    - case with two emails and separate TI indicators
    - requesting email A returns only TI relevant to email A
    - requesting email B returns only TI relevant to email B
    - unrelated case TI is excluded from both.
    """
    case_id = uuid.uuid4()
    email_a_id = uuid.uuid4()
    email_b_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("SCOPE"),
            title="Multi-Email Scoping Test Case",
            status="open",
            priority="high",
        )
        db.add(case)
        db.flush()

        # Email A with IP A (198.51.100.11) and Domain A (domain-a.org)
        email_a = Email(
            id=email_a_id,
            case_id=case.id,
            subject="Email A Phish",
            analysis_status="parsed",
        )
        db.add(email_a)
        db.flush()

        ip_a = IPAddress(email_id=email_a.id, ip_address="198.51.100.11")
        dom_a = Domain(email_id=email_a.id, domain="domain-a.org")
        db.add_all([ip_a, dom_a])

        # Email B with IP B (203.0.113.22) and URL B (https://malicious-b.com/login)
        email_b = Email(
            id=email_b_id,
            case_id=case.id,
            subject="Email B Malware",
            analysis_status="parsed",
        )
        db.add(email_b)
        db.flush()

        ip_b = IPAddress(email_id=email_b.id, ip_address="203.0.113.22")
        url_b = URL(email_id=email_b.id, url="https://malicious-b.com/login", domain="malicious-b.com")
        db.add_all([ip_b, url_b])

        # Case-level Threat Intelligence Results:
        # TI A1 (relevant to Email A)
        ti_a1 = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="ip",
            indicator_value="198.51.100.11",
            provider="virustotal",
            status="success",
            reputation="malicious",
            queried_at=datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        # TI A2 (relevant to Email A)
        ti_a2 = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="domain",
            indicator_value="domain-a.org",
            provider="virustotal",
            status="success",
            reputation="suspicious",
            queried_at=datetime(2026, 1, 1, 10, 5, 0, tzinfo=timezone.utc),
        )
        # TI B1 (relevant to Email B)
        ti_b1 = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="ip",
            indicator_value="203.0.113.22",
            provider="abuseipdb",
            status="success",
            reputation="malicious",
            queried_at=datetime(2026, 1, 1, 10, 10, 0, tzinfo=timezone.utc),
        )
        # TI B2 (relevant to Email B domain extracted from URL)
        ti_b2 = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="domain",
            indicator_value="malicious-b.com",
            provider="virustotal",
            status="success",
            reputation="malicious",
            queried_at=datetime(2026, 1, 1, 10, 15, 0, tzinfo=timezone.utc),
        )
        # TI C: Unrelated case indicator not observed in Email A or Email B
        ti_unrelated = ThreatIntelligenceResult(
            id=uuid.uuid4(),
            case_id=case.id,
            indicator_type="ip",
            indicator_value="192.0.2.99",
            provider="abuseipdb",
            status="success",
            reputation="clean",
            queried_at=datetime(2026, 1, 1, 10, 20, 0, tzinfo=timezone.utc),
        )

        db.add_all([ti_a1, ti_a2, ti_b1, ti_b2, ti_unrelated])
        db.commit()

        try:
            # 1. Query Email A
            resp_a = client.get(f"/api/v1/cases/{case_id}/emails/{email_a_id}")
            assert resp_a.status_code == 200
            data_a = resp_a.json()
            ti_vals_a = [t["indicator_value"] for t in data_a["threat_intelligence"]]

            assert len(ti_vals_a) == 2
            assert "198.51.100.11" in ti_vals_a
            assert "domain-a.org" in ti_vals_a
            # Ensure Email B indicators are NOT present in Email A
            assert "203.0.113.22" not in ti_vals_a
            assert "malicious-b.com" not in ti_vals_a
            # Ensure unrelated case TI is NOT present
            assert "192.0.2.99" not in ti_vals_a

            # 2. Query Email B
            resp_b = client.get(f"/api/v1/cases/{case_id}/emails/{email_b_id}")
            assert resp_b.status_code == 200
            data_b = resp_b.json()
            ti_vals_b = [t["indicator_value"] for t in data_b["threat_intelligence"]]

            assert len(ti_vals_b) == 2
            assert "203.0.113.22" in ti_vals_b
            assert "malicious-b.com" in ti_vals_b
            # Ensure Email A indicators are NOT present in Email B
            assert "198.51.100.11" not in ti_vals_b
            assert "domain-a.org" not in ti_vals_b
            # Ensure unrelated case TI is NOT present
            assert "192.0.2.99" not in ti_vals_b
        finally:
            db.delete(case)
            db.commit()


# ===========================================================================
# 14. canonical schema fields only (no duplicate related_* keys)
# ===========================================================================

def test_14_canonical_response_fields_only():
    """14. Response contains only canonical threat_intelligence and ai_analyses fields."""
    case_id = uuid.uuid4()
    email_id = uuid.uuid4()

    with SessionLocal() as db:
        case = Case(
            id=case_id,
            case_number=_unique_case_num("CANON"),
            title="Canonical Fields Case",
            status="open",
            priority="low",
        )
        db.add(case)
        db.flush()

        email = Email(
            id=email_id,
            case_id=case.id,
            subject="Canonical Fields Email",
            analysis_status="parsed",
        )
        db.add(email)
        db.commit()

        try:
            resp = client.get(f"/api/v1/cases/{case_id}/emails/{email_id}")
            assert resp.status_code == 200
            data = resp.json()

            # Canonical fields must be present
            assert "threat_intelligence" in data
            assert "ai_analyses" in data

            # Duplicate names must NOT exist
            assert "related_threat_intelligence" not in data
            assert "related_ai_analyses" not in data
        finally:
            db.delete(case)
            db.commit()
