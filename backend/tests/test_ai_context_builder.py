"""Tests for Phase 4B — AI Threat Analysis Context Builder.

Verifies schema imports, context construction for single/multi-email cases,
header ordering, URL/domain/IP/attachment representation, threat-intelligence
inclusion (without raw_response), data-safety exclusions, missing-data
handling, deterministic ordering, nonexistent-case exception, and read-only
guarantee.
"""

import uuid
import unittest
from datetime import datetime, timezone

from app.db.session import SessionLocal
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
from app.services.ai.context_builder import CaseNotFoundError, build_ai_context


def _unique_case_number(prefix: str = "CTX") -> str:
    return f"CASE-{prefix}-{uuid.uuid4().hex[:6].upper()}"


class TestAIContextBuilder(unittest.TestCase):
    """Phase 4B test suite for the AI context builder."""

    # ------------------------------------------------------------------
    # 1. Schema imports
    # ------------------------------------------------------------------

    def test_01_schema_imports(self):
        """1. All AI context schemas import successfully."""
        for cls in (
            AIAnalysisContext,
            AICaseContext,
            AIForensicEvidence,
            AIEmailContext,
            AIHeaderEvidence,
            AIURLEvidence,
            AIDomainEvidence,
            AIIPAddressEvidence,
            AIAttachmentEvidence,
            AIThreatIntelligence,
            AIThreatIntelResult,
        ):
            self.assertTrue(callable(cls))

    # ------------------------------------------------------------------
    # 2. Single-email context
    # ------------------------------------------------------------------

    def test_02_single_email_context(self):
        """2. Case with one email produces the expected context."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("SE"),
                title="Single Email Test",
                status="open",
                priority="high",
            )
            db.add(case)
            db.flush()

            email = Email(
                id=uuid.uuid4(),
                case_id=case.id,
                message_id="<test-single@example.com>",
                subject="Single email subject",
                sender="alice@example.com",
                sender_domain="example.com",
                reply_to="bob@example.com",
                analysis_status="parsed",
                raw_file_name="single.eml",
                raw_file_hash="aabb" * 16,
            )
            db.add(email)
            db.commit()

            ctx = build_ai_context(db, case.id)

            # Case metadata
            self.assertEqual(ctx.case.case_id, case.id)
            self.assertEqual(ctx.case.case_number, case.case_number)
            self.assertEqual(ctx.case.case_title, "Single Email Test")
            self.assertEqual(ctx.case.case_status, "open")
            self.assertEqual(ctx.case.case_priority, "high")

            # Forensic evidence
            self.assertEqual(len(ctx.forensic_evidence.emails), 1)
            em = ctx.forensic_evidence.emails[0]
            self.assertEqual(em.email_id, email.id)
            self.assertEqual(em.subject, "Single email subject")
            self.assertEqual(em.sender, "alice@example.com")
            self.assertEqual(em.reply_to, "bob@example.com")
            self.assertEqual(em.analysis_status, "parsed")

            # Threat intelligence (empty)
            self.assertEqual(len(ctx.threat_intelligence.results), 0)

    # ------------------------------------------------------------------
    # 3. Multiple emails
    # ------------------------------------------------------------------

    def test_03_multiple_emails(self):
        """3. Case with multiple emails is represented correctly."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("ME"),
                title="Multi Email Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            for i in range(3):
                db.add(Email(
                    id=uuid.uuid4(),
                    case_id=case.id,
                    subject=f"Email {i}",
                    analysis_status="parsed",
                ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            self.assertEqual(len(ctx.forensic_evidence.emails), 3)
            subjects = [e.subject for e in ctx.forensic_evidence.emails]
            self.assertEqual(len(subjects), 3)

    # ------------------------------------------------------------------
    # 4. Header ordering
    # ------------------------------------------------------------------

    def test_04_headers_ordered_by_header_order(self):
        """4. Email headers are preserved and ordered by header_order."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("HD"),
                title="Header Order Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            email = Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="Headers test",
                analysis_status="parsed",
            )
            db.add(email)
            db.flush()

            # Insert out of order
            db.add(EmailHeader(
                id=uuid.uuid4(), email_id=email.id,
                header_name="Received", header_value="from server2", header_order=2,
            ))
            db.add(EmailHeader(
                id=uuid.uuid4(), email_id=email.id,
                header_name="From", header_value="alice@example.com", header_order=0,
            ))
            db.add(EmailHeader(
                id=uuid.uuid4(), email_id=email.id,
                header_name="Received", header_value="from server1", header_order=1,
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            headers = ctx.forensic_evidence.emails[0].headers
            self.assertEqual(len(headers), 3)
            self.assertEqual(headers[0].header_order, 0)
            self.assertEqual(headers[0].header_name, "From")
            self.assertEqual(headers[1].header_order, 1)
            self.assertEqual(headers[2].header_order, 2)

    # ------------------------------------------------------------------
    # 5. URLs
    # ------------------------------------------------------------------

    def test_05_urls_represented(self):
        """5. URLs are represented correctly."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("UR"),
                title="URL Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            email = Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="URL test",
                analysis_status="parsed",
            )
            db.add(email)
            db.flush()

            db.add(URL(
                id=uuid.uuid4(), email_id=email.id,
                url="https://phish.example.com/login",
                normalized_url="https://phish.example.com/login",
                domain="phish.example.com",
                scheme="https",
                path="/login",
                reputation="malicious",
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            urls = ctx.forensic_evidence.emails[0].urls
            self.assertEqual(len(urls), 1)
            self.assertEqual(urls[0].url, "https://phish.example.com/login")
            self.assertEqual(urls[0].domain, "phish.example.com")
            self.assertEqual(urls[0].scheme, "https")
            self.assertEqual(urls[0].path, "/login")
            self.assertEqual(urls[0].reputation, "malicious")

    # ------------------------------------------------------------------
    # 6. Domains
    # ------------------------------------------------------------------

    def test_06_domains_represented(self):
        """6. Domains are represented correctly."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("DM"),
                title="Domain Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            email = Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="Domain test",
                analysis_status="parsed",
            )
            db.add(email)
            db.flush()

            db.add(Domain(
                id=uuid.uuid4(), email_id=email.id,
                domain="suspicious.net",
                registrar="BadRegistrar Inc.",
                reputation="suspicious",
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            domains = ctx.forensic_evidence.emails[0].domains
            self.assertEqual(len(domains), 1)
            self.assertEqual(domains[0].domain, "suspicious.net")
            self.assertEqual(domains[0].registrar, "BadRegistrar Inc.")
            self.assertEqual(domains[0].reputation, "suspicious")

    # ------------------------------------------------------------------
    # 7. IP addresses and geolocation
    # ------------------------------------------------------------------

    def test_07_ip_addresses_and_geolocation(self):
        """7. IP addresses and geolocation fields are represented correctly."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("IP"),
                title="IP Address Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            email = Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="IP test",
                analysis_status="parsed",
            )
            db.add(email)
            db.flush()

            db.add(IPAddress(
                id=uuid.uuid4(), email_id=email.id,
                ip_address="203.0.113.55",
                version=4,
                asn="AS15169",
                organization="Google LLC",
                country="US",
                region="California",
                city="Mountain View",
                latitude=37.386,
                longitude=-122.084,
                reputation="clean",
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            ips = ctx.forensic_evidence.emails[0].ip_addresses
            self.assertEqual(len(ips), 1)
            self.assertEqual(ips[0].ip_address, "203.0.113.55")
            self.assertEqual(ips[0].version, 4)
            self.assertEqual(ips[0].asn, "AS15169")
            self.assertEqual(ips[0].organization, "Google LLC")
            self.assertEqual(ips[0].country, "US")
            self.assertEqual(ips[0].region, "California")
            self.assertEqual(ips[0].city, "Mountain View")
            self.assertAlmostEqual(ips[0].latitude, 37.386, places=2)
            self.assertAlmostEqual(ips[0].longitude, -122.084, places=2)
            self.assertEqual(ips[0].reputation, "clean")

    # ------------------------------------------------------------------
    # 8. Attachments
    # ------------------------------------------------------------------

    def test_08_attachment_metadata(self):
        """8. Attachment metadata and hashes are represented correctly."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("AT"),
                title="Attachment Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            email = Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="Attachment test",
                analysis_status="parsed",
            )
            db.add(email)
            db.flush()

            db.add(Attachment(
                id=uuid.uuid4(), email_id=email.id,
                file_name="invoice.pdf",
                content_type="application/pdf",
                file_size=102400,
                sha256="abcd" * 16,
                md5="ef01" * 8,
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            atts = ctx.forensic_evidence.emails[0].attachments
            self.assertEqual(len(atts), 1)
            self.assertEqual(atts[0].file_name, "invoice.pdf")
            self.assertEqual(atts[0].content_type, "application/pdf")
            self.assertEqual(atts[0].file_size, 102400)
            self.assertEqual(atts[0].sha256, "abcd" * 16)
            self.assertEqual(atts[0].md5, "ef01" * 8)

    # ------------------------------------------------------------------
    # 9. Threat intelligence normalized fields
    # ------------------------------------------------------------------

    def test_09_threat_intel_normalized_fields(self):
        """9. Threat-intelligence normalized fields are included."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("TI"),
                title="Threat Intel Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            db.add(ThreatIntelligenceResult(
                id=uuid.uuid4(),
                case_id=case.id,
                indicator_type="ip",
                indicator_value="198.51.100.12",
                provider="virustotal",
                queried_at=datetime.now(timezone.utc),
                status="success",
                reputation="malicious",
                confidence=0.95,
                malicious_count=12,
                suspicious_count=3,
                harmless_count=45,
                country="RU",
                asn=15169,
                organization="Bad Network",
                raw_response={"large": "payload", "nested": {"data": True}},
                error_message=None,
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            self.assertEqual(len(ctx.threat_intelligence.results), 1)
            ti = ctx.threat_intelligence.results[0]
            self.assertEqual(ti.indicator_type, "ip")
            self.assertEqual(ti.indicator_value, "198.51.100.12")
            self.assertEqual(ti.provider, "virustotal")
            self.assertEqual(ti.status, "success")
            self.assertEqual(ti.reputation, "malicious")
            self.assertAlmostEqual(ti.confidence, 0.95, places=2)
            self.assertEqual(ti.malicious_count, 12)
            self.assertEqual(ti.suspicious_count, 3)
            self.assertEqual(ti.harmless_count, 45)
            self.assertEqual(ti.country, "RU")
            self.assertEqual(ti.organization, "Bad Network")

    # ------------------------------------------------------------------
    # 10. raw_response NOT included
    # ------------------------------------------------------------------

    def test_10_raw_response_excluded(self):
        """10. raw_response is NOT included in the AI context."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("RR"),
                title="Raw Response Exclusion",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            db.add(ThreatIntelligenceResult(
                id=uuid.uuid4(),
                case_id=case.id,
                indicator_type="domain",
                indicator_value="example.com",
                provider="virustotal",
                queried_at=datetime.now(timezone.utc),
                status="success",
                raw_response={"secret": "provider_data", "pii": "sensitive"},
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            ti = ctx.threat_intelligence.results[0]

            # AIThreatIntelResult schema should NOT have raw_response
            self.assertFalse(hasattr(ti, "raw_response"))
            context_dict = ctx.model_dump()
            for result in context_dict["threat_intelligence"]["results"]:
                self.assertNotIn("raw_response", result)

    # ------------------------------------------------------------------
    # 11. Raw email body NOT included
    # ------------------------------------------------------------------

    def test_11_raw_email_body_excluded(self):
        """11. Raw email body is NOT included."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("RB"),
                title="Body Exclusion",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            db.add(Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="Body test",
                analysis_status="parsed",
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            em = ctx.forensic_evidence.emails[0]
            # AIEmailContext should not have body_plain or body_html
            self.assertFalse(hasattr(em, "body_plain"))
            self.assertFalse(hasattr(em, "body_html"))

            email_dict = ctx.model_dump()["forensic_evidence"]["emails"][0]
            self.assertNotIn("body_plain", email_dict)
            self.assertNotIn("body_html", email_dict)

    # ------------------------------------------------------------------
    # 12. Attachment binary NOT included
    # ------------------------------------------------------------------

    def test_12_attachment_binary_excluded(self):
        """12. Attachment binary/content is NOT included."""
        ctx_schema = AIAttachmentEvidence.model_fields
        self.assertNotIn("content", ctx_schema)
        self.assertNotIn("binary", ctx_schema)
        self.assertNotIn("data", ctx_schema)
        self.assertNotIn("decoded_content", ctx_schema)

    # ------------------------------------------------------------------
    # 13. API keys / configuration NOT included
    # ------------------------------------------------------------------

    def test_13_api_keys_not_included(self):
        """13. API keys/configuration are NOT included."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("AK"),
                title="API Key Exclusion",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            db.add(Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="Key test",
                analysis_status="parsed",
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            serialized = ctx.model_dump_json()
            self.assertNotIn("api_key", serialized.lower())
            self.assertNotIn("database_url", serialized.lower())
            self.assertNotIn("secret", serialized.lower())
            self.assertNotIn("password", serialized.lower())

    # ------------------------------------------------------------------
    # 14. Missing optional evidence → empty collections
    # ------------------------------------------------------------------

    def test_14_missing_optional_evidence(self):
        """14. Missing optional evidence produces empty collections rather than errors."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("MO"),
                title="Missing Optional Test",
                status="open",
                priority="low",
            )
            db.add(case)
            db.flush()

            # Email with zero artefacts
            db.add(Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="Bare email",
                analysis_status="parsed",
            ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            em = ctx.forensic_evidence.emails[0]
            self.assertEqual(em.headers, [])
            self.assertEqual(em.urls, [])
            self.assertEqual(em.domains, [])
            self.assertEqual(em.ip_addresses, [])
            self.assertEqual(em.attachments, [])
            self.assertEqual(ctx.threat_intelligence.results, [])

    # ------------------------------------------------------------------
    # 15. Multiple threat-intelligence results
    # ------------------------------------------------------------------

    def test_15_multiple_threat_intel_results(self):
        """15. Multiple threat-intelligence results are represented correctly."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("MT"),
                title="Multi TI Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            now = datetime.now(timezone.utc)
            for i, provider in enumerate(["virustotal", "abuseipdb"]):
                db.add(ThreatIntelligenceResult(
                    id=uuid.uuid4(),
                    case_id=case.id,
                    indicator_type="ip",
                    indicator_value=f"10.0.0.{i + 1}",
                    provider=provider,
                    queried_at=now,
                    status="success",
                    reputation="malicious",
                ))
            db.commit()

            ctx = build_ai_context(db, case.id)
            self.assertEqual(len(ctx.threat_intelligence.results), 2)
            providers = {r.provider for r in ctx.threat_intelligence.results}
            self.assertEqual(providers, {"virustotal", "abuseipdb"})

    # ------------------------------------------------------------------
    # 16. Deterministic ordering
    # ------------------------------------------------------------------

    def test_16_deterministic_ordering(self):
        """16. Output ordering is deterministic across repeated calls."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("DO"),
                title="Deterministic Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            for i in range(5):
                db.add(Email(
                    id=uuid.uuid4(),
                    case_id=case.id,
                    subject=f"Det email {i}",
                    analysis_status="parsed",
                ))
            db.commit()

            ctx1 = build_ai_context(db, case.id)
            ctx2 = build_ai_context(db, case.id)

            subjects1 = [e.subject for e in ctx1.forensic_evidence.emails]
            subjects2 = [e.subject for e in ctx2.forensic_evidence.emails]
            self.assertEqual(subjects1, subjects2)

    # ------------------------------------------------------------------
    # 17. Nonexistent case
    # ------------------------------------------------------------------

    def test_17_nonexistent_case_raises(self):
        """17. Nonexistent case raises CaseNotFoundError."""
        with SessionLocal() as db:
            fake_id = uuid.uuid4()
            with self.assertRaises(CaseNotFoundError) as cm:
                build_ai_context(db, fake_id)
            self.assertIn(str(fake_id), str(cm.exception))

    # ------------------------------------------------------------------
    # 18. Read-only guarantee
    # ------------------------------------------------------------------

    def test_18_context_build_does_not_modify_db(self):
        """18. Context construction does NOT create or modify database records."""
        with SessionLocal() as db:
            case = Case(
                id=uuid.uuid4(),
                case_number=_unique_case_number("RO"),
                title="Read-Only Test",
                status="open",
                priority="medium",
            )
            db.add(case)
            db.flush()

            email = Email(
                id=uuid.uuid4(),
                case_id=case.id,
                subject="Read-only test",
                analysis_status="parsed",
            )
            db.add(email)
            db.commit()

            # Count rows before
            from app.models.ai_analysis import AIAnalysisResult
            ai_count_before = db.query(AIAnalysisResult).filter(
                AIAnalysisResult.case_id == case.id
            ).count()
            email_count_before = db.query(Email).filter(
                Email.case_id == case.id
            ).count()
            ti_count_before = db.query(ThreatIntelligenceResult).filter(
                ThreatIntelligenceResult.case_id == case.id
            ).count()

            _ = build_ai_context(db, case.id)

            # Count rows after
            ai_count_after = db.query(AIAnalysisResult).filter(
                AIAnalysisResult.case_id == case.id
            ).count()
            email_count_after = db.query(Email).filter(
                Email.case_id == case.id
            ).count()
            ti_count_after = db.query(ThreatIntelligenceResult).filter(
                ThreatIntelligenceResult.case_id == case.id
            ).count()

            self.assertEqual(ai_count_before, ai_count_after)
            self.assertEqual(email_count_before, email_count_after)
            self.assertEqual(ti_count_before, ti_count_after)

            # Also verify the Case record itself is unchanged
            db.refresh(case)
            self.assertEqual(case.title, "Read-Only Test")
            self.assertEqual(case.status, "open")


if __name__ == "__main__":
    unittest.main()
